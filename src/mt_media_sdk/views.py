from __future__ import annotations

import logging
import os
import hashlib
from typing import Any, Dict, Iterable, List, Optional, Tuple

from celery.result import AsyncResult
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.db.models import Prefetch, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import decorators, filters, mixins, status, viewsets
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import FileUploadParser, FormParser, MultiPartParser
from rest_framework.permissions import (
    IsAdminUser,
    IsAuthenticated,
    IsAuthenticatedOrReadOnly,
)
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from .exceptions import UploadError
from .models import (
    Load,
    LoadStatus,
    MediaFile,
    MediaLimit,
    UploadSession,
    UserInteraction,
)
from .serializers import (
    InitiateUploadSessionSerializer,
    LoadDetailSerializer,
    LoadListSerializer,
    LoadUpdateSerializer,
    MediaFileDetailSerializer,
    MediaFileListSerializer,
    MediaFileSerializer,
    MediaFileUploadSerializer,
    MediaLimitSerializer,
    UploadSessionSerializer,
    UserInteractionSerializer,
)
from .uploads.chunked import UploadSessionService

logger = logging.getLogger(__name__)


class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 200


RESUMABLE_SUPPORTED = bool(getattr(settings, "UPLOAD_RESUMABLE_SUPPORTED", False))
MAX_ACTIVE_UPLOADS = max(1, int(getattr(settings, "UPLOAD_HANDLER_MAX_ACTIVE_UPLOADS", 50)))
UPLOAD_PROGRESS_CACHE_TTL = int(getattr(settings, "UPLOAD_PROGRESS_CACHE_TTL", 3600))
UPLOAD_CONTROL_CACHE_TTL = int(getattr(settings, "UPLOAD_CONTROL_CACHE_TTL", 3600))
ASYNC_COMPLETE_THRESHOLD_BYTES = int(getattr(settings, "UPLOAD_ASYNC_COMPLETE_THRESHOLD_BYTES", 64 * 1024 * 1024))


def _tenant_id(request) -> Optional[str]:
    return getattr(request, "tenant_id", None)


def _is_staff(user) -> bool:
    return bool(user and getattr(user, "is_authenticated", False) and getattr(user, "is_staff", False))


def _is_owner(user, obj) -> bool:
    owner = getattr(obj, "owner", None)
    return bool(owner and user and getattr(user, "is_authenticated", False) and str(getattr(owner, "pk", None)) == str(getattr(user, "pk", None)))


def _build_abs_url(request, url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    try:
        if str(url).startswith(("http://", "https://")):
            return url
        if request is not None:
            return request.build_absolute_uri(url)
    except Exception:
        logger.debug("Failed to build absolute URL", exc_info=True)
    return url


def _normalize_file_id(value: Any) -> str:
    return str(value or "").strip()


def _build_upload_service(storage_backend: Optional[str] = None) -> UploadSessionService:
    attempts: Tuple[Dict[str, Any], ...] = (
        {"storage_backend_name": storage_backend},
        {"storage_backend": storage_backend},
        {"backend_name": storage_backend},
        {},
    )
    last_exc: Optional[Exception] = None
    for kwargs in attempts:
        try:
            clean_kwargs = {k: v for k, v in kwargs.items() if v is not None}
            return UploadSessionService(**clean_kwargs)
        except TypeError as exc:
            last_exc = exc
    if last_exc is not None:
        raise last_exc
    return UploadSessionService()


def _media_queryset_base():
    return (
        MediaFile.all_objects.select_related("owner", "content_type", "original")
        .prefetch_related(
            Prefetch(
                "derivatives",
                queryset=MediaFile.all_objects.select_related("owner", "content_type", "original"),
            )
        )
    )


def _load_queryset_base():
    return Load.objects.select_related("user", "file", "session")


def _session_queryset_base():
    return UploadSession.objects.select_related("user", "media_file")


def _content_type_payload(obj: MediaFile) -> Optional[Dict[str, Any]]:
    if not obj.content_type_id or not obj.object_id:
        return None
    try:
        ct = ContentType.objects.get_for_id(obj.content_type_id)
        return {"app_label": ct.app_label, "model": ct.model, "object_id": obj.object_id}
    except Exception:
        logger.debug("Failed to resolve content type for MediaFile %s", obj.pk, exc_info=True)
        return {"app_label": None, "model": None, "object_id": obj.object_id}


def _upload_error_response(exc: UploadError) -> Response:
    code_map = {
        "validation_failed": status.HTTP_422_UNPROCESSABLE_ENTITY,
        "file_too_large": status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        "invalid_file_type": status.HTTP_422_UNPROCESSABLE_ENTITY,
        "unsafe_filename": status.HTTP_422_UNPROCESSABLE_ENTITY,
        "checksum_mismatch": status.HTTP_409_CONFLICT,
        "upload_session_not_found": status.HTTP_404_NOT_FOUND,
        "upload_session_expired": status.HTTP_410_GONE,
        "invalid_state_transition": status.HTTP_409_CONFLICT,
        "part_out_of_range": status.HTTP_400_BAD_REQUEST,
        "rate_limit_exceeded": status.HTTP_429_TOO_MANY_REQUESTS,
        "storage_error": status.HTTP_502_BAD_GATEWAY,
    }
    return Response(exc.to_dict(), status=code_map.get(exc.code, status.HTTP_400_BAD_REQUEST))


def _read_uploaded_bytes(request) -> bytes:
    uploaded = request.data.get("file")
    if uploaded is None and getattr(request, "FILES", None):
        uploaded = request.FILES.get("file")
    if uploaded is None:
        return b""
    if hasattr(uploaded, "read"):
        return uploaded.read()
    if isinstance(uploaded, (bytes, bytearray, memoryview)):
        return bytes(uploaded)
    return bytes(uploaded)


def _tenant_cache_scope(tenant_id: Optional[str]) -> str:
    value = "<global>" if tenant_id is None else str(tenant_id)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _status_cache_key_for_user(user, tenant_id: Optional[str]) -> str:
    return (
        f"upload_status_{getattr(user, 'id', 'global')}_"
        f"{_tenant_cache_scope(tenant_id)}"
    )


def _control_cache_key_for_user(user, tenant_id: Optional[str]) -> str:
    return (
        f"upload_control_{getattr(user, 'id', 'global')}_"
        f"{_tenant_cache_scope(tenant_id)}"
    )


def _get_cache_snapshot(user, tenant_id: Optional[str]) -> Dict[str, Dict[str, Any]]:
    key = _status_cache_key_for_user(user, tenant_id)
    snapshot = cache.get(key, {}) or {}
    if not isinstance(snapshot, dict):
        try:
            snapshot = dict(snapshot)
        except Exception:
            snapshot = {}

    try:
        if len(snapshot) > MAX_ACTIVE_UPLOADS:
            items = sorted(
                snapshot.items(),
                key=lambda kv: (
                    str(kv[1].get("started_at") or kv[1].get("created_at") or ""),
                    str(kv[0]),
                ),
            )
            snapshot = dict(items[-MAX_ACTIVE_UPLOADS:])
    except Exception:
        keys = list(snapshot.keys())[-MAX_ACTIVE_UPLOADS:]
        snapshot = {k: snapshot[k] for k in keys if k in snapshot}

    return snapshot


def _to_iso(value: Any) -> Any:
    return value.isoformat() if hasattr(value, "isoformat") else value


def _normalize_db_upload_row(row: Dict[str, Any], file_id_key: str, file_path_key: Optional[str]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "file_id": _normalize_file_id(row.get(file_id_key)),
        "status": row.get("status"),
        "progress": row.get("progress"),
        "media_type": row.get("media_type"),
        "task_id": row.get("task_id"),
        "created_at": _to_iso(row.get("created_at")),
        "started_at": _to_iso(row.get("started_at")),
        "finished_at": _to_iso(row.get("finished_at")),
    }
    if file_path_key:
        payload["file_path"] = row.get(file_path_key)
    return payload


def _db_active_uploads(user, tenant_id: Optional[str]) -> List[Dict[str, Any]]:
    if Load is None:
        return []

    try:
        model_fields = {f.name for f in Load._meta.get_fields()}
        terminal_values = {
            getattr(LoadStatus, "CANCELLED", "cancelled"),
            getattr(LoadStatus, "FAILED", "failed"),
            getattr(LoadStatus, "COMPLETED", "completed"),
        }

        file_id_key = "external_file_ref" if "external_file_ref" in model_fields else ("file_id" if "file_id" in model_fields else None)
        file_path_key = "storage_path" if "storage_path" in model_fields else ("file_path" if "file_path" in model_fields else None)

        fields = []
        for candidate in (file_id_key, file_path_key, "status", "progress", "media_type", "task_id", "created_at", "started_at", "finished_at"):
            if candidate and candidate in model_fields and candidate not in fields:
                fields.append(candidate)

        qs = Load.objects.filter(user=user).filter(
            Q(session__tenant_id=tenant_id) | Q(file__tenant_id=tenant_id)
        )
        if "status" in model_fields:
            qs = qs.exclude(status__in=list(terminal_values))

        rows = list(qs.values(*fields).order_by("-created_at")[:MAX_ACTIVE_UPLOADS]) if fields else []
        return [_normalize_db_upload_row(row, file_id_key or "id", file_path_key) for row in rows]
    except Exception:
        logger.exception("Failed to fetch active upload rows for user %s", getattr(user, "id", "<anon>"))
        return []


def _merge_cache_and_db(cache_snapshot: Dict[str, Dict[str, Any]], db_rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}

    for row in db_rows:
        file_id = _normalize_file_id(row.get("file_id"))
        if not file_id:
            continue
        merged[file_id] = dict(row)
        cache_entry = cache_snapshot.get(file_id)
        if isinstance(cache_entry, dict):
            merged[file_id].update(cache_entry)

    for file_id, entry in cache_snapshot.items():
        if file_id not in merged:
            merged[file_id] = dict(entry)

    def sort_key(item: Tuple[str, Dict[str, Any]]):
        payload = item[1]
        return (str(payload.get("started_at") or payload.get("created_at") or ""), str(item[0]))

    return [payload for _, payload in sorted(merged.items(), key=sort_key, reverse=True)]


def _mutate_control_cache(
    user,
    tenant_id: Optional[str],
    action: str,
    file_id: str,
) -> Dict[str, List[str]]:
    key = _control_cache_key_for_user(user, tenant_id)
    control = cache.get(key, {}) or {}
    if not isinstance(control, dict):
        try:
            control = dict(control)
        except Exception:
            control = {}

    def to_set(value) -> set[str]:
        if value is None:
            return set()
        if isinstance(value, (list, tuple, set)):
            return {str(v) for v in value if str(v).strip()}
        return {str(value)}

    pause = to_set(control.get("pause_upload"))
    resume = to_set(control.get("resume_upload"))
    cancel = to_set(control.get("cancel_upload"))

    normalized_action = (action or "").lower().strip()
    normalized_file_id = _normalize_file_id(file_id)

    if normalized_action == "pause":
        pause.add(normalized_file_id)
        resume.discard(normalized_file_id)
        cancel.discard(normalized_file_id)
    elif normalized_action == "resume":
        resume.add(normalized_file_id)
        pause.discard(normalized_file_id)
        cancel.discard(normalized_file_id)
    elif normalized_action == "cancel":
        cancel.add(normalized_file_id)
        pause.discard(normalized_file_id)
        resume.discard(normalized_file_id)
    else:
        raise ValueError("Unsupported action")

    payload = {
        "pause_upload": sorted(pause),
        "resume_upload": sorted(resume),
        "cancel_upload": sorted(cancel),
    }
    cache.set(key, payload, timeout=UPLOAD_CONTROL_CACHE_TTL)
    return payload


def _refresh_load_from_celery(load: Load) -> Dict[str, Any]:
    if not load.task_id:
        return {"task_id": None, "state": None, "status": load.status, "progress": load.progress, "info": None}

    result = AsyncResult(load.task_id)
    state = (getattr(result, "state", "") or "").upper()
    info = getattr(result, "info", None)

    mapping = {
        "PENDING": LoadStatus.PENDING,
        "RECEIVED": LoadStatus.PROCESSING,
        "STARTED": LoadStatus.PROCESSING,
        "RETRY": LoadStatus.PENDING,
        "SUCCESS": LoadStatus.COMPLETED,
        "FAILURE": LoadStatus.FAILED,
        "REVOKED": LoadStatus.CANCELLED,
    }
    new_status = mapping.get(state, load.status)

    updates: Dict[str, Any] = {"status": new_status, "updated_at": timezone.now()}
    if new_status == LoadStatus.COMPLETED:
        updates["progress"] = 100.0
        updates["finished_at"] = timezone.now()
    elif new_status == LoadStatus.FAILED and info:
        updates["error_message"] = str(info)[:2000]

    Load.objects.filter(pk=load.pk).update(**updates)
    for key, value in updates.items():
        setattr(load, key, value)

    return {
        "task_id": load.task_id,
        "state": state,
        "status": load.status,
        "progress": load.progress,
        "info": str(info)[:2000] if info else None,
    }


class IsOwnerOrAdmin(IsAuthenticated):
    def has_permission(self, request, view):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return True
        return super().has_permission(request, view)

    def has_object_permission(self, request, view, obj):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return True
        if _is_staff(request.user):
            return True
        return _is_owner(request.user, obj)


class IsStaffOrReadOnly:
    @staticmethod
    def check(request) -> bool:
        return request.method in ("GET", "HEAD", "OPTIONS") or _is_staff(request.user)


class UploadErrorMixin:
    def handle_upload_error(self, exc: UploadError) -> Response:
        return _upload_error_response(exc)


class SimpleUploadView(UploadErrorMixin, APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "media_upload"

    def post(self, request):
        serializer = MediaFileUploadSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        with transaction.atomic():
            try:
                instance = serializer.save(tenant_id=_tenant_id(request), owner=request.user)
            except DjangoValidationError as exc:
                raise DRFValidationError(detail=exc.message_dict if hasattr(exc, "message_dict") else str(exc)) from exc

        return Response(MediaFileSerializer(instance, context={"request": request}).data, status=status.HTTP_201_CREATED)


class UploadSessionInitiateView(UploadErrorMixin, APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "media_upload_session"

    def post(self, request):
        serializer = InitiateUploadSessionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        service = _build_upload_service()
        try:
            result = service.initiate(
                user=request.user,
                tenant_id=_tenant_id(request),
                filename=data["filename"],
                mime_type=data.get("mime_type", ""),
                declared_size=data["size"],
                checksum_expected=data.get("checksum"),
                chunk_size=data.get("chunk_size"),
            )
        except UploadError as exc:
            return self.handle_upload_error(exc)

        if result.get("deduplicated"):
            return Response({"deduplicated": True, "media_file_id": result["media_file_id"]}, status=status.HTTP_200_OK)

        session = result["session"]
        return Response(
            {
                "deduplicated": False,
                "session": UploadSessionSerializer(session, context={"request": request}).data,
                "part_upload_mode": result["part_upload_mode"],
            },
            status=status.HTTP_201_CREATED,
        )


class UploadSessionDetailView(UploadErrorMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, request, session_id):
        qs = _session_queryset_base().filter(tenant_id=_tenant_id(request))
        if not _is_staff(request.user):
            qs = qs.filter(user=request.user)
        return get_object_or_404(qs, pk=session_id)

    def get(self, request, session_id):
        session = self.get_object(request, session_id)
        service = _build_upload_service(session.storage_backend)
        return Response(service.resume_info(session), status=status.HTTP_200_OK)

    def delete(self, request, session_id):
        session = self.get_object(request, session_id)
        service = _build_upload_service(session.storage_backend)
        try:
            service.abort(session)
        except UploadError as exc:
            return self.handle_upload_error(exc)
        return Response(status=status.HTTP_204_NO_CONTENT)


class UploadSessionPartView(UploadErrorMixin, APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [FileUploadParser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "media_upload_part"

    def put(self, request, session_id, part_number):
        qs = _session_queryset_base().filter(tenant_id=_tenant_id(request))
        if not _is_staff(request.user):
            qs = qs.filter(user=request.user)
        session = get_object_or_404(qs, pk=session_id)
        try:
            part_number = int(part_number)
            if part_number < 1:
                return Response({"code": "part_out_of_range", "message": "Part number must be at least 1."}, status=status.HTTP_400_BAD_REQUEST)
        except (TypeError, ValueError):
            return Response({"code": "part_out_of_range", "message": "Invalid part number."}, status=status.HTTP_400_BAD_REQUEST)

        checksum = request.headers.get("X-Part-Checksum")
        raw = _read_uploaded_bytes(request)
        if not raw:
            return Response({"code": "validation_failed", "message": "No file bytes provided."}, status=status.HTTP_400_BAD_REQUEST)

        service = _build_upload_service(session.storage_backend)
        try:
            part = service.upload_part(session, part_number, raw, part_checksum=checksum)
        except UploadError as exc:
            return self.handle_upload_error(exc)

        return Response({"part_number": part.part_number, "size": part.size}, status=status.HTTP_201_CREATED)


class UploadSessionCompleteView(UploadErrorMixin, APIView):
    permission_classes = [IsAuthenticated]
    ASYNC_THRESHOLD_BYTES = ASYNC_COMPLETE_THRESHOLD_BYTES

    def post(self, request, session_id):
        qs = _session_queryset_base().filter(tenant_id=_tenant_id(request))
        if not _is_staff(request.user):
            qs = qs.filter(user=request.user)
        session = get_object_or_404(qs, pk=session_id)
        service = _build_upload_service(session.storage_backend)
        try:
            if (session.declared_size or 0) > self.ASYNC_THRESHOLD_BYTES:
                from .tasks import finalize_upload_session
                finalize_upload_session.delay(str(session.id))
                return Response({"status": "completing", "session_id": str(session.id)}, status=status.HTTP_202_ACCEPTED)

            media_file = service.complete(session, owner=request.user)
        except UploadError as exc:
            return self.handle_upload_error(exc)

        return Response(MediaFileSerializer(media_file, context={"request": request}).data, status=status.HTTP_200_OK)


class MediaLimitViewSet(
    viewsets.GenericViewSet,
    mixins.RetrieveModelMixin,
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
):
    queryset = MediaLimit.objects.all()
    serializer_class = MediaLimitSerializer
    pagination_class = None

    def get_queryset(self):
        tenant = _tenant_id(self.request)
        if tenant is not None:
            return MediaLimit.objects.filter(tenant_id=tenant)
        return MediaLimit.objects.filter(tenant_id__isnull=True)

    def get_permissions(self):
        if self.request.method not in ("GET", "HEAD", "OPTIONS"):
            return (IsAdminUser(),)
        return (IsAuthenticatedOrReadOnly(),)

    def create(self, request, *args, **kwargs):
        if not IsStaffOrReadOnly.check(request):
            return Response({"detail": "Only staff can create MediaLimit."}, status=status.HTTP_403_FORBIDDEN)

        tenant = _tenant_id(request)
        qs = MediaLimit.objects.filter(tenant_id=tenant) if tenant is not None else MediaLimit.objects.filter(tenant_id__isnull=True)
        if qs.exists():
            return Response({"detail": "A MediaLimit already exists for this scope. Update the existing resource instead."}, status=status.HTTP_409_CONFLICT)

        with transaction.atomic():
            return super().create(request, *args, **kwargs)

    def perform_create(self, serializer):
        serializer.save(tenant_id=_tenant_id(self.request))

    def update(self, request, *args, **kwargs):
        if not IsStaffOrReadOnly.check(request):
            return Response({"detail": "Only staff can update MediaLimit."}, status=status.HTTP_403_FORBIDDEN)
        with transaction.atomic():
            return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        if not IsStaffOrReadOnly.check(request):
            return Response({"detail": "Only staff can update MediaLimit."}, status=status.HTTP_403_FORBIDDEN)
        with transaction.atomic():
            return super().partial_update(request, *args, **kwargs)


class MediaFileViewSet(viewsets.ModelViewSet):
    permission_classes = (IsOwnerOrAdmin,)
    parser_classes = (MultiPartParser, FormParser)
    pagination_class = StandardResultsSetPagination
    filter_backends = (DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter)
    filterset_fields = ("owner", "mime_type", "status", "is_public", "content_type")
    search_fields = ("original_filename", "checksum")
    ordering_fields = ("created_at", "size", "updated_at")

    def get_queryset(self):
        qs = _media_queryset_base().filter(tenant_id=_tenant_id(self.request))

        user = getattr(self.request, "user", None)
        if _is_staff(user):
            return qs
        if user and user.is_authenticated:
            return qs.filter(Q(is_public=True) | Q(owner=user))
        return qs.filter(is_public=True)

    def get_serializer_class(self):
        if self.action == "list":
            return MediaFileListSerializer
        if self.action == "create":
            return MediaFileUploadSerializer
        return MediaFileDetailSerializer

    def perform_create(self, serializer):
        with transaction.atomic():
            try:
                serializer.save(tenant_id=_tenant_id(self.request), owner=self.request.user)
            except DjangoValidationError as exc:
                raise DRFValidationError(detail=exc.message_dict if hasattr(exc, "message_dict") else str(exc)) from exc

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        hard = request.query_params.get("hard", "false").lower() in ("1", "true", "yes")

        if hard:
            if not _is_staff(request.user):
                return Response({"detail": "Hard delete requires admin privileges."}, status=status.HTTP_403_FORBIDDEN)
            try:
                storage = getattr(obj.file, "storage", None)
                name = getattr(obj.file, "name", None)
                if name and storage and hasattr(storage, "delete"):
                    storage.delete(name)
            except Exception:
                logger.exception("Error deleting file from storage during hard delete: %s", obj.pk)
            obj.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)

        obj.soft_delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @decorators.action(detail=True, methods=["post"], url_path="restore", permission_classes=(IsAdminUser,))
    def restore(self, request, pk=None):
        obj = get_object_or_404(
            MediaFile.all_objects.filter(tenant_id=_tenant_id(request)),
            pk=pk,
        )
        obj.restore()
        return Response({"detail": "Restored."}, status=status.HTTP_200_OK)

    @decorators.action(detail=True, methods=["get"], url_path="presign", permission_classes=(IsAuthenticatedOrReadOnly,))
    def presign(self, request, pk=None):
        obj = self.get_object()
        expires_raw = request.query_params.get("expires", "60")
        try:
            expires = max(1, min(int(expires_raw), 86400))
        except (TypeError, ValueError):
            return Response({"detail": "Invalid 'expires' parameter; must be integer seconds."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            url = _build_abs_url(request, obj.get_url(expire_seconds=expires))
        except Exception:
            logger.exception("Presign failed for MediaFile %s", obj.pk)
            return Response({"detail": "Could not generate presigned URL."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        if not url:
            return Response(
                {"detail": "This storage backend cannot issue a protected download URL."},
                status=status.HTTP_409_CONFLICT,
            )
        return Response({"url": url}, status=status.HTTP_200_OK)

    @decorators.action(detail=True, methods=["post"], url_path="make-public", permission_classes=(IsAuthenticated,))
    def make_public(self, request, pk=None):
        obj = self.get_object()
        if not (_is_staff(request.user) or _is_owner(request.user, obj)):
            return Response({"detail": "Only owner or staff can change visibility."}, status=status.HTTP_403_FORBIDDEN)
        obj.is_public = True
        obj.save(update_fields=["is_public", "updated_at"])
        return Response({"detail": "Marked public."}, status=status.HTTP_200_OK)

    @decorators.action(detail=True, methods=["post"], url_path="make-private", permission_classes=(IsAuthenticated,))
    def make_private(self, request, pk=None):
        obj = self.get_object()
        if not (_is_staff(request.user) or _is_owner(request.user, obj)):
            return Response({"detail": "Only owner or staff can change visibility."}, status=status.HTTP_403_FORBIDDEN)
        obj.is_public = False
        obj.save(update_fields=["is_public", "updated_at"])
        return Response({"detail": "Marked private."}, status=status.HTTP_200_OK)


class UserInteractionViewSet(viewsets.ModelViewSet):
    queryset = UserInteraction.objects.select_related("user", "content_type")
    serializer_class = UserInteractionSerializer
    permission_classes = (IsAuthenticatedOrReadOnly,)
    pagination_class = StandardResultsSetPagination
    filter_backends = (DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter)
    filterset_fields = ("content_type", "object_id", "interaction_type", "user")
    search_fields = ("session_id", "metadata")
    ordering_fields = ("timestamp",)

    def get_queryset(self):
        qs = super().get_queryset()
        user = getattr(self.request, "user", None)
        if _is_staff(user):
            return qs
        if user and user.is_authenticated:
            return qs.filter(Q(user=user) | Q(user__isnull=True))
        return qs.filter(user__isnull=True)

    def perform_create(self, serializer):
        request = self.request
        if request.user.is_authenticated:
            provided_user = serializer.validated_data.get("user", None)
            if provided_user and str(provided_user.pk) != str(request.user.pk) and not request.user.is_staff:
                raise DRFValidationError({"user": "You may not set a different user."})
            serializer.save(user=request.user)
            return

        if not serializer.validated_data.get("session_id"):
            raise DRFValidationError({"session_id": "Anonymous interactions must include a session_id."})
        serializer.save()


class LoadViewSet(viewsets.ModelViewSet):
    serializer_class = LoadDetailSerializer
    permission_classes = (IsAuthenticatedOrReadOnly,)
    pagination_class = StandardResultsSetPagination
    filter_backends = (DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter)
    filterset_fields = ("status", "task_type", "user")
    search_fields = ("task_id", "external_file_ref", "storage_path")
    ordering_fields = ("created_at", "started_at", "finished_at")

    def get_queryset(self):
        qs = _load_queryset_base()
        user = getattr(self.request, "user", None)
        if _is_staff(user):
            return qs
        if user and user.is_authenticated:
            return qs.filter(user=user)
        return qs.none()

    def get_serializer_class(self):
        if self.action == "list":
            return LoadListSerializer
        if self.action in ("partial_update", "update"):
            return LoadUpdateSerializer
        return LoadDetailSerializer

    def perform_create(self, serializer):
        if self.request.user.is_authenticated:
            serializer.save(user=self.request.user)
        else:
            serializer.save()

    def perform_update(self, serializer):
        with transaction.atomic():
            try:
                serializer.save()
            except DjangoValidationError as exc:
                raise DRFValidationError(detail=exc.message_dict if hasattr(exc, "message_dict") else str(exc)) from exc

    @decorators.action(detail=True, methods=["post"], url_path="refresh", permission_classes=(IsAuthenticated,))
    def refresh_from_celery(self, request, pk=None):
        load = self.get_object()
        if not (_is_staff(request.user) or _is_owner(request.user, load)):
            return Response({"detail": "Only owner or staff can refresh status."}, status=status.HTTP_403_FORBIDDEN)

        try:
            payload = _refresh_load_from_celery(load)
            return Response(payload, status=status.HTTP_200_OK)
        except Exception:
            logger.exception("Failed to refresh Load %s from Celery", load.pk)
            return Response({"detail": "Could not refresh status."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UploadListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        tenant_id = _tenant_id(request)
        try:
            cache_snapshot = _get_cache_snapshot(user, tenant_id)
            db_rows = _db_active_uploads(user, tenant_id)
            merged = _merge_cache_and_db(cache_snapshot, db_rows)
            return Response({"uploads": merged, "resumable_supported": RESUMABLE_SUPPORTED, "server_time": timezone.now().isoformat()}, status=status.HTTP_200_OK)
        except Exception:
            logger.exception("Error fetching upload list for user %s", getattr(user, "id", "<anon>"))
            return Response({"error": "Unable to fetch uploads"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UploadDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, file_id: str):
        user = request.user
        tenant_id = _tenant_id(request)
        file_id = _normalize_file_id(file_id)
        try:
            cache_snapshot = _get_cache_snapshot(user, tenant_id)
            db_rows = _db_active_uploads(user, tenant_id)
            merged_list = _merge_cache_and_db(cache_snapshot, db_rows)
            entry = next((m for m in merged_list if _normalize_file_id(m.get("file_id")) == file_id), None)
            if not entry and isinstance(cache_snapshot, dict):
                entry = cache_snapshot.get(file_id)
            if not entry:
                return Response({"detail": "Upload not found"}, status=status.HTTP_404_NOT_FOUND)
            return Response({"upload": entry, "resumable_supported": RESUMABLE_SUPPORTED}, status=status.HTTP_200_OK)
        except Exception:
            logger.exception("Error fetching upload detail for %s user %s", file_id, getattr(user, "id", "<anon>"))
            return Response({"error": "Unable to fetch upload detail"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UploadControlView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data or {}
        action = (data.get("action") or "").strip().lower()
        file_id = _normalize_file_id(data.get("file_id"))

        if action not in ("pause", "resume", "cancel") or not file_id:
            return Response({"error": "Invalid payload: action and file_id are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            control = _mutate_control_cache(user, _tenant_id(request), action, file_id)
            hint = {
                "resumable_supported": RESUMABLE_SUPPORTED,
                "recommended_action": "resume" if action == "resume" and RESUMABLE_SUPPORTED else ("restart" if action == "resume" and not RESUMABLE_SUPPORTED else "none"),
            }
            logger.info("User %s requested %s for file %s", getattr(user, "id", "<anon>"), action, file_id)
            return Response({"file_id": file_id, "action": action, "status": "accepted", "control_snapshot": control, "hint": hint}, status=status.HTTP_202_ACCEPTED)
        except ValueError:
            return Response({"error": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            logger.exception("Failed to apply control %s for user %s file %s", action, getattr(user, "id", "<anon>"), file_id)
            return Response({"error": "Failed to apply control"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UploadResumeOffsetView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, file_id: str):
        user = request.user
        file_id = _normalize_file_id(file_id)
        try:
            tenant_id = _tenant_id(request)
            snapshot = _get_cache_snapshot(user, tenant_id)
            entry = snapshot.get(file_id, {}) if isinstance(snapshot, dict) else {}
            tmp_path = entry.get("tmp_path") or entry.get("file_path")
            offset: Optional[int] = None

            if tmp_path:
                try:
                    from .tasks import _is_within_media_root

                    if (
                        _is_within_media_root(tmp_path)
                        and os.path.exists(tmp_path)
                        and os.path.isfile(tmp_path)
                    ):
                        offset = os.path.getsize(tmp_path)
                except Exception:
                    logger.exception("Failed to stat tmp_path %s for user %s", tmp_path, getattr(user, "id", "<anon>"))

            if offset is None and Load is not None:
                try:
                    model_fields = {f.name for f in Load._meta.get_fields()}
                    qs = Load.objects.filter(user=user).filter(
                        Q(session__tenant_id=tenant_id) | Q(file__tenant_id=tenant_id)
                    )
                    if "external_file_ref" in model_fields:
                        qs = qs.filter(external_file_ref=file_id)
                    elif "file_id" in model_fields:
                        qs = qs.filter(file_id=file_id)
                    else:
                        qs = qs.none()

                    load = qs.first()
                    if load:
                        fp = getattr(load, "storage_path", None) or getattr(load, "file_path", None)
                        if fp and os.path.exists(fp) and os.path.isfile(fp):
                            offset = os.path.getsize(fp)
                except Exception:
                    logger.debug("No accessible file path for load %s", file_id, exc_info=True)

            return Response({"file_id": file_id, "offset_bytes": offset, "resumable_supported": RESUMABLE_SUPPORTED}, status=status.HTTP_200_OK)
        except Exception:
            logger.exception("Failed to compute resume offset for %s", file_id)
            return Response({"error": "Could not determine resume offset"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
 
