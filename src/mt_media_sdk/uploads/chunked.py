"""Race-safe, resumable chunked upload service.

Public methods retained:
``initiate``, ``presign_part``, ``upload_part``, ``resume_info``,
``complete``, ``abort`` and ``expire_and_cleanup``.

New method:
``register_native_part`` (alias ``confirm_part``) records and server-verifies a
part uploaded through a presigned native-multipart URL.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from contextlib import closing
from dataclasses import dataclass
import math
import os
import re
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Optional

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Sum
from django.utils import timezone

from ..exceptions import (
    ChecksumMismatchError,
    InvalidStateTransitionError,
    PartOutOfRangeError,
    RateLimitExceededError,
    UploadSessionExpiredError,
)
from ..models import (
    LoadStatus,
    MediaFile,
    MediaLimit,
    UploadPart,
    UploadSession,
    UploadSessionStatus,
)
from ..progress.tracker import tracker as progress_tracker
from ..storage.base import UploadedPart
from ..storage.registry import get_storage_backend
from .validation import (
    UploadContext,
    ValidationPipeline,
    normalize_sha256,
    validate_completed_stream,
    validate_json_metadata,
)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_EXTENSION_RE = re.compile(r"^\.[a-z0-9]{1,16}$", re.I)
_MAX_ETAG_LENGTH = 1024
_COPY_BUFFER_BYTES = 1024 * 1024


def _setting(name: str, default: Any) -> Any:
    sentinel = object()
    try:
        configured = getattr(settings, name, sentinel)
        if configured is not sentinel:
            return configured
    except Exception:
        pass
    return os.environ.get(name, default)


def _parts_root() -> Path:
    configured = _setting("UPLOAD_CHUNK_STAGING_DIR", None)
    root = Path(configured or Path(tempfile.gettempdir()) / "media_upload_parts")
    root = root.expanduser().resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        logger.debug("Unable to tighten chunk staging directory permissions", exc_info=True)
    return root


def _session_uuid(session_id: Any) -> str:
    try:
        return str(uuid.UUID(str(session_id)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValidationError("upload session id must be a UUID") from exc


def _session_parts_dir(session_id: Any, *, create: bool = True) -> Path:
    root = _parts_root()
    path = root / _session_uuid(session_id)
    if create:
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
        try:
            path.chmod(0o700)
        except OSError:
            logger.debug("Unable to tighten session directory permissions", exc_info=True)
    return path


def _part_path(session_id: Any, part_number: int) -> Path:
    return _session_parts_dir(session_id) / f"{int(part_number):08d}.part"


def _normalize_etag(value: str) -> str:
    etag = str(value or "").strip()
    if not etag or len(etag) > _MAX_ETAG_LENGTH or _CONTROL_RE.search(etag):
        raise ValidationError("etag is missing or invalid")
    return etag


def _coerce_bytes(data: Any) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValidationError("part data must be bytes-like")
    value = bytes(data)
    if not value:
        raise PartOutOfRangeError("Upload parts must not be empty.")
    return value


def _total_parts(declared_size: int, chunk_size: int) -> int:
    if declared_size <= 0 or chunk_size <= 0:
        raise ValidationError("declared_size and chunk_size must be positive")
    return int(math.ceil(declared_size / chunk_size))


def _expected_part_size(declared_size: int, chunk_size: int, part_number: int) -> int:
    total = _total_parts(declared_size, chunk_size)
    if part_number < 1 or part_number > total:
        raise PartOutOfRangeError(
            f"Part {part_number} is outside the valid range 1..{total}.",
            part_number=part_number,
        )
    if part_number < total:
        return chunk_size
    return declared_size - (chunk_size * (total - 1))


@dataclass(slots=True)
class _LocalPartMutation:
    path: Path
    backup: Path
    had_previous: bool

    def commit(self) -> None:
        self.backup.unlink(missing_ok=True)

    def rollback(self) -> None:
        self.path.unlink(missing_ok=True)
        if self.had_previous and self.backup.exists():
            os.replace(self.backup, self.path)
        else:
            self.backup.unlink(missing_ok=True)


def _replace_local_part(path: Path, data: bytes) -> _LocalPartMutation:
    """Replace a staged part while retaining rollback data until DB commit."""

    reserve = int(_setting("UPLOAD_CHUNK_DISK_RESERVE_BYTES", 256 * 1024 * 1024))
    free = shutil.disk_usage(path.parent).free
    if free - len(data) < reserve:
        raise OSError("Insufficient staging-disk capacity for upload part")

    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    backup = path.with_name(f".{path.name}.{uuid.uuid4().hex}.backup")
    had_previous = path.exists()
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        if had_previous:
            os.replace(path, backup)
        os.replace(temporary, path)
        return _LocalPartMutation(path=path, backup=backup, had_previous=had_previous)
    except Exception:
        path.unlink(missing_ok=True)
        if had_previous and backup.exists():
            os.replace(backup, path)
        raise
    finally:
        temporary.unlink(missing_ok=True)


def _hash_stream(fileobj: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    try:
        fileobj.seek(0)
    except Exception:
        pass
    while True:
        block = fileobj.read(_COPY_BUFFER_BYTES)
        if not block:
            break
        if isinstance(block, str):
            block = block.encode("utf-8")
        digest.update(block)
        total += len(block)
    return digest.hexdigest(), total


class UploadSessionService:
    def __init__(
        self,
        storage_backend_name: Optional[str] = None,
        *,
        validation_pipeline: Optional[ValidationPipeline] = None,
    ) -> None:
        self.storage_backend_name = str(
            storage_backend_name
            or _setting("UPLOAD_STORAGE_BACKEND", "local")
        ).strip()
        if not self.storage_backend_name or _CONTROL_RE.search(self.storage_backend_name):
            raise ImproperlyConfigured("UPLOAD_STORAGE_BACKEND is invalid")
        self.storage = get_storage_backend(self.storage_backend_name)
        self.validation_pipeline = validation_pipeline or ValidationPipeline()

    # ------------------------------------------------------------------
    # Initiation
    # ------------------------------------------------------------------
    def initiate(
        self,
        *,
        user: Any,
        tenant_id: Optional[str],
        filename: str,
        mime_type: str,
        declared_size: int,
        checksum_expected: Optional[str] = None,
        chunk_size: Optional[int] = None,
    ) -> dict[str, Any]:
        if user is None or getattr(user, "pk", None) is None:
            raise ValidationError("A persisted user is required")

        context = self.validation_pipeline.run(
            UploadContext(
                filename=filename,
                mime_type=mime_type,
                size=declared_size,
                tenant_id=tenant_id,
                checksum=checksum_expected,
            )
        )
        limits = MediaLimit.get_solo(tenant_id=tenant_id)
        checksum_expected = context.checksum

        if checksum_expected:
            existing = MediaFile.objects.find_duplicate(
                checksum_expected,
                context.size,
                tenant_id=tenant_id,
            )
            if existing:
                return {
                    "deduplicated": True,
                    "media_file_id": str(existing.id),
                    "session": None,
                }

        resolved_chunk_size = self._validate_chunk_size(
            chunk_size if chunk_size is not None else limits.chunk_size_bytes,
            declared_size=context.size,
        )
        storage_path = self._build_storage_path(context.filename)

        # Lock the user row so concurrent initiation requests for the same user
        # cannot both pass the active-session count.
        with transaction.atomic():
            user_model = type(user)
            locked_user = user_model._default_manager.select_for_update().get(pk=user.pk)
            self._enforce_concurrency_limit(locked_user, limits)
            session = UploadSession.objects.create(
                tenant_id=tenant_id,
                user=locked_user,
                filename=context.filename,
                mime_type=context.mime_type,
                declared_size=context.size,
                chunk_size=resolved_chunk_size,
                checksum_expected=checksum_expected,
                storage_backend=self.storage_backend_name,
                storage_path=storage_path,
                expires_at=timezone.now() + _ttl(limits),
            )

        native_upload_id: Optional[str] = None
        if bool(getattr(self.storage, "supports_native_multipart", False)):
            try:
                native_upload_id = self.storage.initiate_multipart(
                    storage_path,
                    context.mime_type,
                )
            except NotImplementedError:
                native_upload_id = None
            except Exception:
                self._mark_failed(session)
                raise

        try:
            with transaction.atomic():
                locked = self._lock_session(session)
                if native_upload_id:
                    locked.native_upload_id = native_upload_id
                    locked.save(update_fields=["native_upload_id"])
                locked.transition(UploadSessionStatus.UPLOADING)
                session = locked
        except Exception:
            if native_upload_id:
                self._abort_native_best_effort(session, native_upload_id)
            self._mark_failed(session)
            raise

        return {
            "deduplicated": False,
            "session": session,
            "part_upload_mode": "native" if native_upload_id else "direct",
        }

    def _validate_chunk_size(self, value: Any, *, declared_size: int) -> int:
        try:
            chunk_size = int(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError("chunk_size must be an integer") from exc
        minimum = int(_setting("UPLOAD_MIN_CHUNK_SIZE_BYTES", 64 * 1024))
        maximum = int(_setting("UPLOAD_MAX_CHUNK_SIZE_BYTES", 128 * 1024 * 1024))
        if not minimum <= chunk_size <= maximum:
            raise ValidationError(
                f"chunk_size must be between {minimum} and {maximum} bytes"
            )
        total = _total_parts(declared_size, chunk_size)
        max_parts = int(
            _setting(
                "UPLOAD_MAX_MULTIPART_PARTS",
                10_000 if getattr(self.storage, "supports_native_multipart", False) else 100_000,
            )
        )
        if total > max_parts:
            raise ValidationError(
                f"chunk_size creates {total} parts, exceeding the {max_parts}-part limit"
            )
        return chunk_size

    def _enforce_concurrency_limit(self, user: Any, limits: MediaLimit) -> None:
        statuses = [UploadSessionStatus.INITIATED, UploadSessionStatus.UPLOADING]
        completing = getattr(UploadSessionStatus, "COMPLETING", None)
        if completing is not None:
            statuses.append(completing)
        active = UploadSession.objects.filter(user=user, status__in=statuses).count()
        limit = int(limits.max_concurrent_uploads_per_user)
        if active >= limit:
            raise RateLimitExceededError(
                f"You already have {active} uploads in progress (limit {limit}).",
                limit=limit,
            )

    def _build_storage_path(self, filename: str) -> str:
        suffix = Path(filename).suffix.casefold()
        if suffix and not _EXTENSION_RE.fullmatch(suffix):
            suffix = ""
        now = timezone.now()
        return "/".join(
            (
                "media",
                "uploads",
                str(now.year),
                f"{now.month:02d}",
                f"{uuid.uuid4().hex}{suffix}",
            )
        )

    # ------------------------------------------------------------------
    # Part upload and registration
    # ------------------------------------------------------------------
    def presign_part(
        self,
        session: UploadSession,
        part_number: int,
        *,
        expire_seconds: Optional[int] = None,
    ) -> Optional[dict[str, Any]]:
        current = self._fresh_session(session)
        self._guard_uploadable(current)
        self._guard_part_number(current, part_number)
        if not current.native_upload_id:
            return None
        expiry = int(
            expire_seconds
            if expire_seconds is not None
            else _setting("UPLOAD_PART_URL_EXPIRY_SECONDS", 900)
        )
        presigned = self.storage.presign_part(
            current.storage_path,
            current.native_upload_id,
            part_number,
            expire_seconds=expiry,
        )
        return {
            "method": presigned.method,
            "url": presigned.url,
            "headers": dict(getattr(presigned, "headers", {}) or {}),
            "fields": dict(getattr(presigned, "fields", {}) or {}),
            "expires_in": int(getattr(presigned, "expires_in", expiry)),
        }

    def upload_part(
        self,
        session: UploadSession,
        part_number: int,
        data: bytes,
        part_checksum: Optional[str] = None,
    ) -> UploadPart:
        payload = _coerce_bytes(data)
        expected_checksum = normalize_sha256(part_checksum)
        actual_checksum = hashlib.sha256(payload).hexdigest()
        if expected_checksum and not hmac.compare_digest(actual_checksum, expected_checksum):
            raise ChecksumMismatchError(
                "Part checksum mismatch.",
                part_number=part_number,
            )

        local_mutation: Optional[_LocalPartMutation] = None
        try:
            with transaction.atomic():
                locked = self._lock_session(session)
                self._guard_uploadable(locked)
                self._guard_part_number(locked, part_number)
                self._guard_part_size(locked, part_number, len(payload))

                if locked.native_upload_id:
                    uploaded = self.storage.write_part(
                        locked.storage_path,
                        locked.native_upload_id,
                        part_number,
                        payload,
                    )
                    storage_ref = _normalize_etag(uploaded.etag)
                else:
                    target = _part_path(locked.id, part_number)
                    local_mutation = _replace_local_part(target, payload)
                    storage_ref = str(target)

                part = self._upsert_part_locked(
                    locked,
                    part_number=part_number,
                    size=len(payload),
                    checksum=actual_checksum,
                    storage_ref=storage_ref,
                )
                uploaded_bytes = self._recalculate_uploaded_bytes_locked(locked)
        except Exception:
            if local_mutation is not None:
                local_mutation.rollback()
            raise
        else:
            if local_mutation is not None:
                local_mutation.commit()

        self._report_progress(locked, uploaded_bytes, LoadStatus.PROCESSING)
        return part

    def register_native_part(
        self,
        session: UploadSession,
        part_number: int,
        *,
        etag: Optional[str] = None,
        size: Optional[int] = None,
        part_checksum: Optional[str] = None,
    ) -> UploadPart:
        """Register a part uploaded directly through a presigned URL.

        When the storage backend implements ``list_multipart_parts``, the
        server's ETag and size are authoritative and client values are only
        cross-checked.  Production defaults fail closed when server-side
        inspection is unavailable.
        """

        with transaction.atomic():
            locked = self._lock_session(session)
            self._guard_uploadable(locked)
            self._guard_part_number(locked, part_number)
            if not locked.native_upload_id:
                raise InvalidStateTransitionError(
                    "The upload session is not using native multipart storage."
                )

            verified = self._inspect_native_part(locked, part_number)
            if verified is not None:
                verified_etag = _normalize_etag(verified.etag)
                verified_size = int(verified.size)
                if etag is not None and not hmac.compare_digest(
                    verified_etag,
                    _normalize_etag(etag),
                ):
                    raise ChecksumMismatchError(
                        "Native part ETag does not match storage.",
                        part_number=part_number,
                    )
                if size is not None and int(size) != verified_size:
                    raise ChecksumMismatchError(
                        "Native part size does not match storage.",
                        part_number=part_number,
                    )
                etag = verified_etag
                size = verified_size
            elif self._require_verified_native_parts():
                raise ImproperlyConfigured(
                    "The storage backend must implement list_multipart_parts() "
                    "before presigned multipart uploads can be confirmed."
                )

            normalized_etag = _normalize_etag(str(etag or ""))
            try:
                normalized_size = int(size)
            except (TypeError, ValueError) as exc:
                raise ValidationError("size is required for a native part") from exc
            self._guard_part_size(locked, part_number, normalized_size)
            checksum = normalize_sha256(part_checksum) or ""

            part = self._upsert_part_locked(
                locked,
                part_number=part_number,
                size=normalized_size,
                checksum=checksum,
                storage_ref=normalized_etag,
            )
            uploaded_bytes = self._recalculate_uploaded_bytes_locked(locked)

        self._report_progress(locked, uploaded_bytes, LoadStatus.PROCESSING)
        return part

    confirm_part = register_native_part

    def _inspect_native_part(
        self,
        session: UploadSession,
        part_number: int,
    ) -> Optional[UploadedPart]:
        list_parts = getattr(self.storage, "list_multipart_parts", None)
        if not callable(list_parts):
            return None
        try:
            parts: Iterable[UploadedPart] = list_parts(
                session.storage_path,
                session.native_upload_id,
            )
        except NotImplementedError:
            return None
        matches = [part for part in parts if int(part.part_number) == int(part_number)]
        if len(matches) != 1:
            raise PartOutOfRangeError(
                f"Storage did not report exactly one uploaded part {part_number}.",
                part_number=part_number,
            )
        return matches[0]

    def _require_verified_native_parts(self) -> bool:
        configured = _setting("UPLOAD_REQUIRE_SERVER_VERIFIED_NATIVE_PARTS", None)
        if configured is not None:
            return bool(configured)
        return not bool(_setting("DEBUG", False))

    def _guard_part_size(
        self,
        session: UploadSession,
        part_number: int,
        actual_size: int,
    ) -> None:
        expected = _expected_part_size(
            int(session.declared_size),
            int(session.chunk_size),
            int(part_number),
        )
        strict = bool(_setting("UPLOAD_REQUIRE_EXACT_PART_SIZES", True))
        if strict and actual_size != expected:
            raise PartOutOfRangeError(
                f"Part {part_number} must contain exactly {expected} bytes; received {actual_size}.",
                part_number=part_number,
            )
        if not strict and (actual_size <= 0 or actual_size > int(session.chunk_size)):
            raise PartOutOfRangeError(
                f"Part {part_number} must be between 1 and {session.chunk_size} bytes.",
                part_number=part_number,
            )

    def _upsert_part_locked(
        self,
        session: UploadSession,
        *,
        part_number: int,
        size: int,
        checksum: str,
        storage_ref: str,
    ) -> UploadPart:
        part = UploadPart.objects.filter(
            session=session,
            part_number=part_number,
        ).first()
        if part is None:
            try:
                return UploadPart.objects.create(
                    session=session,
                    part_number=part_number,
                    size=size,
                    checksum=checksum,
                    storage_ref=storage_ref,
                )
            except IntegrityError:
                part = UploadPart.objects.select_for_update().get(
                    session=session,
                    part_number=part_number,
                )
        part.size = size
        part.checksum = checksum
        part.storage_ref = storage_ref
        part.save(update_fields=["size", "checksum", "storage_ref"])
        return part

    def _recalculate_uploaded_bytes_locked(self, session: UploadSession) -> int:
        uploaded = int(
            UploadPart.objects.filter(session=session).aggregate(total=Sum("size"))["total"]
            or 0
        )
        session.uploaded_bytes = uploaded
        session.save(update_fields=["uploaded_bytes"])
        return uploaded

    # ------------------------------------------------------------------
    # Resume and completion
    # ------------------------------------------------------------------
    def resume_info(self, session: UploadSession) -> dict[str, Any]:
        current = self._fresh_session(session)
        expired = bool(current.is_expired())
        received = sorted(int(value) for value in current.received_part_numbers())
        return {
            "session_id": str(current.id),
            "status": current.status,
            "total_parts": int(current.total_parts),
            "chunk_size": int(current.chunk_size),
            "received_parts": received,
            "missing_parts": list(current.missing_part_numbers()),
            "uploaded_bytes": int(current.uploaded_bytes),
            "declared_size": int(current.declared_size),
            "expired": expired,
            "expires_at": current.expires_at.isoformat() if current.expires_at else None,
            "part_upload_mode": "native" if current.native_upload_id else "direct",
        }

    def complete(
        self,
        session: UploadSession,
        *,
        owner: Any = None,
        is_public: bool = False,
        metadata: Optional[dict[str, Any]] = None,
    ) -> MediaFile:
        metadata = validate_json_metadata(metadata)

        with transaction.atomic():
            locked = self._lock_session(session)
            if locked.status == UploadSessionStatus.COMPLETED:
                if getattr(locked, "media_file", None) is None:
                    raise InvalidStateTransitionError(
                        "Completed upload session has no media file reference."
                    )
                return locked.media_file
            self._guard_completable(locked)
            parts = list(
                UploadPart.objects.select_for_update()
                .filter(session=locked)
                .order_by("part_number")
            )
            self._validate_complete_part_set(locked, parts)
            locked.transition(UploadSessionStatus.COMPLETING)
            session_id = locked.pk

        stored_new_object = False
        created_media_file: Optional[MediaFile] = None
        assembled_path: Optional[Path] = None
        try:
            current = UploadSession.objects.get(pk=session_id)
            if current.native_upload_id:
                # Completion may create the final object before checksum or content
                # validation fails, so enable compensating deletion first.
                stored_new_object = True
                checksum, size = self._complete_native(current, parts)
                existing = self._find_duplicate(current, checksum, size)
                if existing is not None:
                    self._delete_storage_best_effort(current.storage_path)
                    stored_new_object = False
                    media_file = existing
                else:
                    media_file, media_created = self._create_media_file(
                        current,
                        owner=owner,
                        is_public=is_public,
                        metadata=metadata,
                        checksum=checksum,
                        size=size,
                    )
                    if media_created:
                        created_media_file = media_file
            else:
                assembled_path, checksum, size = self._assemble_local_parts(current, parts)
                self._validate_final_integrity(current, checksum, size)
                with assembled_path.open("rb") as handle:
                    validate_completed_stream(
                        handle,
                        filename=current.filename,
                        mime_type=current.mime_type,
                        expected_size=size,
                        expected_checksum=checksum,
                    )
                existing = self._find_duplicate(current, checksum, size)
                if existing is not None:
                    media_file = existing
                else:
                    stored_new_object = True
                    with assembled_path.open("rb") as handle:
                        saved_size = int(self.storage.save(current.storage_path, handle))
                    if saved_size != size:
                        self._delete_storage_best_effort(current.storage_path)
                        raise ChecksumMismatchError(
                            "Storage reported a size different from the assembled upload."
                        )
                    media_file, media_created = self._create_media_file(
                        current,
                        owner=owner,
                        is_public=is_public,
                        metadata=metadata,
                        checksum=checksum,
                        size=size,
                    )
                    if media_created:
                        created_media_file = media_file

            with transaction.atomic():
                locked = UploadSession.objects.select_for_update().get(pk=session_id)
                if locked.status == UploadSessionStatus.COMPLETED:
                    return locked.media_file
                if locked.status != UploadSessionStatus.COMPLETING:
                    raise InvalidStateTransitionError(
                        f"Session {locked.id} left the completing state unexpectedly."
                    )
                locked.checksum_actual = checksum
                locked.media_file = media_file
                locked.uploaded_bytes = size
                locked.save(
                    update_fields=["checksum_actual", "media_file", "uploaded_bytes"]
                )
                locked.transition(UploadSessionStatus.COMPLETED)

            self._cleanup_local_parts(current)
            self._report_progress(current, size, LoadStatus.COMPLETED)
            return media_file
        except Exception:
            if stored_new_object:
                self._delete_storage_best_effort(getattr(session, "storage_path", ""))
            if created_media_file is not None:
                try:
                    created_media_file.delete()
                except Exception:
                    logger.error(
                        "Unable to remove media row after upload finalization failure",
                        exc_info=True,
                    )
            self._mark_failed(session)
            self._report_progress(
                session,
                int(getattr(session, "uploaded_bytes", 0) or 0),
                LoadStatus.FAILED,
            )
            raise
        finally:
            if assembled_path is not None:
                assembled_path.unlink(missing_ok=True)

    def _validate_complete_part_set(
        self,
        session: UploadSession,
        parts: list[UploadPart],
    ) -> None:
        total_parts = _total_parts(int(session.declared_size), int(session.chunk_size))
        numbers = [int(part.part_number) for part in parts]
        expected_numbers = list(range(1, total_parts + 1))
        if numbers != expected_numbers:
            missing = sorted(set(expected_numbers) - set(numbers))
            raise PartOutOfRangeError(
                f"Missing or duplicate parts: {missing[:10]}",
                missing=missing,
            )
        for part in parts:
            self._guard_part_size(session, int(part.part_number), int(part.size))
            if session.native_upload_id:
                _normalize_etag(part.storage_ref)
            else:
                path = Path(str(part.storage_ref)).resolve()
                expected_parent = _session_parts_dir(session.id, create=False).resolve()
                if path.parent != expected_parent or not path.is_file():
                    raise PartOutOfRangeError(
                        f"Staged part {part.part_number} is missing or outside its session directory.",
                        part_number=part.part_number,
                    )
                with path.open("rb") as handle:
                    actual_checksum, actual_size = _hash_stream(handle)
                if actual_size != int(part.size):
                    raise ChecksumMismatchError(
                        "Staged part size does not match its database record.",
                        part_number=part.part_number,
                    )
                if part.checksum and not hmac.compare_digest(
                    actual_checksum,
                    str(part.checksum).casefold(),
                ):
                    raise ChecksumMismatchError(
                        "Staged part checksum does not match its database record.",
                        part_number=part.part_number,
                    )
        total_size = sum(int(part.size) for part in parts)
        if total_size != int(session.declared_size):
            raise ChecksumMismatchError(
                "The sum of uploaded part sizes does not equal declared_size."
            )
        session.uploaded_bytes = total_size
        session.save(update_fields=["uploaded_bytes"])

    def _assemble_local_parts(
        self,
        session: UploadSession,
        parts: list[UploadPart],
    ) -> tuple[Path, str, int]:
        parts_dir = _session_parts_dir(session.id)
        fd, temporary_name = tempfile.mkstemp(prefix=".assembled.", dir=parts_dir)
        assembled = Path(temporary_name)
        digest = hashlib.sha256()
        total = 0
        try:
            with os.fdopen(fd, "wb") as output:
                for part in parts:
                    with Path(part.storage_ref).open("rb") as source:
                        while True:
                            block = source.read(_COPY_BUFFER_BYTES)
                            if not block:
                                break
                            output.write(block)
                            digest.update(block)
                            total += len(block)
                output.flush()
                os.fsync(output.fileno())
            try:
                assembled.chmod(0o600)
            except OSError:
                pass
            self._validate_final_integrity(session, digest.hexdigest(), total)
            return assembled, digest.hexdigest(), total
        except Exception:
            assembled.unlink(missing_ok=True)
            raise

    def _complete_native(
        self,
        session: UploadSession,
        parts: list[UploadPart],
    ) -> tuple[Optional[str], int]:
        native_parts = [
            UploadedPart(
                part_number=int(part.part_number),
                etag=_normalize_etag(part.storage_ref),
                size=int(part.size),
            )
            for part in parts
        ]
        self.storage.complete_multipart(
            session.storage_path,
            session.native_upload_id,
            native_parts,
        )
        if not self.storage.exists(session.storage_path):
            raise ChecksumMismatchError("Completed native object does not exist in storage.")
        size = int(self.storage.size(session.storage_path))
        if size != int(session.declared_size):
            raise ChecksumMismatchError(
                "Completed native object size does not equal declared_size."
            )
        checksum: Optional[str] = None
        verify_checksum = bool(
            session.checksum_expected
            or _setting("UPLOAD_VERIFY_NATIVE_CHECKSUM", True)
        )
        if verify_checksum:
            with closing(self.storage.open(session.storage_path)) as handle:
                checksum, streamed_size = _hash_stream(handle)
            if streamed_size != size:
                raise ChecksumMismatchError(
                    "Native object changed while its checksum was being verified."
                )
        with closing(self.storage.open(session.storage_path)) as handle:
            validate_completed_stream(
                handle,
                filename=session.filename,
                mime_type=session.mime_type,
                expected_size=size,
                expected_checksum=checksum or session.checksum_expected,
            )
        self._validate_final_integrity(session, checksum, size)
        return checksum or session.checksum_expected, size

    def _validate_final_integrity(
        self,
        session: UploadSession,
        checksum: Optional[str],
        size: int,
    ) -> None:
        if size != int(session.declared_size):
            raise ChecksumMismatchError(
                f"Completed upload is {size} bytes; expected {session.declared_size}."
            )
        expected = normalize_sha256(session.checksum_expected)
        if expected:
            if not checksum:
                raise ChecksumMismatchError(
                    "A declared checksum could not be verified against completed bytes."
                )
            if not hmac.compare_digest(expected, str(checksum).casefold()):
                raise ChecksumMismatchError(
                    "Assembled file checksum does not match the client's declaration."
                )

    def _find_duplicate(
        self,
        session: UploadSession,
        checksum: Optional[str],
        size: int,
    ) -> Optional[MediaFile]:
        if not checksum:
            return None
        return MediaFile.objects.find_duplicate(
            checksum,
            size,
            tenant_id=session.tenant_id,
        )

    def _create_media_file(
        self,
        session: UploadSession,
        *,
        owner: Any,
        is_public: bool,
        metadata: dict[str, Any],
        checksum: Optional[str],
        size: int,
    ) -> tuple[MediaFile, bool]:
        try:
            with transaction.atomic():
                media_file = MediaFile.objects.create(
                    tenant_id=session.tenant_id,
                    owner=owner or session.user,
                    original_filename=session.filename,
                    mime_type=session.mime_type,
                    size=size,
                    checksum=checksum,
                    storage_backend=session.storage_backend,
                    is_public=bool(is_public),
                    metadata=metadata,
                )
                media_file.file.name = session.storage_path
                media_file.save(update_fields=["file"])
                return media_file, True
        except IntegrityError:
            duplicate = self._find_duplicate(session, checksum, size)
            if duplicate is None:
                raise
            duplicate_name = str(getattr(getattr(duplicate, "file", None), "name", "") or "")
            if duplicate_name != session.storage_path:
                self._delete_storage_best_effort(session.storage_path)
            return duplicate, False

    # ------------------------------------------------------------------
    # Abort and expiry
    # ------------------------------------------------------------------
    def abort(self, session: UploadSession) -> None:
        with transaction.atomic():
            locked = self._lock_session(session)
            if locked.status == UploadSessionStatus.ABORTED:
                return
            if locked.status == UploadSessionStatus.COMPLETED:
                raise InvalidStateTransitionError("A completed upload cannot be aborted.")
            if locked.status == UploadSessionStatus.COMPLETING:
                raise InvalidStateTransitionError("An upload cannot be aborted while completing.")
            if locked.native_upload_id:
                self.storage.abort_multipart(
                    locked.storage_path,
                    locked.native_upload_id,
                )
            self._cleanup_local_parts(locked)
            locked.transition(UploadSessionStatus.ABORTED)
        self._report_progress(locked, int(locked.uploaded_bytes or 0), LoadStatus.FAILED)

    def expire_and_cleanup(self, session: UploadSession) -> None:
        with transaction.atomic():
            locked = self._lock_session(session)
            if locked.status in (
                UploadSessionStatus.COMPLETED,
                UploadSessionStatus.ABORTED,
                UploadSessionStatus.EXPIRED,
            ):
                return
            if locked.status == UploadSessionStatus.COMPLETING:
                raise InvalidStateTransitionError(
                    "A completing upload must be resolved before expiry cleanup."
                )
            if locked.native_upload_id:
                self.storage.abort_multipart(
                    locked.storage_path,
                    locked.native_upload_id,
                )
            self._cleanup_local_parts(locked)
            locked.transition(UploadSessionStatus.EXPIRED)
        self._report_progress(locked, int(locked.uploaded_bytes or 0), LoadStatus.FAILED)

    # ------------------------------------------------------------------
    # State, cleanup and progress helpers
    # ------------------------------------------------------------------
    def _lock_session(self, session: UploadSession) -> UploadSession:
        pk = getattr(session, "pk", None)
        if pk is None:
            raise ValidationError("A persisted upload session is required")
        return UploadSession.objects.select_for_update().get(pk=pk)

    def _fresh_session(self, session: UploadSession) -> UploadSession:
        pk = getattr(session, "pk", None)
        if pk is None:
            raise ValidationError("A persisted upload session is required")
        return UploadSession.objects.get(pk=pk)

    def _guard_not_expired(self, session: UploadSession) -> None:
        if session.is_expired():
            expires = session.expires_at.isoformat() if session.expires_at else "unknown"
            raise UploadSessionExpiredError(
                f"Session {session.id} expired at {expires}."
            )

    def _guard_uploadable(self, session: UploadSession) -> None:
        self._guard_not_expired(session)
        if session.status not in (
            UploadSessionStatus.INITIATED,
            UploadSessionStatus.UPLOADING,
        ):
            raise InvalidStateTransitionError(
                f"Session {session.id} is {session.status!r}, not accepting parts."
            )

    def _guard_completable(self, session: UploadSession) -> None:
        self._guard_not_expired(session)
        if session.status not in (
            UploadSessionStatus.INITIATED,
            UploadSessionStatus.UPLOADING,
        ):
            raise InvalidStateTransitionError(
                f"Session {session.id} is {session.status!r}, not completable."
            )

    def _guard_part_number(self, session: UploadSession, part_number: int) -> None:
        try:
            number = int(part_number)
        except (TypeError, ValueError) as exc:
            raise PartOutOfRangeError("part_number must be an integer") from exc
        total = _total_parts(int(session.declared_size), int(session.chunk_size))
        if number < 1 or number > total:
            raise PartOutOfRangeError(
                f"Part {number} is outside the valid range 1..{total}.",
                part_number=number,
            )

    def _cleanup_local_parts(self, session: UploadSession) -> None:
        path = _session_parts_dir(session.id, create=False)
        try:
            shutil.rmtree(path)
        except FileNotFoundError:
            return
        except OSError:
            logger.warning("Unable to remove local upload parts for session %s", session.id, exc_info=True)

    def _delete_storage_best_effort(self, path: str) -> None:
        if not path:
            return
        try:
            if self.storage.exists(path):
                self.storage.delete(path)
        except Exception:
            logger.error("Unable to remove incomplete uploaded object", exc_info=True)

    def _abort_native_best_effort(
        self,
        session: UploadSession,
        upload_id: str,
    ) -> None:
        try:
            self.storage.abort_multipart(session.storage_path, upload_id)
        except Exception:
            logger.error("Unable to abort native multipart initiation", exc_info=True)

    def _mark_failed(self, session: UploadSession) -> None:
        try:
            with transaction.atomic():
                locked = self._lock_session(session)
                if locked.status in (
                    UploadSessionStatus.COMPLETED,
                    UploadSessionStatus.ABORTED,
                    UploadSessionStatus.EXPIRED,
                    UploadSessionStatus.FAILED,
                ):
                    return
                locked.transition(UploadSessionStatus.FAILED)
        except Exception:
            logger.error("Unable to mark upload session as failed", exc_info=True)

    def _report_progress(
        self,
        session: UploadSession,
        uploaded_bytes: int,
        status: Any,
    ) -> None:
        try:
            declared = int(getattr(session, "declared_size", 0) or 0)
            percent = min(100.0, (uploaded_bytes / declared) * 100.0) if declared else 0.0
            progress_tracker.update_progress_by_file_id(
                str(session.id),
                percent,
                status=status,
            )
        except Exception:
            logger.warning("Unable to update upload progress for session %s", session.id, exc_info=True)


def _ttl(limits: MediaLimit):
    from datetime import timedelta

    try:
        hours = int(limits.upload_session_ttl_hours)
    except (TypeError, ValueError) as exc:
        raise ImproperlyConfigured("upload_session_ttl_hours must be an integer") from exc
    if hours < 1 or hours > int(_setting("UPLOAD_MAX_SESSION_TTL_HOURS", 168)):
        raise ImproperlyConfigured("upload_session_ttl_hours is outside the allowed range")
    return timedelta(hours=hours)
