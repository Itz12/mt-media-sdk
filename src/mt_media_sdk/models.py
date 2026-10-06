
"""
media.models
------------
Merged, hardened media models.

This file combines the feature set from both provided versions:
- tenant-aware MediaLimit / MediaFile / UploadSession scoping
- checksum, size, MIME, image/video metadata
- soft delete + restore
- optimistic concurrency for MediaFile status updates
- resumable upload sessions with explicit state transitions
- upload parts
- background Load tracking with retry orchestration
- generic user interaction analytics
- maintenance helpers for cleanup tasks

Apply migrations after replacing this file:
    python manage.py makemigrations media
    python manage.py migrate
"""
from __future__ import annotations

import hashlib
import logging
import mimetypes
import os
import uuid
from datetime import timedelta
from typing import Optional

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.db.models.functions import Coalesce
from django.utils import timezone

logger = logging.getLogger(__name__)

try:
    from django.db.models import JSONField  # Django >= 3.1
except Exception:  # pragma: no cover - fallback for older Django
    from django.contrib.postgres.fields import JSONField  # type: ignore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def media_upload_to(instance, filename: str) -> str:
    base, ext = os.path.splitext(filename or "")
    safe_name = "".join(ch for ch in (base or "") if ch.isalnum() or ch in (" ", "-", "_")).strip()
    now = timezone.now()
    return os.path.join(
        "media",
        instance.__class__.__name__.lower(),
        str(now.year),
        f"{now.month:02}",
        f"{uuid.uuid4().hex}_{safe_name}{(ext or '').lower()}",
    )


def default_chunk_size() -> int:
    return getattr(settings, "UPLOAD_DEFAULT_CHUNK_SIZE", 8 * 1024 * 1024)  # 8 MiB


def default_session_ttl() -> timedelta:
    return timedelta(hours=getattr(settings, "UPLOAD_SESSION_TTL_HOURS", 24))


# ---------------------------------------------------------------------------
# MediaLimit
# ---------------------------------------------------------------------------
class MediaLimit(models.Model):
    """
    A row with tenant_id=None is the global default; a row with a concrete
    tenant_id overrides it for that tenant. Resolution order:
    tenant-specific row -> global row -> hard-coded field defaults.
    """

    tenant_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)

    image = models.BigIntegerField(default=10 * 1024 * 1024, help_text="Max image size (bytes).")
    audio = models.BigIntegerField(default=10 * 1024 * 1024, help_text="Max audio size (bytes).")
    video = models.BigIntegerField(default=50 * 1024 * 1024, help_text="Max video size (bytes).")
    text = models.BigIntegerField(default=5 * 1024 * 1024, help_text="Max text size (bytes).")
    document = models.BigIntegerField(default=10 * 1024 * 1024, help_text="Max document size (bytes).")

    max_concurrent_uploads_per_user = models.PositiveIntegerField(default=5)
    upload_session_ttl_hours = models.PositiveIntegerField(default=24)
    chunk_size_bytes = models.PositiveIntegerField(default=8 * 1024 * 1024)
    requires_virus_scan = models.BooleanField(default=True)
    allowed_extensions = JSONField(default=list, blank=True, help_text="Empty list = no allow-list restriction.")
    blocked_extensions = JSONField(default=list, blank=True)

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Media Limit"
        verbose_name_plural = "Media Limits"
        constraints = [
            models.UniqueConstraint(
                Coalesce("tenant_id", models.Value("")),
                name="unique_medialimit_per_tenant",
            ),
        ]

    def clean(self):
        self.tenant_id = str(self.tenant_id or "").strip() or None
        for field in ("image", "audio", "video", "text", "document"):
            val = getattr(self, field)
            if val is not None and val < 0:
                raise ValidationError({field: "Must be non-negative."})

    def save(self, *args, **kwargs):
        self.tenant_id = str(self.tenant_id or "").strip() or None
        return super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"MediaLimit(tenant={self.tenant_id or 'global'})"

    @classmethod
    def get_solo(cls, tenant_id: Optional[str] = None) -> "MediaLimit":
        if tenant_id:
            obj = cls.objects.filter(tenant_id=tenant_id).first()
            if obj:
                return obj
        obj = cls.objects.filter(tenant_id__isnull=True).first()
        if obj is None:
            obj = cls.objects.create(tenant_id=None)
        return obj


# ---------------------------------------------------------------------------
# MediaFile
# ---------------------------------------------------------------------------
class MediaStatus(models.TextChoices):
    UPLOADED = "uploaded", "Uploaded"
    PROCESSING = "processing", "Processing"
    READY = "ready", "Ready"
    FAILED = "failed", "Failed"
    ARCHIVED = "archived", "Archived"
    QUARANTINED = "quarantined", "Quarantined"


class ScanStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    CLEAN = "clean", "Clean"
    INFECTED = "infected", "Infected"
    SKIPPED = "skipped", "Skipped"
    ERROR = "error", "Error"


class MediaFileManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(deleted=False)

    def find_duplicate(self, checksum: str, size: int, tenant_id: Optional[str] = None):
        """Find a reusable upload strictly within the requested tenant scope."""
        if not checksum:
            return None
        qs = self.filter(
            checksum=checksum,
            size=size,
            status__in=[MediaStatus.READY, MediaStatus.UPLOADED, MediaStatus.PROCESSING],
            tenant_id=tenant_id,
        )
        return qs.order_by("created_at").first()


class MediaFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="media_files",
        null=True,
        blank=True,
        help_text="Optional user that uploaded/owns this file.",
    )

    content_type = models.ForeignKey(ContentType, null=True, blank=True, on_delete=models.SET_NULL)
    object_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    attached_object = GenericForeignKey("content_type", "object_id")

    file = models.FileField(upload_to=media_upload_to, max_length=1024)
    storage_backend = models.CharField(max_length=64, default="local", help_text="Key into media.storage.registry.")

    original_filename = models.CharField(max_length=1024, blank=True, help_text="Original filename provided by client.")
    mime_type = models.CharField(max_length=255, db_index=True, blank=True, help_text="MIME type (content-type).")
    size = models.BigIntegerField(db_index=True, null=True, blank=True, help_text="Size in bytes.")
    checksum = models.CharField(max_length=128, db_index=True, null=True, blank=True, help_text="SHA256 checksum.")

    width = models.IntegerField(null=True, blank=True, db_index=True)
    height = models.IntegerField(null=True, blank=True)
    duration_ms = models.BigIntegerField(null=True, blank=True, help_text="Duration in milliseconds for audio/video.")

    status = models.CharField(max_length=32, choices=MediaStatus.choices, default=MediaStatus.UPLOADED, db_index=True)
    scan_status = models.CharField(max_length=32, choices=ScanStatus.choices, default=ScanStatus.PENDING, db_index=True)
    scan_detail = models.TextField(null=True, blank=True)
    processing_error = models.TextField(null=True, blank=True)

    is_public = models.BooleanField(default=False, db_index=True)
    metadata = JSONField(default=dict, blank=True, help_text="Arbitrary structured metadata from processing pipelines.")

    original = models.ForeignKey("self", null=True, blank=True, related_name="derivatives", on_delete=models.SET_NULL)

    # Optimistic-concurrency guard.
    version = models.PositiveIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    objects = MediaFileManager()
    all_objects = models.Manager()

    class Meta:
        indexes = [
            models.Index(fields=["owner", "created_at"]),
            models.Index(fields=["mime_type", "status"]),
            models.Index(fields=["checksum", "size"]),
            models.Index(fields=["tenant_id", "status"]),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"MediaFile({self.id}, {self.original_filename or getattr(self.file, 'name', '')})"

    def clean(self):
        self.validate_size_against_limits()

    # ---- lifecycle ---------------------------------------------------
    def soft_delete(self) -> None:
        self.deleted = True
        self.deleted_at = timezone.now()
        self.save(update_fields=["deleted", "deleted_at", "updated_at"])

    def restore(self) -> None:
        self.deleted = False
        self.deleted_at = None
        self.save(update_fields=["deleted", "deleted_at", "updated_at"])

    def transition_status(self, new_status: str, *, error: Optional[str] = None) -> None:
        """
        Race-safe status transition guarded by version. Raises ValidationError
        if another writer updated the row in between.
        """
        with transaction.atomic():
            updated = MediaFile.all_objects.filter(pk=self.pk, version=self.version).update(
                status=new_status,
                processing_error=error,
                version=models.F("version") + 1,
                updated_at=timezone.now(),
            )
            if not updated:
                raise ValidationError("Concurrent modification detected; reload and retry.")
            self.refresh_from_db(fields=["status", "processing_error", "version", "updated_at"])

    # ---- checksum ----------------------------------------------------
    def compute_checksum(self, chunk_size: int = 1024 * 1024) -> Optional[str]:
        if not self.file or not getattr(self.file, "name", None):
            return None
        sha = hashlib.sha256()
        try:
            try:
                self.file.open("rb")
                file_obj = self.file
            except Exception:
                file_obj = self.file.storage.open(self.file.name, "rb")
            try:
                chunks = file_obj.chunks(chunk_size) if hasattr(file_obj, "chunks") else iter(lambda: file_obj.read(chunk_size), b"")
                for chunk in chunks:
                    sha.update(chunk)
                return sha.hexdigest()
            finally:
                try:
                    file_obj.close()
                except Exception:
                    pass
        except Exception:
            return None

    def validate_size_against_limits(self) -> None:
        limits = MediaLimit.get_solo(tenant_id=self.tenant_id)
        mt = (self.mime_type or "").lower()
        max_size = (
            limits.image if mt.startswith("image/") else
            limits.audio if mt.startswith("audio/") else
            limits.video if mt.startswith("video/") else
            limits.text if mt.startswith("text/") else
            limits.document
        )
        if self.size is not None and max_size and self.size > max_size:
            raise ValidationError(f"File exceeds allowed size for type (max {max_size} bytes).")

    def _infer_mime_and_size(self) -> None:
        if not self.mime_type and getattr(self.file, "name", None):
            guessed, _ = mimetypes.guess_type(self.file.name)
            if guessed:
                self.mime_type = guessed
        if (self.size is None or self.size == 0) and getattr(self.file, "size", None) not in (None, 0):
            try:
                self.size = int(self.file.size)
            except Exception:
                pass

    def save(self, *args, **kwargs):
        if not self.original_filename and getattr(self.file, "name", None):
            self.original_filename = os.path.basename(self.file.name)
        try:
            self._infer_mime_and_size()
        except Exception:
            pass
        self.validate_size_against_limits()
        super().save(*args, **kwargs)
        if not self.checksum:
            ch = self.compute_checksum()
            if ch:
                try:
                    MediaFile.all_objects.filter(pk=self.pk).update(checksum=ch)
                    self.checksum = ch
                except Exception:
                    pass

    def get_url(self, expire_seconds: int = 60) -> Optional[str]:
        if not self.file or not getattr(self.file, "name", None):
            return None
        try:
            from .storage.registry import get_storage_backend
            backend = get_storage_backend(self.storage_backend)
            if not self.is_public and not getattr(
                backend, "supports_private_download_urls", False
            ):
                return None
            return backend.url(self.file.name, expire_seconds=expire_seconds)
        except Exception:
            try:
                storage = self.file.storage
                gen = getattr(storage, "generate_presigned_url", None)
                if callable(gen):
                    return gen(self.file.name, expires_in=expire_seconds)
            except Exception:
                pass
            if not self.is_public:
                return None
            try:
                return self.file.url
            except Exception:
                return None


# ---------------------------------------------------------------------------
# UploadSession / UploadPart
# ---------------------------------------------------------------------------
class UploadSessionStatus(models.TextChoices):
    INITIATED = "initiated", "Initiated"
    UPLOADING = "uploading", "Uploading"
    COMPLETING = "completing", "Completing"
    COMPLETED = "completed", "Completed"
    ABORTED = "aborted", "Aborted"
    EXPIRED = "expired", "Expired"
    FAILED = "failed", "Failed"


_SESSION_TRANSITIONS: dict[str, set[str]] = {
    UploadSessionStatus.INITIATED: {
        UploadSessionStatus.UPLOADING,
        UploadSessionStatus.ABORTED,
        UploadSessionStatus.EXPIRED,
        UploadSessionStatus.COMPLETING,
    },
    UploadSessionStatus.UPLOADING: {
        UploadSessionStatus.UPLOADING,
        UploadSessionStatus.COMPLETING,
        UploadSessionStatus.ABORTED,
        UploadSessionStatus.EXPIRED,
        UploadSessionStatus.FAILED,
    },
    UploadSessionStatus.COMPLETING: {
        UploadSessionStatus.COMPLETED,
        UploadSessionStatus.FAILED,
        UploadSessionStatus.UPLOADING,
    },
    UploadSessionStatus.COMPLETED: set(),
    UploadSessionStatus.ABORTED: set(),
    UploadSessionStatus.EXPIRED: set(),
    UploadSessionStatus.FAILED: {UploadSessionStatus.UPLOADING, UploadSessionStatus.ABORTED},
}


class UploadSession(models.Model):
    """
    A resumable upload in progress.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="upload_sessions")

    filename = models.CharField(max_length=1024)
    mime_type = models.CharField(max_length=255, blank=True)
    declared_size = models.BigIntegerField(null=True, blank=True)
    chunk_size = models.PositiveIntegerField(default=default_chunk_size)
    total_parts = models.PositiveIntegerField(null=True, blank=True)

    checksum_expected = models.CharField(max_length=128, null=True, blank=True)
    checksum_actual = models.CharField(max_length=128, null=True, blank=True)

    storage_backend = models.CharField(max_length=64, default="local")
    storage_path = models.CharField(max_length=1024, help_text="Final destination key/path once completed.")
    native_upload_id = models.CharField(
        max_length=512,
        null=True,
        blank=True,
        help_text="Cloud-native multipart upload id (e.g. S3 UploadId), if applicable.",
    )

    uploaded_bytes = models.BigIntegerField(default=0)
    status = models.CharField(max_length=32, choices=UploadSessionStatus.choices, default=UploadSessionStatus.INITIATED, db_index=True)
    error_message = models.TextField(null=True, blank=True)
    metadata = JSONField(default=dict, blank=True)

    media_file = models.OneToOneField(MediaFile, null=True, blank=True, on_delete=models.SET_NULL, related_name="source_session")

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(db_index=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "status"]),
            models.Index(fields=["status", "expires_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"UploadSession({self.id}, {self.filename}, {self.status})"

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + default_session_ttl()
        if self.declared_size and self.chunk_size:
            self.total_parts = -(-self.declared_size // self.chunk_size)
        super().save(*args, **kwargs)

    def clean(self):
        if self.declared_size is not None and self.declared_size < 0:
            raise ValidationError({"declared_size": "Must be non-negative."})
        if self.chunk_size is not None and self.chunk_size <= 0:
            raise ValidationError({"chunk_size": "Must be greater than zero."})

    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at

    def extend_expiry(self, hours: int = 1) -> None:
        new_expiry = timezone.now() + timedelta(hours=hours)
        UploadSession.objects.filter(pk=self.pk).update(expires_at=new_expiry)
        self.expires_at = new_expiry

    def transition(self, new_status: str) -> None:
        allowed = _SESSION_TRANSITIONS.get(self.status, set())
        if new_status != self.status and new_status not in allowed:
            from .exceptions import InvalidStateTransitionError
            raise InvalidStateTransitionError(
                f"Cannot move UploadSession from '{self.status}' to '{new_status}'.",
                current=self.status,
                requested=new_status,
            )
        UploadSession.objects.filter(pk=self.pk).update(status=new_status, updated_at=timezone.now())
        self.status = new_status

    def received_part_numbers(self) -> set[int]:
        return set(self.parts.values_list("part_number", flat=True))

    def missing_part_numbers(self) -> list[int]:
        if not self.total_parts:
            return []
        return sorted(set(range(1, self.total_parts + 1)) - self.received_part_numbers())


class UploadPart(models.Model):
    id = models.BigAutoField(primary_key=True)
    session = models.ForeignKey(UploadSession, on_delete=models.CASCADE, related_name="parts")
    part_number = models.PositiveIntegerField()
    size = models.PositiveIntegerField()
    checksum = models.CharField(max_length=128, null=True, blank=True)
    storage_ref = models.CharField(
        max_length=512,
        null=True,
        blank=True,
        help_text="Backend part identifier (e.g. S3 ETag, or local staging path) needed to finish the upload.",
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["session", "part_number"], name="unique_part_per_session")
        ]
        indexes = [models.Index(fields=["session", "part_number"])]

    def __str__(self) -> str:
        return f"UploadPart(session={self.session_id}, part={self.part_number})"


# ---------------------------------------------------------------------------
# Load - background job tracking
# ---------------------------------------------------------------------------
class LoadStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    PROCESSING = "processing", "Processing"
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"
    CANCELLED = "cancelled", "Cancelled"


class Load(models.Model):
    """
    Tracks background jobs (Celery/RQ/other) for media pipeline.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="media_tasks",
    )

    task_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    task_type = models.CharField(max_length=128, help_text="E.g. file_upload, process_media_file, transcode.")

    file = models.ForeignKey(MediaFile, null=True, blank=True, on_delete=models.SET_NULL, related_name="loads")
    session = models.ForeignKey(UploadSession, null=True, blank=True, on_delete=models.SET_NULL, related_name="loads")

    external_file_ref = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    storage_path = models.CharField(max_length=1024, null=True, blank=True)

    media_type = models.CharField(max_length=64, db_index=True)
    progress = models.FloatField(default=0.0)
    status = models.CharField(max_length=32, choices=LoadStatus.choices, default=LoadStatus.PENDING, db_index=True)

    priority = models.SmallIntegerField(default=0, help_text="Higher runs first where the queue respects priority.")
    retry_count = models.PositiveSmallIntegerField(default=0)
    max_retries = models.PositiveSmallIntegerField(default=3)
    next_retry_at = models.DateTimeField(null=True, blank=True)

    error_message = models.TextField(null=True, blank=True)
    meta = JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=["task_id"]),
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["status", "next_retry_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Load({self.id}, task_id={self.task_id or 'N/A'}, status={self.status})"

    def set_progress(self, new_progress: float, new_status: Optional[str] = None, error_message: Optional[str] = None) -> None:
        safe_progress = max(0.0, min(100.0, float(new_progress or 0.0)))
        fields = {"progress": safe_progress, "updated_at": timezone.now()}
        if new_status:
            fields["status"] = new_status
        if error_message is not None:
            fields["error_message"] = error_message
        Load.objects.filter(pk=self.pk).update(**fields)
        for f, v in fields.items():
            setattr(self, f, v)
        if fields.get("status") == LoadStatus.COMPLETED:
            Load.objects.filter(pk=self.pk).update(finished_at=timezone.now())
            self.finished_at = timezone.now()

    def mark_started(self) -> None:
        self.started_at = timezone.now()
        self.status = LoadStatus.PROCESSING
        self.save(update_fields=["started_at", "status", "updated_at"])

    def schedule_retry(self, backoff_seconds: int, error_message: str = "") -> bool:
        """Returns False (and marks FAILED) once max_retries is exhausted."""
        if self.retry_count >= self.max_retries:
            self.set_progress(self.progress, LoadStatus.FAILED, error_message)
            return False
        Load.objects.filter(pk=self.pk).update(
            retry_count=models.F("retry_count") + 1,
            next_retry_at=timezone.now() + timedelta(seconds=backoff_seconds),
            status=LoadStatus.PENDING,
            error_message=error_message,
        )
        self.refresh_from_db(fields=["retry_count", "next_retry_at", "status", "error_message"])
        return True


# ---------------------------------------------------------------------------
# UserInteraction
# ---------------------------------------------------------------------------
class InteractionType(models.TextChoices):
    CLICK = "click", "Click"
    VIEW = "view", "View"
    PURCHASE = "purchase", "Purchase"
    LIKE = "like", "Like"
    SHARE = "share", "Share"


class UserInteraction(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="interactions",
    )
    session_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.CharField(max_length=255, db_index=True)
    target = GenericForeignKey("content_type", "object_id")
    interaction_type = models.CharField(max_length=32, choices=InteractionType.choices, db_index=True)
    weight = models.FloatField(default=1.0)
    metadata = JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["content_type", "object_id", "interaction_type"]),
            models.Index(fields=["user", "timestamp"]),
        ]

    def __str__(self) -> str:
        return f"UserInteraction({self.id}, type={self.interaction_type}, target={self.object_id})"


# ---------------------------------------------------------------------------
# Maintenance utilities
# ---------------------------------------------------------------------------
def purge_soft_deleted_older_than(days: int = 30) -> int:
    threshold = timezone.now() - timedelta(days=days)
    qs = MediaFile.all_objects.filter(deleted=True, deleted_at__lt=threshold)
    deleted_count, _ = qs.delete()
    return deleted_count


def expire_stale_upload_sessions() -> int:
    """
    Marks past-due sessions EXPIRED. Storage-side cleanup should happen in
    task/service code that has access to the storage backend.
    """
    stale = UploadSession.objects.filter(
        expires_at__lt=timezone.now(),
        status__in=[UploadSessionStatus.INITIATED, UploadSessionStatus.UPLOADING, UploadSessionStatus.FAILED],
    )
    count = 0
    for session in stale.iterator():
        try:
            session.transition(UploadSessionStatus.EXPIRED)
            count += 1
        except Exception:
            logger.debug(
                "Upload session %s was concurrently transitioned; skipping",
                session.pk,
                exc_info=True,
            )
            continue
    return count
