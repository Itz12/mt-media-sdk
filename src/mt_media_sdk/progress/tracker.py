"""
.progress.tracker
-------------------------
Race-safe bridge between background jobs (Celery) and the ``Load`` model,
plus optional push notifications via a ``ProgressBackend``.

This unified version keeps both the legacy and the current call patterns
working:

- legacy callers can still use ``file_id`` and the older create/update methods
- current callers can use ``external_file_ref`` / ``task_id`` and the newer
  transactional policy-based behavior
- all mutations stay race-safe via ``select_for_update`` inside transactions
- the push backend remains optional and lazy-loaded
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from celery.result import AsyncResult
from django.core.exceptions import ValidationError
from django.db import DatabaseError, IntegrityError, OperationalError, transaction
from django.utils import timezone

from ..models import Load, LoadStatus

logger = logging.getLogger(__name__)

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class ProgressTrackerError(Exception):
    """Base error for the progress tracking service."""


class ProgressConflictError(ProgressTrackerError):
    """Raised when an identifier belongs to a different task/file/user."""


class InvalidProgressTransition(ProgressTrackerError):
    """Raised when a terminal or regressive update is not allowed."""


@dataclass(frozen=True, slots=True)
class ProgressPolicy:
    allow_progress_regression: bool = True
    allow_terminal_override: bool = False
    auto_create_by_file_id: bool = True
    maximum_identifier_length: int = 255


def _status_value(status: Any) -> str:
    value = getattr(status, "value", status)
    if not isinstance(value, str):
        raise ValidationError("status must be a LoadStatus value")
    candidate = value.strip()
    allowed = set(getattr(LoadStatus, "values", ()))
    if not allowed:
        allowed = {
            str(getattr(LoadStatus, name))
            for name in dir(LoadStatus)
            if name.isupper() and isinstance(getattr(LoadStatus, name), str)
        }
    if allowed and candidate not in allowed:
        raise ValidationError("status is not a recognized LoadStatus value")
    return candidate


def _status_by_name(name: str, fallback: str) -> str:
    return str(getattr(LoadStatus, name, fallback))


def _model_fields() -> set[str]:
    return {field.name for field in Load._meta.get_fields()}


def _clean_identifier(value: Any, *, name: str, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    candidate = value.strip()
    if not candidate:
        return None
    if len(candidate) > maximum or _CONTROL_RE.search(candidate):
        raise ValidationError(f"{name} is invalid")
    return candidate


def _clean_progress(value: Any) -> float:
    if isinstance(value, bool):
        raise ValidationError("progress must be numeric")
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValidationError("progress must be numeric") from exc
    if not math.isfinite(result):
        raise ValidationError("progress must be finite")
    return min(100.0, max(0.0, result))


def _clean_optional_text(value: Any, *, maximum: int = 2048) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > maximum:
        return text[:maximum]
    return text


class ProgressTracker:
    """Transactional and backward-compatible progress tracking service."""

    def __init__(
        self,
        progress_backend=None,
        *,
        policy: ProgressPolicy | None = None,
    ) -> None:
        self._backend = progress_backend  # resolved lazily if None
        self.policy = policy or ProgressPolicy()
        self._fields = _model_fields()
        self._pending = _status_by_name("PENDING", "pending")
        self._processing = _status_by_name("PROCESSING", "processing")
        self._completed = _status_by_name("COMPLETED", "completed")
        self._failed = _status_by_name("FAILED", "failed")
        self._cancelled = _status_by_name("CANCELLED", "cancelled")
        self._terminal = {self._completed, self._failed, self._cancelled}

    @property
    def backend(self):
        if self._backend is None:
            from .backends import get_progress_backend
            self._backend = get_progress_backend()
        return self._backend

    def _field_set(self) -> set[str]:
        return self._fields

    def _lookup(self, *, task_id: str | None = None, file_id: str | None = None):
        if task_id is not None and "task_id" in self._fields:
            clean = _clean_identifier(
                task_id,
                name="task_id",
                maximum=self.policy.maximum_identifier_length,
            )
            return Load._default_manager.select_for_update().filter(task_id=clean)

        if file_id is not None and "external_file_ref" in self._fields:
            clean = _clean_identifier(
                file_id,
                name="file_id",
                maximum=self.policy.maximum_identifier_length,
            )
            return Load._default_manager.select_for_update().filter(external_file_ref=clean)

        return Load._default_manager.select_for_update().none()

    def _resolve_existing(
        self,
        *,
        task_id: str | None = None,
        file_id: str | None = None,
    ) -> tuple[Load | None, str | None]:
        if task_id is not None and "task_id" in self._fields:
            clean_task_id = _clean_identifier(
                task_id,
                name="task_id",
                maximum=self.policy.maximum_identifier_length,
            )
            load = Load._default_manager.select_for_update().filter(task_id=clean_task_id).first()
            if load is not None:
                return load, "task_id"

        if file_id is not None and "external_file_ref" in self._fields:
            clean_file_id = _clean_identifier(
                file_id,
                name="file_id",
                maximum=self.policy.maximum_identifier_length,
            )
            load = Load._default_manager.select_for_update().filter(external_file_ref=clean_file_id).first()
            if load is not None:
                return load, "external_file_ref"

        return None, None

    def _build_defaults(
        self,
        *,
        user: Any = None,
        task_type: str | None = None,
        file_id: str | None = None,
        task_id: str | None = None,
        status: Any = None,
        progress: Any = 0,
        metadata: Mapping[str, Any] | None = None,
        storage_path: str = "",
        media_type: str = "",
        media_file: Any = None,
        session: Any = None,
        priority: int = 0,
    ) -> dict[str, Any]:
        defaults: dict[str, Any] = {}
        candidate_task_type = task_type if task_type not in {None, ""} else "unknown"
        candidates = {
            "user": user,
            "task_type": _clean_identifier(
                candidate_task_type,
                name="task_type",
                maximum=self.policy.maximum_identifier_length,
            ),
            "external_file_ref": _clean_identifier(
                file_id,
                name="file_id",
                maximum=self.policy.maximum_identifier_length,
            ),
            "task_id": _clean_identifier(
                task_id,
                name="task_id",
                maximum=self.policy.maximum_identifier_length,
            ),
            "status": _status_value(status or self._pending),
            "progress": _clean_progress(progress),
            "metadata": dict(metadata or {}),
            "storage_path": _clean_optional_text(storage_path),
            "media_type": _clean_optional_text(media_type),
            "file": media_file,
            "session": session,
            "priority": int(priority),
        }
        for field, value in candidates.items():
            if field in self._fields and value is not None:
                defaults[field] = value
        return defaults

    @transaction.atomic
    def create_task(
        self,
        *,
        user: Any = None,
        task_type: str | None = None,
        file_id: str | None = None,
        storage_path: str = "",
        media_type: str = "",
        task_id: str | None = None,
        media_file=None,
        session=None,
        priority: int = 0,
        status: Any = None,
        progress: Any = 0,
        metadata: Mapping[str, Any] | None = None,
    ) -> Load | None:
        clean_task_id = _clean_identifier(
            task_id,
            name="task_id",
            maximum=self.policy.maximum_identifier_length,
        )
        clean_file_id = _clean_identifier(
            file_id,
            name="file_id",
            maximum=self.policy.maximum_identifier_length,
        )

        if not clean_task_id and not clean_file_id:
            raise ValidationError("task_id or file_id is required")

        lookup: dict[str, Any]
        if clean_task_id and "task_id" in self._fields:
            lookup = {"task_id": clean_task_id}
        elif clean_file_id and "external_file_ref" in self._fields:
            lookup = {"external_file_ref": clean_file_id}
        else:
            raise ValidationError("the Load model lacks a supported identifier field")

        existing = Load._default_manager.select_for_update().filter(**lookup).first()
        defaults = self._build_defaults(
            user=user,
            task_type=task_type,
            file_id=clean_file_id,
            task_id=clean_task_id,
            status=status,
            progress=progress,
            metadata=metadata,
            storage_path=storage_path,
            media_type=media_type,
            media_file=media_file,
            session=session,
            priority=priority,
        )

        if existing is not None:
            if user is not None and "user" in self._fields:
                existing_user_id = getattr(existing, "user_id", None)
                requested_user_id = getattr(user, "pk", None)
                if existing_user_id not in {None, requested_user_id}:
                    raise ProgressConflictError("task identifier belongs to another user")
            if task_type and "task_type" in self._fields:
                current_type = getattr(existing, "task_type", None)
                if current_type not in {None, "", task_type}:
                    raise ProgressConflictError("task identifier belongs to another task type")
            if clean_file_id and "external_file_ref" in self._fields:
                current_file_id = getattr(existing, "external_file_ref", None)
                if current_file_id not in {None, "", clean_file_id}:
                    raise ProgressConflictError("task identifier belongs to another file")
            return existing

        try:
            return Load._default_manager.create(**defaults)
        except IntegrityError:
            existing = Load._default_manager.select_for_update().filter(**lookup).first()
            if existing is None:
                raise
            return existing

    def _update_locked(
        self,
        *,
        lookup: Dict[str, Any],
        progress: float,
        status: Optional[str],
        error_message: Optional[str],
    ) -> Optional[Load]:
        try:
            with transaction.atomic():
                load = (
                    Load.objects.select_for_update()
                    .filter(**lookup)
                    .order_by("-created_at")
                    .first()
                )
                if not load:
                    return None

                load.progress = max(0.0, min(100.0, float(progress or 0.0)))
                if status is not None and "status" in self._fields:
                    load.status = status
                if error_message is not None:
                    for field_name in ("error_message", "error", "failure_reason"):
                        if field_name in self._fields:
                            setattr(load, field_name, str(error_message).strip()[:2048])
                            break
                updates = ["progress", "updated_at"]
                if "status" in self._fields:
                    updates.append("status")
                if error_message is not None:
                    for field_name in ("error_message", "error", "failure_reason"):
                        if field_name in self._fields:
                            updates.append(field_name)
                            break
                load.save(update_fields=list(dict.fromkeys(updates)))

                if status == self._completed and "finished_at" in self._fields:
                    Load.objects.filter(pk=load.pk).update(finished_at=timezone.now())
                    load.finished_at = timezone.now()

                return load
        except (OperationalError, DatabaseError):
            logger.exception("DB error updating Load for %s", lookup)
        except Exception:
            logger.exception("Unexpected error updating Load for %s", lookup)
        return None

    @transaction.atomic
    def _update(
        self,
        *,
        task_id: str | None = None,
        file_id: str | None = None,
        progress: Any | None,
        status: Any | None = None,
        error_message: Optional[str] = None,
        auto_create: bool = False,
    ) -> Load | None:
        lookup = {}
        if task_id is not None and "task_id" in self._fields:
            lookup = {"task_id": _clean_identifier(
                task_id,
                name="task_id",
                maximum=self.policy.maximum_identifier_length,
            )}
        elif file_id is not None and "external_file_ref" in self._fields:
            lookup = {"external_file_ref": _clean_identifier(
                file_id,
                name="file_id",
                maximum=self.policy.maximum_identifier_length,
            )}
        else:
            return None

        load = Load._default_manager.select_for_update().filter(**lookup).first()
        if load is None:
            if not auto_create:
                return None
            if file_id is None:
                return None
            load = self.create_task(
                task_type="file_upload",
                file_id=file_id,
                status=status or self._pending,
                progress=progress,
            )
            if load is None:
                return None
            # Re-lock the row we just created
            load = Load._default_manager.select_for_update().filter(pk=load.pk).first()

        if load is None:
            return None

        current_status = str(getattr(load, "status", self._pending))
        next_status = _status_value(status or current_status)
        current_progress = float(getattr(load, "progress", 0) or 0)
        next_progress = current_progress if progress is None else _clean_progress(progress)

        if (
            current_status in self._terminal
            and not self.policy.allow_terminal_override
            and (next_status != current_status or next_progress != current_progress)
        ):
            raise InvalidProgressTransition("terminal progress records are immutable")

        if not self.policy.allow_progress_regression and next_progress < current_progress:
            raise InvalidProgressTransition("progress cannot decrease")

        updates: list[str] = []
        if "progress" in self._fields:
            load.progress = next_progress
            updates.append("progress")
        if "status" in self._fields:
            load.status = next_status
            updates.append("status")
        if "started_at" in self._fields and next_status == self._processing and not getattr(load, "started_at", None):
            load.started_at = timezone.now()
            updates.append("started_at")
        if "finished_at" in self._fields:
            if next_status in self._terminal:
                load.finished_at = getattr(load, "finished_at", None) or timezone.now()
                updates.append("finished_at")
            elif self.policy.allow_terminal_override and getattr(load, "finished_at", None):
                load.finished_at = None
                updates.append("finished_at")
        for timestamp_field in ("updated_at", "last_updated"):
            if timestamp_field in self._fields:
                setattr(load, timestamp_field, timezone.now())
                updates.append(timestamp_field)
        if error_message is not None:
            for field_name in ("error_message", "error", "failure_reason"):
                if field_name in self._fields:
                    setattr(load, field_name, str(error_message).strip()[:2048])
                    updates.append(field_name)
                    break

        load.save(update_fields=list(dict.fromkeys(updates)))
        return load

    def update_progress_by_task_id(
        self,
        task_id: str,
        progress: Any,
        status: Any | None = None,
        error_message: Optional[str] = None,
    ) -> Load | None:
        if not task_id:
            logger.warning("update_progress_by_task_id called without task_id")
            return None
        load = self._update(
            task_id=task_id,
            progress=progress,
            status=status,
            error_message=error_message,
        )
        self._publish(load)
        return load

    def update_progress_by_file_id(
        self,
        file_id: str,
        progress: Any,
        status: Any | None = None,
        error_message: Optional[str] = None,
    ) -> Load | None:
        if not file_id:
            logger.warning("update_progress_by_file_id called without file_id")
            return None
        load = self._update(
            file_id=file_id,
            progress=progress,
            status=status,
            error_message=error_message,
            auto_create=self.policy.auto_create_by_file_id,
        )
        if load is None and self.policy.auto_create_by_file_id:
            # Best-effort auto-create for the legacy worker path.
            created = self.create_task(
                user=None,
                task_type="unknown",
                file_id=file_id,
                status=status or self._pending,
                progress=progress,
            )
            if created is not None:
                load = self._update(
                    file_id=file_id,
                    progress=progress,
                    status=status,
                    error_message=error_message,
                    auto_create=False,
                )
        self._publish(load)
        return load

    def mark_complete(
        self,
        identifier: str,
        by_task_id: bool | None = None,
    ) -> Load | None:
        if by_task_id is True:
            return self.update_progress_by_task_id(identifier, 100.0, self._completed)
        if by_task_id is False:
            return self.update_progress_by_file_id(identifier, 100.0, self._completed)

        # Compatibility mode: try task_id first, then file_id.
        load = self.update_progress_by_task_id(identifier, 100.0, self._completed)
        if load is None:
            load = self.update_progress_by_file_id(identifier, 100.0, self._completed)
        return load

    def mark_failed(
        self,
        identifier: str,
        error_message: str = "Task failed",
        by_task_id: bool | None = None,
    ) -> Load | None:
        if by_task_id is True:
            return self.update_progress_by_task_id(
                identifier,
                0.0,
                self._failed,
                error_message,
            )
        if by_task_id is False:
            return self.update_progress_by_file_id(
                identifier,
                0.0,
                self._failed,
                error_message,
            )

        load = self.update_progress_by_task_id(
            identifier,
            0.0,
            self._failed,
            error_message,
        )
        if load is None:
            load = self.update_progress_by_file_id(
                identifier,
                0.0,
                self._failed,
                error_message,
            )
        return load

    def _publish(self, load: Optional[Load]) -> None:
        if not load:
            return
        try:
            payload = {
                "task_id": getattr(load, "task_id", None),
                "file_id": getattr(load, "external_file_ref", None),
                "status": getattr(load, "status", None),
                "progress": getattr(load, "progress", None),
                "error_message": getattr(load, "error_message", None),
            }
            key_id = getattr(load, "task_id", None) or getattr(load, "external_file_ref", None) or str(getattr(load, "pk", "unknown"))
            user_id = getattr(load, "user_id", None) or "anon"
            self.backend.set(f"load:{key_id}", payload, timeout=3600)
            self.backend.publish(f"upload_progress.{user_id}", payload)
        except Exception:
            logger.debug(
                "Progress backend publish failed for task_id=%s",
                getattr(load, "task_id", None),
                exc_info=True,
            )

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        if not task_id:
            return {"error": "missing task_id"}
        state = "UNKNOWN"
        try:
            async_res = AsyncResult(task_id)
            state = getattr(async_res, "state", None) or "UNKNOWN"
            if state == "PROGRESS":
                info = getattr(async_res, "info", {}) or {}
                return {"status": state, "progress": float(info.get("progress", 0.0))}
        except Exception:
            logger.debug("Celery AsyncResult lookup failed for %s", task_id, exc_info=True)
        try:
            load = Load.objects.get(task_id=task_id)
            return {"status": load.status, "progress": float(load.progress)}
        except Load.DoesNotExist:
            return {"status": state, "progress": 100.0 if state == "SUCCESS" else 0.0}
        except (OperationalError, DatabaseError):
            logger.debug("DB error fetching Load for task_id=%s", task_id, exc_info=True)
            return {"status": state, "progress": 0.0}

    def get_by_task_id(self, task_id: str) -> Load | None:
        clean = _clean_identifier(
            task_id,
            name="task_id",
            maximum=self.policy.maximum_identifier_length,
        )
        return Load._default_manager.filter(task_id=clean).first()

    def get_by_file_id(self, file_id: str) -> Load | None:
        clean = _clean_identifier(
            file_id,
            name="file_id",
            maximum=self.policy.maximum_identifier_length,
        )
        return Load._default_manager.filter(external_file_ref=clean).first()


# Module-level singleton for convenience call sites:
#   from media.progress.tracker import tracker
tracker = ProgressTracker()

__all__ = [
    "InvalidProgressTransition",
    "ProgressConflictError",
    "ProgressPolicy",
    "ProgressTracker",
    "ProgressTrackerError",
    "tracker",
]
