"""
media.tasks
-----------
Celery tasks orchestrating post-upload processing (virus scan -> ready) and
periodic maintenance (expired session cleanup, soft-delete purge, stuck-scan
retry).

This version keeps the existing task surface area, but centralizes progress,
retry, and scan-status handling so the module is less repetitive, more
idempotent, and safer under concurrent execution.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from asgiref.sync import async_to_sync
from celery import Task, shared_task
from celery.utils.log import get_task_logger
from channels.layers import get_channel_layer
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError

# Optional django_clamd integration.
try:
    from django_clamd.validators import validate_file_infection  # type: ignore

    DJANGO_CLAMD_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    validate_file_infection = None  # type: ignore
    DJANGO_CLAMD_AVAILABLE = False

# Optional local helper.
try:
    from .security.validators import _clamav_file_scan  # type: ignore

    CLAMAV_HELPER_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    _clamav_file_scan = None  # type: ignore
    CLAMAV_HELPER_AVAILABLE = False

# Optional validator classes kept for compatibility with older code paths.
try:
    from .security.validators import CustomValidator, ValidatorHandler  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    CustomValidator = None  # type: ignore
    ValidatorHandler = None  # type: ignore

from .exceptions import ScanUnavailableError, VirusDetectedError
from .models import (
    Load,
    LoadStatus,
    MediaFile,
    MediaLimit,
    MediaStatus,
    ScanStatus,
    UploadSession,
    UploadSessionStatus,
    expire_stale_upload_sessions,
    purge_soft_deleted_older_than,
)
from .progress.tracker import tracker as progress_tracker
logger = logging.getLogger(__name__)
logger = get_task_logger(__name__)
logger.setLevel(getattr(settings, "TASKS_LOG_LEVEL", logging.INFO))

DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_BASE_SECONDS = 30


@dataclass(frozen=True, slots=True)
class VirusScanResult:
    clean: bool
    detail: str | None = None
    engine: str = "clamav"


class ClamAVVirusScanner:
    """Small synchronous adapter around the SDK's hardened ClamAV client."""

    def scan(self, fileobj) -> VirusScanResult:
        try:
            from .security.validators import get_clamav_client
        except Exception as exc:
            raise ScanUnavailableError("Virus scanner integration is unavailable.") from exc

        client = get_clamav_client()
        if client is None:
            raise ScanUnavailableError("Virus scanner is unavailable.")
        try:
            scan = getattr(client, "instream", None)
            if not callable(scan):
                raise ScanUnavailableError("Virus scanner does not support stream scanning.")
            try:
                fileobj.seek(0)
            except Exception:
                pass
            response = scan(fileobj)
        except ScanUnavailableError:
            raise
        except Exception as exc:
            raise ScanUnavailableError("Virus scanner request failed.") from exc
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    logger.debug("Failed to close ClamAV client", exc_info=True)

        if not isinstance(response, dict) or not response:
            raise ScanUnavailableError("Virus scanner returned an invalid response.")
        for value in response.values():
            if not isinstance(value, tuple) or not value:
                continue
            status = str(value[0]).upper()
            detail = str(value[1]) if len(value) > 1 and value[1] else None
            if status == "FOUND":
                return VirusScanResult(clean=False, detail=detail)
            if status == "OK":
                return VirusScanResult(clean=True)
        raise ScanUnavailableError("Virus scanner returned an unknown status.")


def get_virus_scanner() -> ClamAVVirusScanner:
    return ClamAVVirusScanner()


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _is_within_media_root(file_path: str) -> bool:
    """
    Guard: if ENFORCE_MEDIA_ROOT is enabled, ensure file_path is under MEDIA_ROOT.
    This prevents accidental deletion/scan of arbitrary system files.
    """
    try:
        if not getattr(settings, "ENFORCE_MEDIA_ROOT", True):
            return True
        media_root = getattr(settings, "MEDIA_ROOT", None)
        if not media_root:
            return True

        abs_media = os.path.abspath(media_root)
        abs_file = os.path.abspath(file_path)

        try:
            return os.path.commonpath([abs_media, abs_file]) == abs_media
        except Exception:
            return False
    except Exception:
        logger.exception("Error checking MEDIA_ROOT guard for %s", file_path)
        return False


def _clamav_enabled() -> bool:
    return bool(getattr(settings, "CLAMAV_ENABLED", False))


def _run_maybe_async(fn: Callable, *args, **kwargs):
    """
    Execute a sync or async callable and return its result.
    """
    result = fn(*args, **kwargs)
    if asyncio.iscoroutine(result):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                new_loop = asyncio.new_event_loop()
                try:
                    return new_loop.run_until_complete(result)
                finally:
                    new_loop.close()
            return loop.run_until_complete(result)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(result)
            finally:
                loop.close()
    return result


def update_cache_progress(
    cache_key: str, progress: int, status: str, extra: Optional[Dict[str, Any]] = None
) -> None:
    """Safely update cached task progress."""
    payload = {"progress": max(0, min(100, _safe_int(progress))), "status": str(status or "")}
    if extra:
        try:
            payload.update(extra)
        except Exception:
            logger.debug("Failed to merge extra progress data", exc_info=True)
    try:
        cache.set(
            cache_key,
            payload,
            timeout=getattr(settings, "UPLOAD_PROGRESS_CACHE_TTL", 3600),
        )
    except Exception:
        logger.exception("Failed to update cache for key %s", cache_key)


def _load_for_task(task_id: Optional[str]) -> Optional[Load]:
    if not task_id:
        return None
    return (
        Load.objects.select_related("file", "session", "user")
        .filter(task_id=task_id)
        .order_by("-created_at")
        .first()
    )


def _load_for_media_file(media_file: MediaFile) -> Optional[Load]:
    return (
        Load.objects.select_related("file", "session", "user")
        .filter(file=media_file, task_type="process_media_file")
        .order_by("-created_at")
        .first()
    )


def _set_load_state(
    load: Optional[Load],
    *,
    progress: Optional[float] = None,
    status: Optional[str] = None,
    error_message: Optional[str] = None,
) -> None:
    if not load:
        return
    try:
        if progress is None:
            progress = load.progress
        load.set_progress(progress, status, error_message)
    except Exception:
        logger.debug("Failed to update Load %s", getattr(load, "pk", None), exc_info=True)


def _mark_media_scan_state(
    media_file: MediaFile,
    *,
    scan_status: str,
    scan_detail: Optional[str] = None,
    processing_error: Optional[str] = None,
) -> None:
    updates: Dict[str, Any] = {"scan_status": scan_status}
    if scan_detail is not None:
        updates["scan_detail"] = scan_detail
    if processing_error is not None:
        updates["processing_error"] = processing_error
    try:
        for field, value in updates.items():
            setattr(media_file, field, value)
        media_file.save(update_fields=list(updates.keys()))
    except Exception:
        logger.exception("Failed to update scan state for media file %s", media_file.pk)


def _retry_or_fail(task, load: Optional[Load], exc: Exception) -> None:
    retries = _safe_int(getattr(task.request, "retries", 0), 0)
    if retries < DEFAULT_MAX_RETRIES:
        backoff = DEFAULT_BACKOFF_BASE_SECONDS * (2**retries)
        if load:
            try:
                load.schedule_retry(backoff, error_message=str(exc))
            except Exception:
                logger.debug("Failed to schedule retry for Load %s", load.pk, exc_info=True)
        raise task.retry(exc=exc, countdown=backoff)
    if load:
        _set_load_state(load, progress=load.progress, status=LoadStatus.FAILED, error_message=str(exc))


def _scan_file_with_available_engine(file_path: str) -> Dict[str, Any]:
    """
    Normalize scanner responses into a small status vocabulary.
    """
    if not _clamav_enabled():
        return {"status": "skipped", "reason": "clamav_disabled", "file": file_path}

    if not os.path.exists(file_path):
        return {"status": "failed", "error": "file not found", "file": file_path}

    if not _is_within_media_root(file_path):
        return {"status": "failed", "error": "file outside media root", "file": file_path}

    scan_timeout = float(getattr(settings, "CLAMAV_SCAN_TIMEOUT", 30.0))

    if CLAMAV_HELPER_AVAILABLE and _clamav_file_scan is not None:
        try:
            result = _run_maybe_async(_clamav_file_scan, file_path, timeout=scan_timeout)
            if isinstance(result, dict):
                lowered = {str(k).lower(): v for k, v in result.items()}
                status = lowered.get("status")
                if status in {"infected", "clean", "skipped", "failed"}:
                    payload = dict(result)
                    payload.setdefault("file", file_path)
                    return payload

                # Legacy helper shape: detect tuple like ("FOUND", ...)
                for value in result.values():
                    if isinstance(value, tuple) and value and str(value[0]).upper() == "FOUND":
                        return {"status": "infected", "error": str(value), "file": file_path}

            return {"status": "clean", "file": file_path}
        except Exception:
            logger.exception("ClamAV helper scan failed for %s; attempting fallback.", file_path)

    if DJANGO_CLAMD_AVAILABLE and validate_file_infection is not None:
        try:
            with open(file_path, "rb") as fh:
                validate_file_infection(fh)
            return {"status": "clean", "file": file_path}
        except ValidationError as ve:
            return {"status": "infected", "error": str(ve), "file": file_path}
        except Exception:
            logger.exception("django_clamd scanning failed for %s.", file_path)
            return {"status": "skipped", "reason": "clamd_error", "file": file_path}

    return {"status": "skipped", "reason": "no_scanner", "file": file_path}


def _safe_send_progress_ws(user_id: int, file_id: str, progress: int, channel_layer) -> None:
    if channel_layer is None:
        return
    try:
        async_to_sync(channel_layer.group_send)(
            f"progress_{user_id}",
            {
                "type": "send_progress",
                "upload_status": {"file_id": file_id, "progress": progress},
            },
        )
    except Exception:
        logger.debug(
            "Failed to send websocket progress to group progress_%s for file %s",
            user_id,
            file_id,
            exc_info=True,
        )


def _task_state_update(task: Task, progress: int) -> None:
    try:
        task.update_state(state="PROGRESS", meta={"progress": progress})
    except Exception:
        logger.debug("Could not update celery state for task %s", getattr(task.request, "id", None), exc_info=True)


def _update_load_progress_from_task(task: Task, progress: int) -> None:
    try:
        task_id = getattr(task.request, "id", None)
        if task_id:
            Load.objects.filter(task_id=task_id).update(progress=progress)
    except Exception:
        logger.debug("Could not update Load progress for task %s", getattr(task.request, "id", None), exc_info=True)


def _process_file_progress_loop(
    *,
    task: Task,
    file_path: str,
    file_id: str,
    user_id: int,
    cache_key: str,
    direction: str,
    sleep_seconds: float,
    channel_layer=None,
) -> Dict[str, Any]:
    if not os.path.exists(file_path):
        update_cache_progress(cache_key, 0, "failed", {"error": "file not found"})
        return {"status": "failed", "error": "file not found", "file_id": file_id}

    if not _is_within_media_root(file_path):
        update_cache_progress(cache_key, 0, "failed", {"error": "file outside media root"})
        return {"status": "failed", "error": "file outside media root", "file_id": file_id}

    total_size = os.path.getsize(file_path)
    if total_size == 0:
        update_cache_progress(cache_key, 100, "completed")
        _task_state_update(task, 100)
        _update_load_progress_from_task(task, 100)
        return {"status": "completed", "file_id": file_id}

    chunk_size = int(getattr(settings, f"{direction.upper()}_CHUNK_BYTES", 1024 * 1024))
    chunk_size = max(1, chunk_size)

    processed_size = 0
    in_progress_status = "uploading" if direction == "upload" else "downloading"

    while processed_size < total_size:
        processed_size += min(chunk_size, total_size - processed_size)
        progress = int((processed_size / total_size) * 100)
        update_cache_progress(cache_key, progress, in_progress_status)
        _safe_send_progress_ws(user_id, file_id, progress, channel_layer)
        _task_state_update(task, progress)
        _update_load_progress_from_task(task, progress)
        time.sleep(max(0.0, float(sleep_seconds)))

    update_cache_progress(cache_key, 100, "completed")
    return {"status": "completed", "file_id": file_id}


# ---------------------------------------------------------------------
# Main task: post-upload processing
# ---------------------------------------------------------------------
@shared_task(bind=True, max_retries=DEFAULT_MAX_RETRIES)
def process_media_file(self, media_file_id: str):
    """
    Virus scan a MediaFile, then transition it to READY or QUARANTINED.

    This task is idempotent and concurrency-aware:
    - It uses the model's optimistic status transition guard.
    - It avoids double-processing the same task when a duplicate Celery job runs.
    - It updates the linked Load row using the model helper instead of duplicating state logic.
    """
    try:
        media_file = (
            MediaFile.all_objects.select_related("owner")
            .filter(pk=media_file_id)
            .first()
        )
        if media_file is None:
            logger.warning("process_media_file: MediaFile %s no longer exists.", media_file_id)
            return {"status": "missing", "media_file_id": media_file_id}

        load = _load_for_media_file(media_file)

        if media_file.status in {MediaStatus.READY, MediaStatus.QUARANTINED, MediaStatus.ARCHIVED}:
            if load:
                _set_load_state(load, progress=100, status=LoadStatus.COMPLETED)
            return {"status": str(media_file.status), "media_file_id": str(media_file_id)}

        if not getattr(media_file, "file", None) or not getattr(media_file.file, "name", None):
            media_file.transition_status(MediaStatus.FAILED, error="File is missing from storage.")
            if load:
                _set_load_state(load, progress=100, status=LoadStatus.FAILED, error_message="File is missing from storage.")
            return {"status": "failed", "media_file_id": str(media_file_id)}

        # Move to processing only once. If another worker already moved it, the
        # model's version guard prevents duplicate work.
        media_file.transition_status(MediaStatus.PROCESSING)
        if load:
            _set_load_state(load, progress=10, status=LoadStatus.PROCESSING)

        limits = MediaLimit.get_solo(tenant_id=getattr(media_file, "tenant_id", None))
        scan_result: Dict[str, Any]

        if limits.requires_virus_scan:
            scanner = get_virus_scanner()
            try:
                with media_file.file.storage.open(media_file.file.name, "rb") as fh:
                    scan_result = scanner.scan(fh)
            except ScanUnavailableError:
                raise
            except VirusDetectedError:
                raise
            except Exception as exc:
                logger.exception("Scan failed for MediaFile %s", media_file_id)
                _mark_media_scan_state(
                    media_file,
                    scan_status=ScanStatus.ERROR,
                    scan_detail=str(exc),
                    processing_error=str(exc),
                )
                _retry_or_fail(self, load, exc)
                return {"status": "retrying", "media_file_id": str(media_file_id)}

            clean = bool(getattr(scan_result, "clean", False))
            detail = getattr(scan_result, "detail", None)
            engine = getattr(scan_result, "engine", None)

            if not clean:
                media_file.transition_status(
                    MediaStatus.QUARANTINED,
                    error="Virus scan flagged this file.",
                )
                _mark_media_scan_state(
                    media_file,
                    scan_status=ScanStatus.INFECTED,
                    scan_detail=detail or f"Virus detected by {engine or 'scanner'}",
                    processing_error="Virus scan flagged this file.",
                )
                if load:
                    _set_load_state(load, progress=100, status=LoadStatus.FAILED, error_message="Virus detected.")
                raise VirusDetectedError(
                    f"MediaFile {media_file_id} flagged by {engine}: {detail}"
                )

            _mark_media_scan_state(
                media_file,
                scan_status=ScanStatus.CLEAN,
                scan_detail=None,
                processing_error=None,
            )
        else:
            _mark_media_scan_state(
                media_file,
                scan_status=ScanStatus.SKIPPED,
                scan_detail="Virus scan skipped by policy.",
                processing_error=None,
            )

        if load:
            _set_load_state(load, progress=90, status=LoadStatus.PROCESSING)

        media_file.transition_status(MediaStatus.READY)
        if load:
            _set_load_state(load, progress=100, status=LoadStatus.COMPLETED)

        progress_tracker.update_progress_by_file_id(
            str(media_file_id),
            100,
            status=LoadStatus.COMPLETED,
        )
        return {"status": "completed", "media_file_id": str(media_file_id)}

    except VirusDetectedError:
        raise  # terminal; never retry an infected file
    except ScanUnavailableError as exc:
        logger.warning("Scanner unavailable for %s: %s", media_file_id, exc)
        try:
            media_file = MediaFile.all_objects.filter(pk=media_file_id).first()
            if media_file:
                _mark_media_scan_state(
                    media_file,
                    scan_status=ScanStatus.ERROR,
                    scan_detail=str(exc),
                    processing_error=str(exc),
                )
        except Exception:
            logger.debug("Failed to persist scan ERROR state for %s", media_file_id, exc_info=True)
        _retry_or_fail(self, _load_for_task(getattr(self.request, "id", None)), exc)
        return {"status": "retrying", "media_file_id": str(media_file_id)}
    except Exception as exc:
        logger.exception("process_media_file failed for %s", media_file_id)
        try:
            media_file = MediaFile.all_objects.filter(pk=media_file_id).first()
            if media_file:
                _mark_media_scan_state(
                    media_file,
                    scan_status=ScanStatus.ERROR,
                    scan_detail=str(exc),
                    processing_error=str(exc),
                )
        except Exception:
            logger.debug("Failed to persist scan ERROR state for %s", media_file_id, exc_info=True)
        _retry_or_fail(self, _load_for_task(getattr(self.request, "id", None)), exc)
        return {"status": "retrying", "media_file_id": str(media_file_id)}


# ---------------------------------------------------------------------
# Upload session completion and maintenance
# ---------------------------------------------------------------------
@shared_task
def finalize_upload_session(session_id: str, is_public: bool = False):
    """Finalize a chunked upload and return the created MediaFile id."""
    from .uploads.chunked import UploadSessionService

    session = UploadSession.objects.get(pk=session_id)
    service = UploadSessionService(storage_backend_name=session.storage_backend)
    media_file = service.complete(session, is_public=is_public)
    return str(media_file.id)


@shared_task
def cleanup_expired_sessions():
    """
    Mark stale sessions EXPIRED and then release storage-side resources.
    """
    from .uploads.chunked import UploadSessionService

    count = expire_stale_upload_sessions()
    stragglers = (
        UploadSession.objects.filter(status=UploadSessionStatus.EXPIRED)
        .order_by("-updated_at")[:200]
    )

    services: dict[str, UploadSessionService] = {}
    for session in stragglers:
        service = services.setdefault(
            session.storage_backend,
            UploadSessionService(session.storage_backend),
        )
        try:
            service.expire_and_cleanup(session)
        except Exception:
            logger.exception("Failed cleaning up expired session %s", session.id)
    return count


@shared_task
def purge_soft_deleted_media(days: int = 30):
    return purge_soft_deleted_older_than(days=days)


@shared_task
def retry_pending_scans():
    """
    Requeue MediaFiles stuck in ERROR scan status.
    """
    stuck = MediaFile.objects.filter(scan_status=ScanStatus.ERROR).order_by("updated_at")[:100]
    count = 0
    for media_file in stuck:
        process_media_file.delay(str(media_file.id))
        count += 1
    return count


# ---------------------------------------------------------------------
# Virus scanning task
# ---------------------------------------------------------------------
@shared_task(bind=False)
def scan_file_for_viruses(file_path: str) -> Dict[str, Any]:
    """
    Scan a file for viruses and return a normalized status payload.
    """
    try:
        result = _scan_file_with_available_engine(file_path)
        if result.get("status") == "infected":
            logger.warning("Virus detected in %s: %s", file_path, result.get("error"))
        elif result.get("status") == "clean":
            logger.info("File %s passed scan.", file_path)
        else:
            logger.info("Virus scan skipped/failed for %s: %s", file_path, result.get("reason") or result.get("error"))
        return result
    except Exception as exc:
        logger.exception("Unexpected error scanning file %s: %s", file_path, exc)
        return {"status": "failed", "error": str(exc), "file": file_path}


# ---------------------------------------------------------------------
# Simulated download / upload processing helpers
# ---------------------------------------------------------------------
@shared_task(bind=True)
def file_download_task(self: Task, user_id: int, file_url: str) -> Dict[str, Any]:
    """Simulate a file download with periodic progress updates."""
    try:
        total_chunks = max(1, _safe_int(getattr(settings, "SIMULATED_DOWNLOAD_CHUNKS", 20), 20))
        chunk_sleep = max(0.0, float(getattr(settings, "SIMULATED_DOWNLOAD_SLEEP", 1.0)))

        for i in range(1, total_chunks + 1):
            time.sleep(chunk_sleep)
            progress = int((i / total_chunks) * 100)
            _task_state_update(self, progress)

            try:
                task_id = getattr(self.request, "id", None)
                if task_id:
                    Load.objects.filter(task_id=task_id).update(progress=progress)
            except Exception:
                logger.debug("Could not update Load progress for task %s", getattr(self.request, "id", None), exc_info=True)

        return {"message": "File downloaded successfully!"}
    except Exception as exc:
        logger.exception("Download failed for user %s: %s", user_id, exc)
        return {"status": "failed", "error": str(exc)}


@shared_task(bind=True)
def process_upload(
    self: Task, file_path: str, file_id: str, user_id: int
) -> Dict[str, Any]:
    """
    Process a file upload with safe progress reporting.
    """
    cache_key = f"upload_progress_{file_id}"
    channel_layer = None
    try:
        channel_layer = get_channel_layer()
    except Exception:
        logger.debug("channels get_channel_layer failed", exc_info=True)

    try:
        if _clamav_enabled():
            scan_result = _scan_file_with_available_engine(file_path)
            if scan_result.get("status") == "infected":
                update_cache_progress(cache_key, 0, "failed", {"error": "infected"})
                return {"status": "infected", "error": scan_result.get("error"), "file_id": file_id}

        result = _process_file_progress_loop(
            task=self,
            file_path=file_path,
            file_id=file_id,
            user_id=user_id,
            cache_key=cache_key,
            direction="upload",
            sleep_seconds=float(getattr(settings, "UPLOAD_PROGRESS_SLEEP", 0.5)),
            channel_layer=channel_layer,
        )

        if result.get("status") == "completed":
            task_id = getattr(self.request, "id", None)
            if task_id:
                try:
                    Load.objects.filter(task_id=task_id).update(
                        progress=100,
                        status=getattr(settings, "FINAL_LOAD_STATUS_ON_COMPLETE", LoadStatus.COMPLETED),
                    )
                except Exception:
                    logger.debug("Could not finalize Load progress for task %s", getattr(self.request, "id", None), exc_info=True)
        return result

    except ValidationError as e:
        update_cache_progress(cache_key, 0, "failed", {"error": str(e)})
        logger.warning("Validation error in process_upload for %s: %s", file_path, e)
        return {"status": "failed", "error": str(e)}
    except Exception as exc:
        update_cache_progress(cache_key, 0, "failed", {"error": str(exc)})
        logger.exception("Upload failed for %s: %s", file_path, exc)
        return {"status": "failed", "error": str(exc)}


@shared_task(bind=True)
def process_download(
    self: Task, file_path: str, file_id: str, user_id: int
) -> Dict[str, Any]:
    """
    Background task for processing file downloads with safe progress updates.
    """
    cache_key = f"download_progress_{file_id}"
    try:
        result = _process_file_progress_loop(
            task=self,
            file_path=file_path,
            file_id=file_id,
            user_id=user_id,
            cache_key=cache_key,
            direction="download",
            sleep_seconds=float(getattr(settings, "DOWNLOAD_PROGRESS_SLEEP", 0.5)),
            channel_layer=None,
        )
        return result
    except ValidationError as e:
        update_cache_progress(cache_key, 0, "failed", {"error": str(e)})
        logger.warning("Validation error in process_download for %s: %s", file_path, e)
        return {"status": "failed", "error": str(e)}
    except Exception as exc:
        update_cache_progress(cache_key, 0, "failed", {"error": str(exc)})
        logger.exception("Download error for %s: %s", file_id, exc)
        return {"status": "failed", "error": str(exc)}


@shared_task(bind=False)
def update_user_preference(user_id: int, category_id: int) -> None:
    """Update cached user session preferences (keeps last 10 entries)."""
    try:
        session_pref_key = f"user_session_{user_id}_preferences"
        session_preferences = cache.get(session_pref_key, {}) or {}
        recent_categories = session_preferences.get("recent_categories", [])

        if category_id not in recent_categories:
            recent_categories.append(category_id)

        session_preferences["recent_categories"] = recent_categories[-10:]
        cache.set(
            session_pref_key,
            session_preferences,
            timeout=getattr(settings, "USER_PREF_CACHE_TTL", 3600),
        )

        logger.info("Preferences updated for user %s.", user_id)
    except Exception as exc:
        logger.exception("Error updating preferences for user %s: %s", user_id, exc)
