"""
media.uploads.handler
------------------------
Django ``FileUploadHandler`` for simple (non-chunked) uploads. Good fit for
files that comfortably fit in one HTTP request (images, documents, short
clips).

For large files that need real resumability, use
``media.uploads.chunked.UploadSessionService`` instead - a single HTTP
request handler *cannot* survive a dropped connection no matter how clever
the pause/resume bookkeeping is, so this module doesn't pretend otherwise:
"pause" here aborts the request, and the client is expected to fall back to
the chunked flow for anything that genuinely needs resume-after-disconnect.

Improvements over a naive version:
  * Computes a running SHA-256 checksum while streaming (no second read
    pass over the file).
  * Runs ``ValidationPipeline`` as soon as filename/content-type/length are
    known, rejecting bad uploads before any bytes are written to disk.
  * Reports failures with structured error codes instead of silently
    dropping the connection.
"""
from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import time
import uuid
from threading import Timer
from typing import Any, Dict, List, Optional

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings
from django.core.cache import cache
from django.core.files.uploadhandler import FileUploadHandler, StopUpload

from ..exceptions import FileTooLargeError, InvalidFileTypeError, UnsafeFilenameError
from ..progress.tracker import tracker as progress_tracker
from .validation import UploadContext, ValidationPipeline

logger = logging.getLogger(__name__)

TAKE_OWNERSHIP = getattr(settings, "UPLOAD_HANDLER_TAKE_OWNERSHIP", False)
CLEANUP_DELAY_S = int(getattr(settings, "UPLOAD_HANDLER_CLEANUP_DELAY_S", 300))
THROTTLE_SECONDS = float(getattr(settings, "UPLOAD_HANDLER_THROTTLE_SECONDS", 1.0))
THROTTLE_PERCENT = int(getattr(settings, "UPLOAD_HANDLER_THROTTLE_PERCENT", 2))
TMP_DIR_CONFIG = getattr(settings, "TEMP_UPLOAD_DIR", None)
SNIFF_BYTES = int(getattr(settings, "UPLOAD_MIME_SNIFF_BYTES", 2048))


class UploadStatus:
    PENDING = "pending"
    UPLOADING = "uploading"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    FAILED = "failed"
    COMPLETED = "completed"
    TERMINAL = {CANCELLED, FAILED, COMPLETED}


def _ensure_dir(path: Optional[str]) -> None:
    if path:
        try:
            os.makedirs(path, exist_ok=True)
        except Exception:
            logger.debug("Failed to ensure dir %s", path, exc_info=True)


class ProgressUploadHandler(FileUploadHandler):
    def __init__(self, request=None):
        super().__init__(request)
        self.request = request
        self.user = getattr(request, "user", None)
        uid = getattr(self.user, "id", "global")
        self.group_name = f"upload_user_{uid}"
        self.file_id = str(uuid.uuid4())
        self.start_time = time.time()

        self._written = 0
        self._hasher = hashlib.sha256()
        self._sniff_buffer = b""
        self._last_sent_progress = -1
        self._last_send_time = 0.0
        self.channel_layer = get_channel_layer()
        self.cancelled = False
        self.content_length = 0
        self.file_name: Optional[str] = None
        self.content_type: Optional[str] = None

        self._tmp_path: Optional[str] = self._make_tmp_path() if TAKE_OWNERSHIP else None

        if self.request is not None and not hasattr(self.request, "_uploaded_tmp_files"):
            self.request._uploaded_tmp_files: List[Dict[str, Any]] = []  # type: ignore

        self._init_cache_status()

    # -------------------- setup helpers --------------------
    def _make_tmp_path(self) -> Optional[str]:
        try:
            if TMP_DIR_CONFIG:
                _ensure_dir(TMP_DIR_CONFIG)
                tmp = tempfile.NamedTemporaryFile(delete=False, dir=TMP_DIR_CONFIG)
            else:
                tmp = tempfile.NamedTemporaryFile(delete=False)
            path = tmp.name
            tmp.close()
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
            return path
        except Exception:
            logger.exception("Failed creating tmp file; falling back to cooperative mode.")
            return None

    def _status_cache_key(self) -> str:
        return f"upload_status_{getattr(self.user, 'id', 'global')}"

    def _control_cache_key(self) -> str:
        return f"upload_control_{getattr(self.user, 'id', 'global')}"

    def _init_cache_status(self) -> None:
        upload_dict = cache.get(self._status_cache_key(), {}) or {}
        upload_dict[self.file_id] = {
            "progress": 0, "status": UploadStatus.UPLOADING, "error_code": None,
            "error_message": None, "tmp_path": self._tmp_path, "started_at": time.time(),
        }
        cache.set(self._status_cache_key(), upload_dict, timeout=CLEANUP_DELAY_S + 60)
        self._send_progress({self.file_id: upload_dict[self.file_id]})

    # -------------------- FileUploadHandler hooks --------------------
    def new_file(self, field_name, file_name, content_type, content_length, charset=None, content_type_extra=None):
        self.field_name = field_name
        self.file_name = file_name
        self.content_type = content_type or "application/octet-stream"
        try:
            self.content_length = int(content_length) if content_length is not None else 0
        except Exception:
            self.content_length = 0

        try:
            ValidationPipeline().run(UploadContext(
                filename=file_name, mime_type=self.content_type,
                size=self.content_length, tenant_id=getattr(self.request, "tenant_id", None),
            ))
        except (FileTooLargeError, InvalidFileTypeError, UnsafeFilenameError) as exc:
            self._update_cache_status(status=UploadStatus.FAILED, error_code=422, error_message=str(exc))
            raise StopUpload(connection_reset=True) from exc

        upload_dict = cache.get(self._status_cache_key(), {}) or {}
        entry = upload_dict.get(self.file_id, {})
        entry.update({"filename": file_name, "content_type": self.content_type, "content_length": self.content_length})
        upload_dict[self.file_id] = entry
        cache.set(self._status_cache_key(), upload_dict, timeout=CLEANUP_DELAY_S + 60)

        progress_tracker.create_task(
            user=getattr(self.request, "user", None), task_type="file_upload",
            file_id=self.file_id, storage_path=self._tmp_path or "", media_type=self.content_type,
        )

        if self.request is not None:
            self.request._uploaded_tmp_files.append({
                "file_id": self.file_id, "tmp_path": self._tmp_path, "filename": file_name,
                "content_type": self.content_type, "content_length": self.content_length,
                "created_at": time.time(), "progress": 0,
            })

    def receive_data_chunk(self, raw_data: bytes, start: int):
        try:
            controls = self._fetch_controls()

            if self.file_id in controls["cancel"]:
                self.cancelled = True
                self._update_cache_status(status=UploadStatus.CANCELLED, error_code=4001, error_message="Upload cancelled.")
                self._remove_tmp_file()
                self._remove_control("cancel", self.file_id)
                raise StopUpload(connection_reset=True)

            if self.file_id in controls["pause"]:
                self._update_cache_status(
                    status=UploadStatus.PAUSED,
                    error_message="Server paused upload (connection aborted). For true resume-after-disconnect, use the chunked upload session API.",
                )
                self._remove_control("pause", self.file_id)
                raise StopUpload(connection_reset=True)

            self._hasher.update(raw_data)
            if len(self._sniff_buffer) < SNIFF_BYTES:
                self._sniff_buffer += raw_data[: SNIFF_BYTES - len(self._sniff_buffer)]

            if TAKE_OWNERSHIP and self._tmp_path:
                try:
                    with open(self._tmp_path, "ab") as tf:
                        tf.write(raw_data)
                except Exception:
                    logger.exception("Failed writing chunk to tmp file for %s", self.file_id)
                    self._update_cache_status(status=UploadStatus.FAILED, error_code=5001, error_message="IO error writing temp file.")
                    raise StopUpload(connection_reset=True)

            self._written += len(raw_data)
            percent = self._compute_percent()
            self._update_cache_status(progress=percent)

            if self.request is not None:
                for e in self.request._uploaded_tmp_files:
                    if e.get("file_id") == self.file_id:
                        e.update({"progress": percent, "tmp_path": self._tmp_path})
                        break

            return None if TAKE_OWNERSHIP else raw_data
        except StopUpload:
            raise
        except Exception as exc:
            logger.exception("Error processing chunk for %s", self.file_id)
            self._update_cache_status(status=UploadStatus.FAILED, error_code=5002, error_message=str(exc))
            raise StopUpload(connection_reset=True)

    def file_complete(self, file_size):
        try:
            checksum = self._hasher.hexdigest()
            self._update_cache_status(progress=100, status=UploadStatus.COMPLETED)
            if self.request is not None:
                for e in self.request._uploaded_tmp_files:
                    if e.get("file_id") == self.file_id:
                        e.update({"progress": 100, "checksum": checksum})
                        break
            progress_tracker.mark_complete(self.file_id, by_task_id=False)
            return None
        except Exception as exc:
            logger.exception("file_complete error for %s", self.file_id)
            self._update_cache_status(status=UploadStatus.FAILED, error_code=5003, error_message=str(exc))
            return None

    def upload_complete(self):
        logger.debug("upload_complete for %s", self.file_id)

    # -------------------- cache / control helpers --------------------
    def _compute_percent(self) -> int:
        if self.content_length:
            try:
                return min(100, int((self._written / max(1, self.content_length)) * 100))
            except Exception:
                return 0
        try:
            return min(99, int(self._written / (1024 * 1024)))
        except Exception:
            return 0

    def _update_cache_status(self, progress=None, status=None, error_code=None, error_message=None):
        upload_dict = cache.get(self._status_cache_key(), {}) or {}
        entry = upload_dict.get(self.file_id) or {"progress": 0, "status": UploadStatus.UPLOADING, "tmp_path": self._tmp_path, "started_at": time.time()}
        if progress is not None:
            entry["progress"] = int(progress)
        if status is not None:
            entry["status"] = status
        if error_code is not None:
            entry["error_code"] = error_code
        if error_message is not None:
            entry["error_message"] = error_message
        upload_dict[self.file_id] = entry
        cache.set(self._status_cache_key(), upload_dict, timeout=CLEANUP_DELAY_S + 60)
        self._send_progress_throttled(upload_dict)
        progress_tracker.update_progress_by_file_id(
            self.file_id, entry.get("progress", 0), status=entry.get("status"), error_message=entry.get("error_message"),
        )
        if entry.get("status") in UploadStatus.TERMINAL:
            self._schedule_cleanup()

    def _fetch_controls(self) -> Dict[str, set]:
        controls = cache.get(self._control_cache_key(), {}) or {}
        to_set = lambda v: set(v) if isinstance(v, (list, tuple, set)) else ({v} if v else set())
        return {
            "cancel": to_set(controls.get("cancel_upload")),
            "pause": to_set(controls.get("pause_upload")),
            "resume": to_set(controls.get("resume_upload")),
        }

    def _remove_control(self, action: str, file_id: str) -> None:
        field = {"pause": "pause_upload", "resume": "resume_upload", "cancel": "cancel_upload"}.get(action)
        if not field:
            return
        key = self._control_cache_key()
        controls = cache.get(key, {}) or {}
        vals = set(controls.get(field, []))
        vals.discard(file_id)
        controls[field] = list(vals)
        cache.set(key, controls, timeout=3600)

    def _remove_tmp_file(self) -> None:
        if self._tmp_path and os.path.exists(self._tmp_path):
            try:
                os.remove(self._tmp_path)
            except Exception:
                logger.debug("Failed removing tmp file %s", self._tmp_path, exc_info=True)

    def _schedule_cleanup(self) -> None:
        cache_key, tmp_path, file_id = self._status_cache_key(), self._tmp_path, self.file_id

        def _cleanup():
            try:
                upload_dict = cache.get(cache_key, {}) or {}
                upload_dict.pop(file_id, None)
                cache.set(cache_key, upload_dict, timeout=CLEANUP_DELAY_S + 60)
                if tmp_path and os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                logger.exception("Cleanup error for %s", file_id)

        t = Timer(CLEANUP_DELAY_S, _cleanup)
        t.daemon = True
        t.start()

    def _send_progress(self, payload: Dict[str, Any]) -> None:
        if not self.channel_layer:
            return
        try:
            async_to_sync(self.channel_layer.group_send)(self.group_name, {"type": "send_progress", "upload_status": payload})
        except Exception:
            logger.debug("Channel send failed for %s", self.file_id, exc_info=True)

    def _send_progress_throttled(self, upload_dict: Dict[str, Any]) -> None:
        now = time.time()
        entry = upload_dict.get(self.file_id, {})
        progress = int(entry.get("progress", 0) or 0)
        if abs(progress - self._last_sent_progress) >= THROTTLE_PERCENT or now - self._last_send_time >= THROTTLE_SECONDS or self._last_sent_progress < 0:
            self._send_progress({self.file_id: entry})
            self._last_sent_progress, self._last_send_time = progress, now

    def cancel(self) -> None:
        self.cancelled = True
        self._update_cache_status(status=UploadStatus.CANCELLED, error_code=4001, error_message="Cancelled by server.")
        self._remove_tmp_file()

    def get_tmp_path(self) -> Optional[str]:
        return self._tmp_path

    def get_checksum(self) -> str:
        return self._hasher.hexdigest()
