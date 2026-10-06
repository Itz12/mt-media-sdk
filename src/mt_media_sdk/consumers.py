"""
media.consumers
------------------
Websocket consumer for live upload/progress updates. Two delivery paths:
  * push - if the configured ProgressBackend supports pub/sub (e.g.
    RedisProgressBackend), updates are group_send'd to the client the
    moment they happen (see ProgressTracker._publish).
  * poll - a low-frequency reconciliation loop (default 3s) that merges
    cache + DB state, so clients still get updates with the default
    DjangoCacheProgressBackend (locmem/Memcached have no pub/sub) and so a
    missed push (e.g. a message sent while briefly disconnected) still
    self-heals within one poll interval.

Protocol
~~~~~~~~
Client -> server (JSON):
    {"action": "pause"|"resume"|"cancel", "file_id": "..."}
    {"action": "ping"}
Server -> client (JSON):
    {"type": "progress_update", "uploads": [...], "initial": bool}
    {"type": "progress_event", "upload_status": {...}}      # push path
    {"type": "command_response", "file_id", "action", "status", "hint"}
    {"type": "pong"}
    {"type": "error", "code", "message"}
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Dict

from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings
from django.core.cache import cache

from .models import Load

logger = logging.getLogger(__name__)

MAX_ACTIVE_UPLOADS = getattr(settings, "UPLOAD_HANDLER_MAX_ACTIVE_UPLOADS", 10)
POLL_INTERVAL_S = float(getattr(settings, "UPLOAD_PROGRESS_POLL_INTERVAL", 3.0))
HEARTBEAT_INTERVAL_S = float(getattr(settings, "UPLOAD_PROGRESS_HEARTBEAT_INTERVAL", 20.0))

TERMINAL_STATUSES = {"cancelled", "failed", "completed", "aborted", "expired"}


class UploadProgressConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope.get("user")
        if not self.user or not getattr(self.user, "is_authenticated", False):
            logger.warning("Unauthenticated websocket connection attempt to upload progress consumer.")
            await self.close()
            return

        self.group_name = f"upload_user_{self.user.id}"
        self.push_group_name = f"upload_progress.{self.user.id}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.channel_layer.group_add(self.push_group_name, self.channel_name)
        await self.accept()
        logger.info("User %s connected to upload progress websocket.", self.user.id)

        try:
            await self.send_progress_updates(initial=True)
        except Exception:
            logger.exception("Failed to send initial progress snapshot on connect.")

        self._poll_task = asyncio.create_task(self._poll_loop())
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def disconnect(self, close_code):
        for group in (getattr(self, "group_name", None), getattr(self, "push_group_name", None)):
            if group:
                try:
                    await self.channel_layer.group_discard(group, self.channel_name)
                except Exception:
                    logger.debug("Error discarding channel group %s.", group, exc_info=True)

        for attr in ("_poll_task", "_heartbeat_task"):
            task = getattr(self, attr, None)
            if task:
                task.cancel()
                try:
                    await task
                except Exception:
                    pass

        logger.info("User %s disconnected (code=%s).", getattr(self.user, "id", "<anon>"), close_code)

    async def receive(self, text_data=None, bytes_data=None):
        try:
            data = json.loads(text_data or "{}")
            action = (data.get("action") or "").strip().lower()

            if action == "ping":
                await self.send(text_data=json.dumps({"type": "pong"}))
                return

            file_id = data.get("file_id")
            if action not in ("pause", "resume", "cancel") or not file_id:
                await self._send_error("invalid_command", "Expected {action: pause|resume|cancel, file_id: ...}")
                return

            await sync_to_async(self._apply_control, thread_sensitive=True)(action, file_id)
            await self._send_command_response(file_id, action, "accepted", hint=self._recommended_action_for_client(action))

        except Exception as exc:
            logger.exception("Error processing websocket command: %s", exc)
            await self._send_error("internal_error", str(exc))

    def _apply_control(self, action: str, file_id: str) -> None:
        control_key = f"upload_control_{self.user.id}"
        control = cache.get(control_key, {}) or {}
        to_set = lambda field: set(control.get(field, []))
        pause_set, resume_set, cancel_set = to_set("pause_upload"), to_set("resume_upload"), to_set("cancel_upload")

        if action == "pause":
            pause_set.add(file_id); resume_set.discard(file_id)
        elif action == "resume":
            resume_set.add(file_id); pause_set.discard(file_id); cancel_set.discard(file_id)
        elif action == "cancel":
            cancel_set.add(file_id); pause_set.discard(file_id); resume_set.discard(file_id)

        cache.set(control_key, {
            "pause_upload": list(pause_set), "resume_upload": list(resume_set), "cancel_upload": list(cancel_set),
        }, timeout=3600)

    def _recommended_action_for_client(self, action: str) -> str:
        if action == "pause":
            return "Upload paused (connection aborted). For true resume-after-disconnect, use the chunked upload session API instead of the simple upload endpoint."
        if action == "resume":
            return "Resume requested: if this file was on the simple upload endpoint, restart it; chunked sessions resume via GET .../sessions/{id}/."
        if action == "cancel":
            return "Upload cancelled; any staged data will be cleaned up server-side."
        return ""

    async def _send_command_response(self, file_id, action, status_, hint=None):
        await self.send(text_data=json.dumps({
            "type": "command_response", "file_id": file_id, "action": action, "status": status_, "hint": hint,
        }))

    async def _send_error(self, code: str, message: str):
        await self.send(text_data=json.dumps({"type": "error", "code": code, "message": message}))

    # ---- push path: invoked via channel_layer.group_send from ProgressTracker/tasks ----
    async def send_progress(self, event):
        await self.send(text_data=json.dumps({"type": "progress_event", "upload_status": event.get("upload_status", {})}))

    # ---- poll path (reconciliation fallback) ----
    async def _poll_loop(self):
        try:
            while True:
                await asyncio.sleep(POLL_INTERVAL_S)
                await self.send_progress_updates()
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Progress poll loop failed for user %s", getattr(self.user, "id", "<anon>"))

    async def _heartbeat_loop(self):
        try:
            while True:
                await asyncio.sleep(HEARTBEAT_INTERVAL_S)
                await self.send(text_data=json.dumps({"type": "pong", "heartbeat": True}))
        except asyncio.CancelledError:
            pass

    async def send_progress_updates(self, initial=False):
        try:
            cache_key = f"upload_status_{self.user.id}"
            cache_data = cache.get(cache_key, {}) or {}
            if isinstance(cache_data, dict) and len(cache_data) > MAX_ACTIVE_UPLOADS:
                trimmed = sorted(cache_data.items(), key=lambda kv: kv[1].get("started_at", 0))[-MAX_ACTIVE_UPLOADS:]
                cache_data = dict(trimmed)
                cache.set(cache_key, cache_data, timeout=3600)

            db_uploads = await self._get_active_uploads()
            merged: Dict[str, Any] = {}
            for d in db_uploads:
                fid = d.get("file_id")
                if fid:
                    merged[fid] = {**d, **(cache_data.get(fid, {}) if isinstance(cache_data, dict) else {})}
            if isinstance(cache_data, dict):
                for fid, entry in cache_data.items():
                    merged.setdefault(fid, entry)

            await self.send(text_data=json.dumps({
                "type": "progress_update", "initial": bool(initial), "uploads": list(merged.values()),
            }))
        except Exception:
            logger.exception("send_progress_updates failed")

    @sync_to_async
    def _get_active_uploads(self):
        try:
            qs = Load.objects.filter(user=self.user).exclude(status__in=TERMINAL_STATUSES)
            rows = list(qs.values(
                "external_file_ref", "status", "progress", "task_id", "storage_path", "media_type", "created_at",
            ).order_by("-created_at")[:MAX_ACTIVE_UPLOADS])
            normalized = []
            for r in rows:
                started = r.get("created_at")
                if hasattr(started, "isoformat"):
                    started = started.isoformat()
                storage = r.get("storage_path")
                normalized.append({
                    "file_id": r.get("external_file_ref"),
                    "status": r.get("status"),
                    "progress": float(r.get("progress") or 0.0),
                    "task_id": r.get("task_id"),
                    "file_name": os.path.basename(storage) if storage else None,
                    "file_type": r.get("media_type"),
                    "started_at": started,
                })
            return normalized
        except Exception:
            logger.exception("Failed querying active uploads from DB.")
            return []
