from __future__ import annotations

from functools import lru_cache
import os
from pathlib import Path
import threading
import time
import uuid

from .storage_settings import (
    StorageAlias, StorageBucketSpec, StorageHealthError, StorageSettings,
    build_storage_django_settings, build_storage_settings, clear_s3_client_cache,
    validate_storage_settings,
)

_FAILURE_CACHE_SECONDS = 30.0
_LOCK = threading.RLock()
_LAST_FAILURE: tuple[float, type[BaseException], str] | None = None


def _safe_failure(exc: BaseException) -> tuple[type[BaseException], str]:
    return type(exc), type(exc).__name__


def _raise_cached_failure(entry: tuple[float, type[BaseException], str]) -> None:
    _, exc_type, message = entry
    raise exc_type(message)


def _get_storage_settings_uncached() -> StorageSettings:
    global _LAST_FAILURE
    now = time.monotonic()
    with _LOCK:
        if _LAST_FAILURE is not None and now - _LAST_FAILURE[0] < _FAILURE_CACHE_SECONDS:
            _raise_cached_failure(_LAST_FAILURE)
        try:
            settings = build_storage_settings(os.environ)
            validate_storage_settings(settings)
        except (StorageHealthError, ValueError, RuntimeError) as exc:
            exc_type, message = _safe_failure(exc)
            _LAST_FAILURE = (now, exc_type, message)
            raise
        _LAST_FAILURE = None
        return settings

def _configured_django_storage_settings() -> StorageSettings | None:
    try:
        from django.conf import settings as django_settings
        candidate = getattr(django_settings, "STORAGE_SETTINGS", None)
    except Exception:
        return None
    return candidate if isinstance(candidate, StorageSettings) else None

@lru_cache(maxsize=1)
def get_storage_settings() -> StorageSettings:
    configured = _configured_django_storage_settings()
    return configured if configured is not None else _get_storage_settings_uncached()

@lru_cache(maxsize=1)
def get_django_storage_settings() -> dict[str, object]:
    configured = _configured_django_storage_settings()
    if configured is not None:
        return {
            "STORAGES": configured.build_django_storages(),
            "MEDIA_URL": configured.media_url,
            "STATIC_URL": configured.static_url,
            "MEDIA_ROOT": str(configured.storage_root / "media"),
            "STATIC_ROOT": str(configured.storage_root / "staticfiles"),
            "BACKUP_ROOT": str(configured.backup_root),
            "STORAGE_CONFIG": configured.as_dict(),
        }
    return build_storage_django_settings(os.environ)


def clear_storage_caches() -> None:
    global _LAST_FAILURE
    with _LOCK:
        get_storage_settings.cache_clear()
        get_django_storage_settings.cache_clear()
        _LAST_FAILURE = None
    try:
        from .registry import clear_storage_backend_cache
        clear_storage_backend_cache()
    finally:
        clear_s3_client_cache()


def get_storage_backend_for_alias(alias: StorageAlias = "media", *, settings: StorageSettings | None = None):
    from .registry import get_storage_backend_for_bucket
    return get_storage_backend_for_bucket(alias, settings=settings)


def get_bucket_spec(alias: StorageAlias = "media") -> StorageBucketSpec:
    bucket = get_storage_settings().get_bucket(alias)
    if bucket is None:
        raise ValueError(f"Unknown storage alias: {alias}")
    return bucket


def probe_storage_bucket(bucket: StorageBucketSpec, settings: StorageSettings) -> tuple[bool, str]:
    if not bucket.is_remote():
        return True, "local"
    from .storage_settings import get_s3_client_for_bucket
    canary_key = f".health-check/{uuid.uuid4().hex}.tmp"
    payload = b"must-tip-storage-health-check"
    client = get_s3_client_for_bucket(bucket)
    try:
        client.put_object(Bucket=bucket.bucket_name, Key=canary_key, Body=payload, **bucket.s3_object_parameters())
        response = client.get_object(Bucket=bucket.bucket_name, Key=canary_key)
        body = response.get("Body")
        data = body.read(len(payload) + 1) if body is not None else b""
        close = getattr(body, "close", None)
        if callable(close): close()
        if data != payload:
            return False, "read-integrity"
        client.delete_object(Bucket=bucket.bucket_name, Key=canary_key)
        try:
            client.head_object(Bucket=bucket.bucket_name, Key=canary_key)
            return False, "delete-verification"
        except Exception as exc:
            response = getattr(exc, "response", None)
            error = response.get("Error", {}) if isinstance(response, dict) else {}
            status = response.get("ResponseMetadata", {}).get("HTTPStatusCode") if isinstance(response, dict) else None
            code = str(error.get("Code", "")) if isinstance(error, dict) else ""
            if status != 404 and code not in {"404", "NoSuchKey", "NotFound"}:
                return False, type(exc).__name__
        return True, "put/get/delete"
    except Exception as exc:
        try: client.delete_object(Bucket=bucket.bucket_name, Key=canary_key)
        except Exception: pass
        return False, type(exc).__name__


def get_private_media_url(object_key: str, *, expires_seconds: int | None = None) -> str:
    return get_storage_settings().build_private_media_url(object_key, expires_seconds=expires_seconds)


def get_private_upload_url(object_key: str, *, expires_seconds: int | None = None) -> str:
    return get_storage_settings().build_private_upload_url(object_key, expires_seconds=expires_seconds)


def run_uploaded_file_scan(file_path: Path, *, object_key: str | None = None, bucket_name: str | None = None) -> None:
    get_storage_settings().run_virus_scan_hook(file_path, object_key=object_key, bucket_name=bucket_name)


def record_storage_event(event: str, *, alias: str = "media", success: bool, duration_seconds: float = 0.0, detail: str | None = None) -> None:
    get_storage_settings().record_metric(event, alias=alias, success=success, duration_seconds=duration_seconds, detail=detail)  # type: ignore[arg-type]
