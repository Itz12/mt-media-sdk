from __future__ import annotations

import importlib
import threading
from typing import Mapping

from ..exceptions import StorageBackendError
from .base import StorageBackend

_LOCK = threading.RLock()
_BACKEND_CLASSES: dict[str, type[StorageBackend]] = {}
_BACKEND_CACHE: dict[tuple[str, str], StorageBackend] = {}
_MAX_BACKENDS = 64


def _load_class(path: str) -> type[StorageBackend]:
    module_name, _, attr = str(path).rpartition(".")
    if not module_name or not attr:
        raise StorageBackendError("Storage backend path must be a dotted class path")
    module = importlib.import_module(module_name)
    candidate = getattr(module, attr, None)
    if not isinstance(candidate, type) or not issubclass(candidate, StorageBackend):
        raise StorageBackendError("Configured storage backend must subclass StorageBackend")
    return candidate


def _default_classes() -> dict[str, type[StorageBackend]]:
    from .local import LocalFileSystemBackend
    from .s3 import S3StorageBackend
    return {"local": LocalFileSystemBackend, "filesystem": LocalFileSystemBackend, "s3": S3StorageBackend}


def register_storage_backend(name: str, backend: type[StorageBackend], *, replace: bool = False) -> None:
    key = str(name or "").strip().casefold()
    if not key or len(key) > 64:
        raise StorageBackendError("Storage backend name is invalid")
    if not isinstance(backend, type) or not issubclass(backend, StorageBackend):
        raise StorageBackendError("Storage backend must subclass StorageBackend")
    with _LOCK:
        if key in _BACKEND_CLASSES and not replace:
            raise StorageBackendError("Storage backend is already registered")
        if key not in _BACKEND_CLASSES and len(_BACKEND_CLASSES) >= _MAX_BACKENDS:
            raise StorageBackendError("Storage backend registry is full")
        _BACKEND_CLASSES[key] = backend


def get_storage_backend(name: str) -> StorageBackend:
    key = str(name or "").strip().casefold()
    with _LOCK:
        cls = _BACKEND_CLASSES.get(key)
    if cls is None:
        cls = _default_classes().get(key)
    if cls is None:
        try:
            from django.conf import settings
            configured = getattr(settings, "UPLOAD_STORAGE_BACKENDS", {})
        except Exception:
            configured = {}
        if isinstance(configured, Mapping) and key in configured:
            cls = _load_class(str(configured[key]))
    if cls is None:
        raise StorageBackendError("Unknown storage backend")
    return cls()


def get_storage_backend_for_bucket(alias: str = "media", settings=None) -> StorageBackend:
    if settings is None:
        from .storage_bootstrap import get_storage_settings
        settings = get_storage_settings()
    bucket = settings.get_bucket(alias)  # type: ignore[arg-type]
    if bucket is None:
        raise StorageBackendError("Unknown storage bucket alias")
    backend_name = "s3" if bucket.is_remote() else "local"
    cache_key = (str(alias), settings.configuration_digest or settings.configuration_fingerprint())
    with _LOCK:
        cached = _BACKEND_CACHE.get(cache_key)
        if cached is not None:
            return cached
        cls = _BACKEND_CLASSES.get(backend_name) or _default_classes()[backend_name]
        try:
            backend = cls.from_bucket_spec(bucket, settings)
        except NotImplementedError:
            backend = cls()
        if len(_BACKEND_CACHE) >= _MAX_BACKENDS:
            _BACKEND_CACHE.pop(next(iter(_BACKEND_CACHE)))
        _BACKEND_CACHE[cache_key] = backend
        return backend


def clear_storage_backend_cache() -> None:
    with _LOCK:
        backends = list(_BACKEND_CACHE.values())
        _BACKEND_CACHE.clear()
    for backend in backends:
        close = getattr(backend, "close", None)
        if callable(close):
            try: close()
            except Exception: pass
