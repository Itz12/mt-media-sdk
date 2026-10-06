"""
media.progress.backends
--------------------------
Abstraction over "where does live progress state live". The default,
``DjangoCacheProgressBackend``, works with whatever ``CACHES['default']``
is configured (locmem for dev, Memcached/Redis for prod) but has no
push/pub-sub capability, so the websocket consumer falls back to polling.

``RedisProgressBackend`` adds real pub/sub: ``ProgressTracker`` publishes to
a per-user channel the instant a Load updates, and the consumer can push
that straight to the browser instead of waiting for its poll loop. Swap
backends via ``settings.UPLOAD_PROGRESS_BACKEND`` - no other module needs
to change.
"""
from __future__ import annotations

import abc
import json
from typing import Optional

from django.conf import settings
from django.core.cache import cache as django_cache


class ProgressBackend(abc.ABC):
    @abc.abstractmethod
    def set(self, key: str, data: dict, timeout: int = 3600) -> None: ...

    @abc.abstractmethod
    def get(self, key: str) -> Optional[dict]: ...

    @abc.abstractmethod
    def delete(self, key: str) -> None: ...

    def publish(self, channel: str, message: dict) -> None:
        """Optional push notification. Default no-op; backends that support
        pub/sub (Redis) override this."""
        return None


class DjangoCacheProgressBackend(ProgressBackend):
    def set(self, key, data, timeout=3600):
        django_cache.set(key, data, timeout=timeout)

    def get(self, key):
        return django_cache.get(key)

    def delete(self, key):
        django_cache.delete(key)


class RedisProgressBackend(ProgressBackend):
    """Direct redis-py client. Requires the ``redis`` package and
    ``settings.UPLOAD_PROGRESS_REDIS_URL``. Imported lazily so the module
    loads fine without the optional dependency installed."""

    def __init__(self, url: Optional[str] = None):
        import redis
        self._redis = redis.Redis.from_url(
            url or getattr(settings, "UPLOAD_PROGRESS_REDIS_URL", "redis://localhost:6379/0")
        )

    def set(self, key, data, timeout=3600):
        self._redis.set(key, json.dumps(data), ex=timeout)

    def get(self, key):
        raw = self._redis.get(key)
        return json.loads(raw) if raw else None

    def delete(self, key):
        self._redis.delete(key)

    def publish(self, channel, message):
        self._redis.publish(channel, json.dumps(message))


_backend_instance: Optional[ProgressBackend] = None


def get_progress_backend() -> ProgressBackend:
    global _backend_instance
    if _backend_instance is not None:
        return _backend_instance
    path = getattr(settings, "UPLOAD_PROGRESS_BACKEND", None)
    if not path:
        _backend_instance = DjangoCacheProgressBackend()
    else:
        from django.utils.module_loading import import_string
        backend_cls = import_string(path)
        _backend_instance = backend_cls()
    return _backend_instance
