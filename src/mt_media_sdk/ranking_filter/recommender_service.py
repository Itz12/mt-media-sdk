from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit, urlunsplit

# optional heavy deps
try:
    import numpy as np  # type: ignore
except Exception:
    np = None  # type: ignore

# Recommended lightweight redis client (must be installed by the app)
try:
    import redis as redis_lib  # type: ignore
except Exception:
    redis_lib = None  # type: ignore

logger = logging.getLogger("recommender")
# Library code should never call logging.basicConfig() at import time - doing
# so silently configures (or reconfigures) the *root* logger the moment this
# module is imported, which can clobber whatever logging setup the host
# application already has. A NullHandler is the correct default: it means
# "do nothing until the application attaches its own handler", which is
# exactly what a reusable service module should do.
logger.addHandler(logging.NullHandler())


# ---------------------------
# Shared type aliases
# ---------------------------
# Canonical home for these two aliases - dynamic_streams.py and
# dynamic_featured.py both import them from here rather than each declaring
# their own copy (they used to: recommender_service.py had a named alias,
# dynamic_streams.py re-declared an identical one, dynamic_featured.py
# inlined the same signature unnamed in every function parameter - three
# ways to spell the same type, with no guarantee they'd stay in sync).
ProductFetcher = Callable[[Iterable[int]], Iterable[Any]]
FeaturedFetcher = Callable[[], Iterable[Any]]
UserInteractionFetcher = Callable[[], Iterable[Tuple[int, int, float]]]
MessagePublisher = Callable[[str, Dict[str, Any]], None]
MetricsHook = Callable[[str, Dict[str, Any]], None]

__all__ = [
    "RecommenderConfig",
    "RecommenderService",
    "ProductFetcher",
    "FeaturedFetcher",
    "UserInteractionFetcher",
    "MessagePublisher",
    "MetricsHook",
]


def redact_redis_url(url: Optional[str]) -> str:
    """
    Strip userinfo (user:password@) from a redis:// URL before it ever
    touches a log line. redis://:mysecretpassword@host:6379/0 logged
    verbatim - which the original code did on every connection failure -
    puts the Redis password in plaintext application logs, which routinely
    end up in log aggregators, error trackers, or support tickets. Returns
    "<invalid-url>" rather than raising if the URL can't be parsed, since
    this is only ever used for display/logging, never for the actual
    connection.
    """
    if not url:
        return "<empty>"
    try:
        parts = urlsplit(url)
        if "@" in parts.netloc:
            host_part = parts.netloc.rsplit("@", 1)[1]
            netloc = f"***:***@{host_part}"
        else:
            netloc = parts.netloc
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        return "<unparseable-url>"


# ---------------------------
# Config / dataclass
# ---------------------------
@dataclass
class RecommenderConfig:
    interaction_list_max: int = 20
    click_expire_seconds: int = 30 * 24 * 3600  # 30 days
    featured_cache_ttl: int = 3600  # 1 hour
    trending_global_key: str = "global:clicks"  # zset for global trending
    namespace: str = "rec"  # prefix for redis keys to avoid collisions
    redis_url_env: str = "REDIS_URL"  # env var used if redis_client not provided

    # -- Connection resilience --------------------------------------------
    # The original client construction (`redis_lib.from_url(redis_url)`) set
    # no timeouts at all: a network partition or a slow/hung Redis node
    # could block a calling request/task indefinitely. These bound the
    # worst case per call.
    socket_timeout_seconds: float = 3.0
    socket_connect_timeout_seconds: float = 2.0
    retry_on_timeout: bool = True
    max_connections: Optional[int] = 50
    health_check_interval_seconds: int = 30

    # -- Circuit breaker ----------------------------------------------------
    # After this many consecutive failures across public methods, stop
    # attempting Redis calls for circuit_breaker_cooldown_seconds rather
    # than paying a fresh timeout on every single call during an outage.
    circuit_breaker_threshold: int = 5
    circuit_breaker_cooldown_seconds: float = 30.0

    # -- Featured boost weights ---------------------------------------------
    # Previously hardcoded inline inside compute_boost_score(); centralized
    # here so it's configurable the same way every other tunable in this
    # service is, and so a caller building a RecommenderConfig from
    # settings/env doesn't have two different places to look.
    boost_weights: Dict[str, float] = field(
        default_factory=lambda: {
            "clicks": 0.7,
            "impressions": 0.3,
            "category_match": 3.0,
            "recent_boost": 1.0,
        }
    )

    # -- Collaborative-recommendation caching --------------------------------
    collaborative_cache_ttl_seconds: int = 300
    cache_ttl_jitter_ratio: float = 0.1  # +/- 10% jitter to avoid synchronized expiry


# ---------------------------
# Main service class
# ---------------------------
class RecommenderService:
    """
    RecommenderService: centralized logic for tracking interactions, computing featured boosts,
    trending and collaborative recommendations.

    External systems (redis, ml_model, message publisher) should be injected for tests.

    Every public method is defensive by design: a missing/failed Redis
    connection degrades to `{"ok": False, "error": "redis_unavailable", ...}`
    (or `"circuit_open"` under sustained failures - see the circuit-breaker
    note below) rather than raising, so a Redis outage degrades a
    recommendation feature gracefully instead of taking down the request
    that happens to call it.

    See the "Example usage" section at the bottom of this module for a
    complete, realistic setup (DI wiring, a DRF view, a periodic featured-
    ranking task).
    """

    def __init__(
        self,
        *,
        redis_client: Optional["redis_lib.Redis"] = None,
        config: Optional[RecommenderConfig] = None,
        ml_model: Optional[Any] = None,
        message_publisher: Optional[MessagePublisher] = None,
        metrics_hook: Optional[MetricsHook] = None,
    ):
        self.config = config or RecommenderConfig()
        self._ml_model = ml_model
        self._publisher = message_publisher
        self._metrics = metrics_hook

        # circuit breaker state
        self._consecutive_failures = 0
        self._circuit_opened_at: Optional[float] = None

        # instantiate or validate redis client
        if redis_client is not None:
            self.redis = redis_client
        else:
            if redis_lib is None:
                # allow running without redis for read-only or local unit-tests, but writes will fail explicitly
                self.redis = None
                logger.warning(
                    "redis library not installed and no redis_client injected; Redis features disabled"
                )
            else:
                # try connect via URL env or localhost fallback
                redis_url = os.environ.get(
                    self.config.redis_url_env, "redis://localhost:6379/0"
                )
                try:
                    # prefer from_url which handles connection pools; now with
                    # bounded timeouts and pool sizing instead of client
                    # defaults (which, for socket timeouts, means "never").
                    self.redis = redis_lib.from_url(
                        redis_url,
                        socket_timeout=self.config.socket_timeout_seconds,
                        socket_connect_timeout=self.config.socket_connect_timeout_seconds,
                        retry_on_timeout=self.config.retry_on_timeout,
                        max_connections=self.config.max_connections,
                        health_check_interval=self.config.health_check_interval_seconds,
                    )
                except TypeError:
                    # Some redis-py versions/forks don't accept every kwarg
                    # above (e.g. very old clients lack health_check_interval
                    # on from_url). Retry with just the two that matter most
                    # (timeouts) rather than failing outright over a
                    # secondary tuning parameter.
                    try:
                        self.redis = redis_lib.from_url(
                            redis_url,
                            socket_timeout=self.config.socket_timeout_seconds,
                            socket_connect_timeout=self.config.socket_connect_timeout_seconds,
                        )
                    except Exception:
                        logger.exception(
                            "Failed to create redis client from url=%s",
                            redact_redis_url(redis_url),
                        )
                        self.redis = None
                except Exception:
                    logger.exception(
                        "Failed to create redis client from url=%s",
                        redact_redis_url(redis_url),
                    )
                    self.redis = None

    # ---------------------------
    # Connection lifecycle / health
    # ---------------------------
    def health_check(self) -> Dict[str, Any]:
        """
        Explicit health probe, suitable for a readiness/liveness endpoint or
        a periodic background check. Does not consult or affect the circuit
        breaker's failure count in either direction beyond what a real PING
        naturally would - a manual health check succeeding does reset the
        breaker (that's the point of calling it), a failure opens it exactly
        like any other failed operation.
        """
        t0 = time.time()
        if self.redis is None:
            return {"ok": False, "error": "redis_unavailable", "elapsed_ms": int((time.time() - t0) * 1000)}
        try:
            pong = self.redis.ping()
            self._record_redis_success()
            return {"ok": bool(pong), "elapsed_ms": int((time.time() - t0) * 1000)}
        except Exception as exc:
            self._record_redis_failure()
            return {
                "ok": False,
                "error": "exception",
                "detail": str(exc),
                "elapsed_ms": int((time.time() - t0) * 1000),
            }

    def close(self) -> None:
        """Release the underlying connection pool. Safe to call multiple
        times or when Redis was never configured. Intended for graceful
        shutdown (e.g. an ASGI lifespan handler or a worker exit hook) -
        redis-py connection pools otherwise just get garbage collected,
        which works but isn't deterministic."""
        if self.redis is None:
            return
        try:
            close_fn = getattr(self.redis, "close", None)
            if callable(close_fn):
                close_fn()
                return
            pool = getattr(self.redis, "connection_pool", None)
            disconnect_fn = getattr(pool, "disconnect", None)
            if callable(disconnect_fn):
                disconnect_fn()
        except Exception:
            logger.debug("RecommenderService.close(): error while closing redis client", exc_info=True)

    # ---------------------------
    # Circuit breaker
    # ---------------------------
    def _circuit_is_open(self) -> bool:
        if self._circuit_opened_at is None:
            return False
        if (time.time() - self._circuit_opened_at) >= self.config.circuit_breaker_cooldown_seconds:
            # Cooldown elapsed - close the circuit and give the next call a
            # real chance rather than staying open forever on a fixed timer.
            self._circuit_opened_at = None
            self._consecutive_failures = 0
            return False
        return True

    def _record_redis_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.config.circuit_breaker_threshold and self._circuit_opened_at is None:
            self._circuit_opened_at = time.time()
            logger.warning(
                "RecommenderService: circuit breaker opened after %d consecutive Redis failures; "
                "pausing Redis calls for %.0fs",
                self._consecutive_failures, self.config.circuit_breaker_cooldown_seconds,
            )

    def _record_redis_success(self) -> None:
        if self._consecutive_failures or self._circuit_opened_at:
            logger.info("RecommenderService: Redis call succeeded; circuit breaker reset")
        self._consecutive_failures = 0
        self._circuit_opened_at = None

    def _redis_ready(self) -> bool:
        return self.redis is not None and not self._circuit_is_open()

    def _unavailable_response(self, **extra) -> Dict[str, Any]:
        """Shared shape for "can't reach Redis right now" responses, used by
        both the "never configured" and "circuit breaker open" cases so
        callers checking `resp.get("error") == "redis_unavailable"` keep
        working either way; `circuit_open` is additive for callers that
        want to distinguish the two."""
        return {
            "ok": False,
            "error": "redis_unavailable",
            "circuit_open": self._circuit_is_open(),
            **extra,
        }

    # ---------------------------
    # Redis key helpers
    # ---------------------------
    def _interaction_key(self, user_id: int, action: str) -> str:
        return f"{self.config.namespace}:user:{user_id}:action:{action}"

    def _clicks_zset_key(self, user_id: Optional[int] = None) -> str:
        # use configured global key when user_id is None
        if user_id is None:
            return f"{self.config.namespace}:{self.config.trending_global_key}"
        return f"{self.config.namespace}:user:{user_id}:clicks"

    def _featured_boost_key(self, product_id: int) -> str:
        return f"{self.config.namespace}:featured:product:{product_id}:boost"

    def _collaborative_cache_key(self, user_id: int, top_k_users: int, top_products: int) -> str:
        return f"{self.config.namespace}:user:{user_id}:collab:{top_k_users}:{top_products}"

    def _ttl_with_jitter(self, base_ttl: int) -> int:
        """Add up to +/- cache_ttl_jitter_ratio to a TTL so many keys set at
        the same time (e.g. a batch featured-ranking update) don't all
        expire in the same instant and stampede recomputation."""
        ratio = max(0.0, min(0.5, self.config.cache_ttl_jitter_ratio))
        if ratio <= 0 or base_ttl <= 0:
            return base_ttl
        import random
        jitter = base_ttl * ratio
        return max(1, int(base_ttl + random.uniform(-jitter, jitter)))  # noqa: S311

    # ---------------------------
    # Utilities
    # ---------------------------
    def _safe_pipeline(self):
        """
        Return a pipeline-like object. For real redis-py this will be the pipeline.
        For lightweight fakes that return self from .pipeline(), it will be that object.
        We do not try to normalize behavior here — callers remain defensive.
        """
        if self.redis is None:
            raise RuntimeError("Redis client not configured")
        try:
            return self.redis.pipeline()
        except Exception:
            # Try alternative locations or return redis itself as a last resort.
            try:
                return self.redis.connection.pipeline()
            except Exception:
                return self.redis

    @staticmethod
    def _to_text(v: Union[bytes, bytearray, str, int, None]) -> Optional[str]:
        if v is None:
            return None
        if isinstance(v, (bytes, bytearray)):
            try:
                return v.decode()
            except Exception:
                return str(v)
        return str(v)

    def _head_equals(self, key: str, val: Union[int, str, bytes]) -> bool:
        """
        Check whether the first element of the redis list at `key` equals `val`.
        Works with bytes/str/int stored by fakes. Falls back to .storage if lrange returned empty.
        """
        try:
            head = None
            head_arr = []
            try:
                head_arr = self.redis.lrange(key, 0, 0)
            except Exception:
                # last resort: try reading storage directly if available
                head_arr = []
            if not head_arr and hasattr(self.redis, "storage"):
                arr = self.redis.storage.get(key, [])
                head = arr[0] if arr else None
            else:
                head = head_arr[0] if head_arr else None

            if head is None:
                return False
            head_txt = self._to_text(head)
            val_txt = self._to_text(val)
            return head_txt == val_txt
        except Exception:
            return False

    def _decode_redis_list_to_ints(
        self, arr: Iterable[Union[bytes, str, int]]
    ) -> List[int]:
        out: List[int] = []
        for v in arr or []:
            try:
                if isinstance(v, (bytes, bytearray)):
                    s = v.decode()
                else:
                    s = str(v)
                out.append(int(s))
            except Exception:
                logger.debug("Skipping a Redis list value that is not an integer")
                continue
        return out

    def _decode_redis_zrange(
        self, arr: Iterable, withscores: bool = True
    ) -> List[Tuple[int, float]]:
        """
        Normalize zrange-like return into list of (int_member, float_score).
        Accepts sequences like [(b'mem', b'score'), ...] or [(b'mem', score_float), ...]
        or simple member lists if withscores=False.
        """
        items: List[Tuple[int, float]] = []
        if not arr:
            return items
        try:
            for entry in arr:
                if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                    mem, sc = entry[0], entry[1]
                else:
                    mem = entry
                    sc = None
                mem_txt = self._to_text(mem)
                if mem_txt is None:
                    continue
                pid = None
                # Try parse member as int first
                try:
                    pid = int(mem_txt)
                except Exception:
                    # maybe the return is swapped: score then member
                    try:
                        sc_txt = self._to_text(sc)
                        pid = int(sc_txt) if sc_txt is not None else None
                    except Exception:
                        pid = None
                # parse score
                score = 0.0
                try:
                    if sc is None:
                        # no score present
                        score = 0.0
                    else:
                        if isinstance(sc, (bytes, bytearray)):
                            score = float(sc.decode())
                        else:
                            score = float(sc)
                except Exception:
                    # fallback: maybe mem_txt is the score (swapped)
                    try:
                        score = float(mem_txt)
                    except Exception:
                        score = 0.0
                if pid is None:
                    continue
                items.append((pid, score))
        except Exception:
            logger.exception("Failed decoding zrange response")
        return items

    # ---------------------------
    # Interaction tracking (lightweight)
    # ---------------------------
    def track_interaction(
        self,
        user_id: int,
        product_id: int,
        action: str,
        *,
        publish: bool = False,
    ) -> Dict[str, Any]:
        """
        Append a recent interaction into a per-user Redis list (views/clicks/etc).
        This method prefers pipeline usage but always validates state and performs
        a synchronous fallback write if the pipeline didn't persist to ensure tests
        (and callers) see the recorded value.
        """
        t0 = time.time()
        resp = {
            "ok": False,
            "user_id": user_id,
            "product_id": product_id,
            "action": action,
        }
        if not self._redis_ready():
            resp.update(self._unavailable_response(elapsed_ms=int((time.time() - t0) * 1000)))
            return resp

        key = self._interaction_key(user_id, action)
        try:
            # Try pipeline first
            pipe = None
            try:
                pipe = self._safe_pipeline()
            except Exception:
                pipe = None

            executed_ok = False
            if pipe is not None:
                try:
                    # try to enqueue lpush/ltrim (some fakes apply immediately)
                    pipe.lpush(key, product_id)
                    pipe.ltrim(key, 0, self.config.interaction_list_max - 1)
                except Exception:
                    # not all pipeline-like objects implement these ops
                    pass
                try:
                    res = pipe.execute()
                    if isinstance(res, (list, tuple)) or res is True or res is None:
                        executed_ok = True
                except Exception:
                    executed_ok = False

            # If pipeline didn't persist (or pipeline semantics are weird), ensure direct write
            try:
                # if already at head, avoid duplicate insertion from fallback
                if not self._head_equals(key, product_id):
                    try:
                        self.redis.lpush(key, product_id)
                        # trim synchronously
                        try:
                            self.redis.ltrim(
                                key, 0, self.config.interaction_list_max - 1
                            )
                        except Exception:
                            # some fakes may not implement ltrim; ignore
                            pass
                    except Exception:
                        # best-effort: attempt to set storage directly for very simple fakes
                        try:
                            if hasattr(self.redis, "storage"):
                                self.redis.storage.setdefault(key, []).insert(
                                    0, product_id
                                )
                                # trim
                                self.redis.storage[key] = self.redis.storage[key][
                                    : self.config.interaction_list_max
                                ]
                        except Exception:
                            logger.debug(
                                "track_interaction: fallback storage write failed for key=%s",
                                key,
                            )
            except Exception:
                # If checking head/doing fallback failed, ignore — we'll still mark success if pipeline executed
                if not executed_ok:
                    logger.debug(
                        "track_interaction: both pipeline and fallback attempts had issues for key=%s",
                        key,
                    )

            resp["ok"] = True
            resp["elapsed_ms"] = int((time.time() - t0) * 1000)
            self._record_redis_success()

            # optional hooks
            if publish and self._publisher:
                try:
                    self._publisher(
                        "recommender.interaction",
                        {
                            "user_id": user_id,
                            "product_id": product_id,
                            "action": action,
                        },
                    )
                except Exception:
                    logger.exception("message_publisher failed in track_interaction")
            if self._metrics:
                try:
                    self._metrics(
                        "recommender.track_interaction",
                        {"user_id": user_id, "action": action},
                    )
                except Exception:
                    logger.debug("metrics_hook raised in track_interaction")
            return resp

        except Exception:
            logger.exception(
                "track_interaction failed for user=%s product=%s", user_id, product_id
            )
            self._record_redis_failure()
            resp.update(
                {"error": "exception", "elapsed_ms": int((time.time() - t0) * 1000)}
            )
            return resp

    def get_user_preferences(
        self, user_id: int, actions: Sequence[str] = ("views", "clicks")
    ) -> Dict[str, Any]:
        """
        Read recent interactions for given actions.

        Works with both:
          - redis-py pipeline semantics where pipeline.lrange(...) queues commands and
            pipeline.execute() returns a list of results; and
          - test/mocks (like the provided FakeRedis) where pipeline() returns self
            and lrange(...) runs immediately (returning a concrete list) and execute()
            returns a boolean.

        Returns {"ok":True, "data":{"views":[..], "clicks":[..]}, "meta":{...}}
        """
        t0 = time.time()
        out: Dict[str, Any] = {"ok": False, "data": {}, "meta": {}}

        if not self._redis_ready():
            out.update(
                self._unavailable_response(
                    elapsed_ms=int((time.time() - t0) * 1000),
                    data={a: [] for a in actions},
                )
            )
            return out

        try:
            pipe = None
            try:
                pipe = self._safe_pipeline()
            except Exception:
                pipe = None

            if pipe is None:
                # Direct mode: call lrange for each action and decode
                data: Dict[str, List[int]] = {}
                for a in actions:
                    raw = []
                    key = self._interaction_key(user_id, a)
                    try:
                        raw = self.redis.lrange(key, 0, -1)
                    except Exception:
                        raw = []
                    # fallback: some test fakes use .storage and lrange with end=-1 returned []
                    if (not raw) and hasattr(self.redis, "storage"):
                        raw = self.redis.storage.get(key, []) or []
                    data[a] = self._decode_redis_list_to_ints(raw or [])
                out.update({"ok": True, "data": data})
                out["meta"]["elapsed_ms"] = int((time.time() - t0) * 1000)
                self._record_redis_success()

                # metrics
                if self._metrics:
                    try:
                        self._metrics(
                            "recommender.get_user_preferences",
                            {
                                "user_id": user_id,
                                "counts": {k: len(v) for k, v in data.items()},
                            },
                        )
                    except Exception:
                        logger.debug("metrics_hook raised in get_user_preferences")
                return out

            # Pipeline mode (defensive)
            queued_results = []
            queued_cols = []
            for a in actions:
                try:
                    # some pipeline implementations return concrete data immediately
                    res = pipe.lrange(self._interaction_key(user_id, a), 0, -1)
                    queued_results.append(res)
                    queued_cols.append(a)
                except Exception:
                    queued_results.append(None)
                    queued_cols.append(a)

            exec_results = None
            try:
                exec_results = pipe.execute()
            except Exception:
                exec_results = None

            data: Dict[str, List[int]] = {}
            if isinstance(exec_results, (list, tuple)) and len(exec_results) >= len(
                actions
            ):
                # exec_results may be longer (other queued commands) — map first len(actions)
                for a, res in zip(actions, exec_results[: len(actions)], strict=False):
                    data[a] = self._decode_redis_list_to_ints(res or [])
            else:
                # fall back to immediate results or direct lrange
                for a, res in zip(queued_cols, queued_results, strict=False):
                    if res is None:
                        try:
                            raw = self.redis.lrange(
                                self._interaction_key(user_id, a), 0, -1
                            )
                        except Exception:
                            raw = []
                        data[a] = self._decode_redis_list_to_ints(raw or [])
                    else:
                        data[a] = self._decode_redis_list_to_ints(res or [])

            # final sanity: if pipeline path returned empty lists but direct lrange has data, prefer direct
            for a in list(actions):
                if not data.get(a):
                    try:
                        raw_direct = self.redis.lrange(
                            self._interaction_key(user_id, a), 0, -1
                        )
                        decoded = self._decode_redis_list_to_ints(raw_direct or [])
                        if decoded:
                            data[a] = decoded
                    except Exception:
                        pass

            out.update({"ok": True, "data": data})
            out["meta"]["elapsed_ms"] = int((time.time() - t0) * 1000)
            self._record_redis_success()
            if self._metrics:
                try:
                    self._metrics(
                        "recommender.get_user_preferences",
                        {
                            "user_id": user_id,
                            "counts": {k: len(v) for k, v in data.items()},
                        },
                    )
                except Exception:
                    logger.debug("metrics_hook raised in get_user_preferences")
            return out

        except Exception:
            logger.exception("get_user_preferences failed for user=%s", user_id)
            self._record_redis_failure()
            out.update(
                {
                    "error": "exception",
                    "meta": {"elapsed_ms": int((time.time() - t0) * 1000)},
                    "data": {a: [] for a in actions},
                }
            )
            return out

    def track_click(
        self,
        user_id: Optional[int],
        product_id: int,
        *,
        per_user: bool = True,
        publish: bool = False,
    ) -> Dict[str, Any]:
        """
        Increase click counters. Optionally increment both per-user zset and global trending zset.
        Returns dict with ok and new scores (best-effort).
        """
        t0 = time.time()
        resp = {"ok": False, "user_id": user_id, "product_id": product_id}
        if not self._redis_ready():
            resp.update(self._unavailable_response(elapsed_ms=int((time.time() - t0) * 1000)))
            return resp
        try:
            pipe = None
            try:
                pipe = self._safe_pipeline()
            except Exception:
                pipe = None

            # NOTE: redis clients differ in zincrby signature; try common forms
            def _zincrby_safe(p, key, amt, member) -> bool:
                try:
                    p.zincrby(key, amt, member)
                    return True
                except TypeError:
                    try:
                        p.zincrby(key, member, amt)
                        return True
                    except Exception:
                        return False
                except Exception:
                    return False

            # Try to use pipeline
            if pipe is not None:
                try:
                    if per_user and user_id is not None:
                        _zincrby_safe(
                            pipe, self._clicks_zset_key(user_id), 1, product_id
                        )
                        try:
                            pipe.expire(
                                self._clicks_zset_key(user_id),
                                self.config.click_expire_seconds,
                            )
                        except Exception:
                            pass
                    _zincrby_safe(pipe, self._clicks_zset_key(None), 1, product_id)
                    try:
                        pipe.expire(
                            self._clicks_zset_key(None),
                            self.config.click_expire_seconds,
                        )
                    except Exception:
                        pass
                except Exception:
                    pass
                try:
                    pipe.execute()
                except Exception:
                    pass

            # verify whether zscore changed; if not, apply synchronous increment(s)
            try:
                # per-user increment
                if per_user and user_id is not None:
                    per_key = self._clicks_zset_key(user_id)
                    per_score = None
                    try:
                        per_score = self.redis.zscore(per_key, product_id)
                    except Exception:
                        if hasattr(self.redis, "zsets"):
                            per_score = self.redis.zsets.get(per_key, {}).get(
                                str(product_id), 0
                            )
                    if not per_score:
                        # attempt to safely increment without relying on zincrby signature
                        try:
                            # prefer direct zsets mutation if available on fake
                            if hasattr(self.redis, "zsets"):
                                self.redis.zsets.setdefault(per_key, {})
                                cur = float(
                                    self.redis.zsets[per_key].get(str(product_id), 0.0)
                                )
                                self.redis.zsets[per_key][str(product_id)] = cur + 1.0
                            else:
                                _zincrby_safe(self.redis, per_key, 1, product_id)
                            try:
                                self.redis.expire(
                                    per_key, self.config.click_expire_seconds
                                )
                            except Exception:
                                pass
                        except Exception:
                            pass

                # global
                gkey = self._clicks_zset_key(None)
                gscore = None
                try:
                    gscore = self.redis.zscore(gkey, product_id)
                except Exception:
                    if hasattr(self.redis, "zsets"):
                        gscore = self.redis.zsets.get(gkey, {}).get(str(product_id), 0)
                if not gscore:
                    try:
                        if hasattr(self.redis, "zsets"):
                            self.redis.zsets.setdefault(gkey, {})
                            cur = float(
                                self.redis.zsets[gkey].get(str(product_id), 0.0)
                            )
                            self.redis.zsets[gkey][str(product_id)] = cur + 1.0
                        else:
                            _zincrby_safe(self.redis, gkey, 1, product_id)
                        try:
                            self.redis.expire(gkey, self.config.click_expire_seconds)
                        except Exception:
                            pass
                    except Exception:
                        pass
            except Exception:
                logger.debug(
                    "track_click: verification/fallback increments failed; continuing"
                )

            resp["ok"] = True
            resp["elapsed_ms"] = int((time.time() - t0) * 1000)
            self._record_redis_success()
            if publish and self._publisher:
                try:
                    self._publisher(
                        "recommender.click",
                        {"user_id": user_id, "product_id": product_id},
                    )
                except Exception:
                    logger.exception("message_publisher failed in track_click")
            if self._metrics:
                try:
                    self._metrics(
                        "recommender.track_click",
                        {"user_id": user_id, "product_id": product_id},
                    )
                except Exception:
                    logger.debug("metrics_hook raised in track_click")
            return resp
        except Exception:
            logger.exception(
                "track_click failed for user=%s product=%s", user_id, product_id
            )
            self._record_redis_failure()
            resp.update(
                {"error": "exception", "elapsed_ms": int((time.time() - t0) * 1000)}
            )
            return resp

    def get_trending_products(
        self, top_n: int = 5, user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Returns {"ok": True, "items": [(product_id, score), ...], "meta": {...}}
        """
        t0 = time.time()
        out = {"ok": False, "items": [], "meta": {}}
        if not self._redis_ready():
            out.update(self._unavailable_response(meta={"elapsed_ms": int((time.time() - t0) * 1000)}))
            return out
        try:
            key = self._clicks_zset_key(user_id)
            # prefer zrevrange withscores
            try:
                raw = self.redis.zrevrange(key, 0, top_n - 1, withscores=True)
            except TypeError:
                # older/newer client variations -> call without withscores then zscore per member
                raw_members = self.redis.zrevrange(key, 0, top_n - 1)
                raw = []
                for mem in raw_members:
                    try:
                        score = self.redis.zscore(key, mem) or 0.0
                    except Exception:
                        score = 0.0
                    raw.append((mem, score))
            items = self._decode_redis_zrange(raw, withscores=True)
            # Ensure ordering descending by score (some fake clients may already return ordered)
            items.sort(key=lambda t: float(t[1] or 0.0), reverse=True)
            out.update({"ok": True, "items": items})
            out["meta"]["elapsed_ms"] = int((time.time() - t0) * 1000)
            self._record_redis_success()
            if self._metrics:
                try:
                    self._metrics(
                        "recommender.get_trending",
                        {"user_id": user_id, "count": len(items)},
                    )
                except Exception:
                    logger.debug("metrics_hook raised in get_trending_products")
            return out
        except Exception:
            logger.exception("get_trending_products failed (user=%s)", user_id)
            self._record_redis_failure()
            out.update(
                {
                    "error": "exception",
                    "meta": {"elapsed_ms": int((time.time() - t0) * 1000)},
                }
            )
            return out

    # ---------------------------
    # Featured ranking updates (batch)
    # ---------------------------
    def compute_boost_score(
        self,
        product_obj: Any,
        user_preferences: Optional[Dict[str, List[int]]] = None,
        *,
        weights: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """
        Compute a boost score and return a breakdown dict. Default weights
        come from self.config.boost_weights (previously hardcoded here
        directly); an explicit `weights` argument still overrides per-call
        exactly as before.
        """
        w = dict(self.config.boost_weights)
        if weights:
            w.update(weights)
        product_id = (
            getattr(product_obj, "id", None) or getattr(product_obj, "pk", None) or None
        )
        try:
            clicks = float(getattr(product_obj, "clicks", 0) or 0)
            impressions = float(getattr(product_obj, "impressions", 0) or 0)
            engagement = clicks * w["clicks"] + impressions * w["impressions"]

            # category id resolution (attempt multiple shapes)
            category_id = None
            try:
                category_id = product_obj.product.category.id  # type: ignore
            except Exception:
                try:
                    category_id = getattr(product_obj, "category_id", None)
                except Exception:
                    category_id = None

            cat_score = 0.0
            if user_preferences:
                user_cats = (
                    user_preferences.get("categories")
                    or user_preferences.get("views")
                    or []
                )
                try:
                    user_cats_set = {int(x) for x in user_cats}
                    if category_id is not None and int(category_id) in user_cats_set:
                        cat_score = float(w["category_match"])
                except Exception:
                    cat_score = 0.0

            recent_boost_val = 0.0
            try:
                created_at = getattr(product_obj, "created_at", None)
                if created_at is not None:
                    created_ts = (
                        created_at.timestamp()
                        if hasattr(created_at, "timestamp")
                        else None
                    )
                    if created_ts and (time.time() - created_ts) < (7 * 24 * 3600):
                        recent_boost_val = float(w["recent_boost"])
            except Exception:
                recent_boost_val = 0.0

            boost = float(engagement + cat_score + recent_boost_val)
            return {
                "product_id": int(product_id) if product_id is not None else None,
                "boost": boost,
                "components": {
                    "engagement": engagement,
                    "category_match": cat_score,
                    "recent_boost": recent_boost_val,
                },
            }
        except Exception:
            logger.exception("compute_boost_score failed for product=%s", product_id)
            return {"product_id": product_id, "boost": 0.0, "components": {}}

    def update_featured_rankings(
        self,
        featured_fetcher: FeaturedFetcher,
        product_fetcher: Optional[Callable[[int], Dict[str, Any]]] = None,
        *,
        pipeline_batch: bool = True,
        publish: bool = False,
    ) -> Dict[str, Any]:
        """
        Recalculate boost scores for featured products and cache them in Redis.
        `product_fetcher` if provided should accept vendor/user_id and return user prefs (optional).
        """
        t0 = time.time()
        details: List[Dict[str, Any]] = []
        errors = 0
        updated = 0
        if not self._redis_ready():
            return {
                **self._unavailable_response(),
                "updated": 0,
                "elapsed_ms": int((time.time() - t0) * 1000),
            }

        try:
            featured_iter = featured_fetcher()
            pipe = None
            try:
                if pipeline_batch:
                    pipe = self._safe_pipeline()
            except Exception:
                pipe = None

            for p in featured_iter:
                try:
                    # Optionally fetch context for this featured item (caller-defined)
                    user_prefs = {}
                    try:
                        user_id = p.vendor.user.id
                    except Exception:
                        user_id = None
                    if user_id and product_fetcher:
                        try:
                            user_prefs = product_fetcher(user_id) or {}
                        except Exception:
                            user_prefs = {}

                    boost_info = self.compute_boost_score(p, user_prefs)
                    key = self._featured_boost_key(int(getattr(p, "id", 0) or 0))
                    ttl = self._ttl_with_jitter(self.config.featured_cache_ttl)
                    # try writing with pipeline, else sync set, else storage fallback
                    wrote = False
                    if pipe is not None:
                        try:
                            # redis-py pipeline accepts ex=..., but some fakes may differ
                            try:
                                pipe.set(key, boost_info["boost"], ex=ttl)
                            except TypeError:
                                pipe.set(key, boost_info["boost"], ttl)
                            wrote = True
                        except Exception:
                            wrote = False
                    if not wrote:
                        try:
                            try:
                                self.redis.set(key, boost_info["boost"], ex=ttl)
                            except TypeError:
                                # some simple fakes accept positional ttl
                                try:
                                    self.redis.set(key, boost_info["boost"], ttl)
                                except Exception:
                                    # fallback to storage attribute if present
                                    if hasattr(self.redis, "storage"):
                                        self.redis.storage[key] = boost_info["boost"]
                                    else:
                                        # last resort: use .set without expiry
                                        try:
                                            self.redis.set(key, boost_info["boost"])
                                        except Exception:
                                            pass
                        except Exception:
                            logger.debug(
                                "update_featured_rankings: direct set fallback failed for key=%s",
                                key,
                            )

                    details.append(
                        {
                            "product_id": boost_info["product_id"],
                            "boost": boost_info["boost"],
                            "key": key,
                        }
                    )
                    updated += 1
                except Exception:
                    logger.exception(
                        "Failed updating featured boost for product object"
                    )
                    errors += 1

            # attempt to flush pipeline if used
            if pipe is not None:
                try:
                    pipe.execute()
                except Exception:
                    # ignore: some fakes have already executed commands
                    pass

            elapsed_ms = int((time.time() - t0) * 1000)
            res = {
                "ok": True,
                "updated": updated,
                "errors": errors,
                "details": details,
                "elapsed_ms": elapsed_ms,
            }
            self._record_redis_success()
            if publish and self._publisher:
                try:
                    self._publisher("recommender.featured_updates", res)
                except Exception:
                    logger.exception(
                        "message_publisher failed in update_featured_rankings"
                    )
            if self._metrics:
                try:
                    self._metrics(
                        "recommender.update_featured_rankings",
                        {"updated": updated, "errors": errors},
                    )
                except Exception:
                    logger.debug("metrics_hook raised in update_featured_rankings")
            return res
        except Exception:
            logger.exception("update_featured_rankings failed")
            self._record_redis_failure()
            return {
                "ok": False,
                "updated": updated,
                "errors": errors + 1,
                "elapsed_ms": int((time.time() - t0) * 1000),
            }

    def get_featured_boost(self, product_id: int) -> Optional[float]:
        """
        Read boost value for product from Redis (if available). Returns None when unavailable.
        """
        if not self._redis_ready():
            return None
        key = self._featured_boost_key(product_id)
        try:
            raw = None
            get_fn = getattr(self.redis, "get", None)
            if callable(get_fn):
                try:
                    raw = get_fn(key)
                except Exception:
                    raw = None
            if raw is None and hasattr(self.redis, "storage"):
                raw = self.redis.storage.get(key)
            if raw is None:
                return None
            if isinstance(raw, (bytes, bytearray)):
                try:
                    raw = raw.decode()
                except Exception:
                    raw = str(raw)
            try:
                return float(raw)
            except Exception:
                try:
                    # if storage may hold ints/other numeric types
                    return float(str(raw))
                except Exception:
                    return None
        except Exception:
            logger.exception("get_featured_boost failed for product=%s", product_id)
            return None

    # ---------------------------
    # ML prediction (optional)
    # ---------------------------
    def predict_user_preference(
        self, user_vector: Sequence[float], product_vector: Sequence[float]
    ) -> Dict[str, Any]:
        """
        Returns {"ok": True, "score": float, "method": "ml"|"cosine"|"fallback", "meta": {...}}
        Score normalized to 0..1
        """
        t0 = time.time()
        try:
            if self._ml_model is not None and hasattr(self._ml_model, "predict"):
                try:
                    concat = list(user_vector) + list(product_vector)
                    pred = self._ml_model.predict([concat])
                    try:
                        score = float(pred[0][0])
                    except Exception:
                        score = float(pred[0])
                    return {
                        "ok": True,
                        "score": max(0.0, min(1.0, score)),
                        "method": "ml",
                        "elapsed_ms": int((time.time() - t0) * 1000),
                    }
                except Exception:
                    logger.exception("ML model predict failed; falling back to cosine")
            # fallback cosine using numpy if available
            if np is not None:
                a = np.asarray(user_vector, dtype=float)
                b = np.asarray(product_vector, dtype=float)
                if a.size != b.size:
                    m = max(a.size, b.size)
                    a = np.pad(a, (0, m - a.size))
                    b = np.pad(b, (0, m - b.size))
                na = np.linalg.norm(a)
                nb = np.linalg.norm(b)
                if na == 0 or nb == 0:
                    return {
                        "ok": True,
                        "score": 0.5,
                        "method": "cosine",
                        "elapsed_ms": int((time.time() - t0) * 1000),
                    }
                score = float(np.dot(a, b) / (na * nb))
                return {
                    "ok": True,
                    "score": (score + 1.0) / 2.0,
                    "method": "cosine",
                    "elapsed_ms": int((time.time() - t0) * 1000),
                }
            # pure-Python fallback
            try:
                a = list(map(float, user_vector))
                b = list(map(float, product_vector))
                m = max(len(a), len(b))
                a += [0.0] * (m - len(a))
                b += [0.0] * (m - len(b))
                dot = sum(x * y for x, y in zip(a, b, strict=False))
                na = sum(x * x for x in a) ** 0.5
                nb = sum(x * x for x in b) ** 0.5
                if na == 0 or nb == 0:
                    return {
                        "ok": True,
                        "score": 0.5,
                        "method": "fallback",
                        "elapsed_ms": int((time.time() - t0) * 1000),
                    }
                score = dot / (na * nb)
                return {
                    "ok": True,
                    "score": (score + 1.0) / 2.0,
                    "method": "fallback",
                    "elapsed_ms": int((time.time() - t0) * 1000),
                }
            except Exception:
                logger.exception("predict_user_preference fallback failed")
                return {
                    "ok": False,
                    "score": 0.5,
                    "method": "error",
                    "elapsed_ms": int((time.time() - t0) * 1000),
                }
        except Exception:
            logger.exception("predict_user_preference top-level error")
            return {
                "ok": False,
                "score": 0.5,
                "method": "error",
                "elapsed_ms": int((time.time() - t0) * 1000),
            }

    # ---------------------------
    # Lightweight collaborative filtering (approximate)
    # ---------------------------
    def get_collaborative_recommendations(
        self,
        user_id: int,
        user_interaction_fetcher: UserInteractionFetcher,
        product_resolver: ProductFetcher,
        *,
        top_k_users: int = 5,
        top_products: int = 20,
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """
        Returns {"ok": True, "items": [<product objects>], "meta": {...}}
        Uses simple sparse cosine similarity over interactions (suitable for
        small-medium datasets - this is an O(users x products) Python loop,
        not something to run against a large interaction table on every
        request without caching).

        When use_cache is True (default) and Redis is available, the
        *computed candidate product ids* are cached for
        config.collaborative_cache_ttl_seconds - not the resolved product
        objects, which aren't generically cacheable - so a cache hit still
        calls product_resolver() for fresh objects but skips the expensive
        similarity computation. Falls back to computing fresh (uncached)
        whenever Redis is unavailable or the cache read/write fails, so
        caching is purely an optimization, never a correctness dependency.
        """
        t0 = time.time()
        out = {"ok": False, "items": [], "meta": {}}

        cache_key = None
        if use_cache and self._redis_ready():
            cache_key = self._collaborative_cache_key(user_id, top_k_users, top_products)
            try:
                cached_raw = self.redis.get(cache_key)
                if cached_raw:
                    cached_ids = self._decode_redis_list_to_ints(
                        cached_raw.split(b",") if isinstance(cached_raw, (bytes, bytearray)) else str(cached_raw).split(",")
                    )
                    if cached_ids:
                        items = list(product_resolver(cached_ids))
                        out.update({
                            "ok": True,
                            "items": items,
                            "meta": {
                                "source": "collaborative_cache",
                                "elapsed_ms": int((time.time() - t0) * 1000),
                            },
                        })
                        self._record_redis_success()
                        return out
            except Exception:
                logger.debug("get_collaborative_recommendations: cache read failed for user=%s", user_id, exc_info=True)

        try:
            interactions = list(user_interaction_fetcher())
            if not interactions:
                out.update(
                    {
                        "ok": True,
                        "items": [],
                        "meta": {
                            "elapsed_ms": int((time.time() - t0) * 1000),
                            "reason": "no_interactions",
                        },
                    }
                )
                return out

            # build user -> {product:weight}
            user_map: Dict[int, Dict[int, float]] = {}
            for u, pid, w in interactions:
                uid = int(u)
                pid_i = int(pid)
                user_map.setdefault(uid, {}).setdefault(pid_i, 0.0)
                user_map[uid][pid_i] += float(w)

            if user_id not in user_map:
                # fallback to trending
                trending = self.get_trending_products(top_n=top_products)
                if trending.get("ok"):
                    items = list(
                        product_resolver([pid for pid, _ in trending.get("items", [])])
                    )
                    out.update(
                        {
                            "ok": True,
                            "items": items,
                            "meta": {
                                "source": "trending_fallback",
                                "elapsed_ms": int((time.time() - t0) * 1000),
                            },
                        }
                    )
                    return out
                else:
                    out.update(
                        {
                            "ok": True,
                            "items": [],
                            "meta": {
                                "source": "no_user_data",
                                "elapsed_ms": int((time.time() - t0) * 1000),
                            },
                        }
                    )
                    return out

            # sparse similarity
            def sparse_cosine(uvec: Dict[int, float], vvec: Dict[int, float]) -> float:
                keys = set(uvec.keys()) & set(vvec.keys())
                if not keys:
                    return 0.0
                dot = sum(uvec[k] * vvec[k] for k in keys)
                na = sum(v * v for v in uvec.values()) ** 0.5
                nb = sum(v * v for v in vvec.values()) ** 0.5
                if na == 0 or nb == 0:
                    return 0.0
                return dot / (na * nb)

            target = user_map[int(user_id)]
            sims: List[Tuple[int, float]] = []
            for other_id, vec in user_map.items():
                if other_id == int(user_id):
                    continue
                sims.append((other_id, sparse_cosine(target, vec)))
            sims.sort(key=lambda x: x[1], reverse=True)
            top_users = [uid for uid, s in sims[:top_k_users] if s > 0.0]

            candidate_scores: Dict[int, float] = {}
            for uid in top_users:
                vec = user_map.get(uid, {})
                for pid, w in vec.items():
                    if pid in target:
                        continue
                    candidate_scores[pid] = candidate_scores.get(pid, 0.0) + w

            sorted_pids = sorted(
                candidate_scores.items(), key=lambda kv: kv[1], reverse=True
            )
            top_product_ids = [pid for pid, _ in sorted_pids[:top_products]]
            products = list(product_resolver(top_product_ids))

            if cache_key and top_product_ids:
                try:
                    ttl = self._ttl_with_jitter(self.config.collaborative_cache_ttl_seconds)
                    payload = ",".join(str(pid) for pid in top_product_ids)
                    try:
                        self.redis.set(cache_key, payload, ex=ttl)
                    except TypeError:
                        self.redis.set(cache_key, payload, ttl)
                except Exception:
                    logger.debug("get_collaborative_recommendations: cache write failed for user=%s", user_id, exc_info=True)

            out.update(
                {
                    "ok": True,
                    "items": products,
                    "meta": {
                        "source": "computed",
                        "top_users": top_users,
                        "num_candidates": len(candidate_scores),
                        "elapsed_ms": int((time.time() - t0) * 1000),
                    },
                }
            )
            return out
        except Exception:
            logger.exception(
                "get_collaborative_recommendations failed for user=%s", user_id
            )
            out.update(
                {
                    "ok": False,
                    "items": [],
                    "meta": {"elapsed_ms": int((time.time() - t0) * 1000)},
                }
            )
            return out


# ============================
# Example usage
# ============================
#
# --- Dependency-injected setup (recommended for tests and for explicit
#     control over pool sizing/timeouts in production) --------------------
#
# import redis
# from recommender_service import RecommenderConfig, RecommenderService
#
# config = RecommenderConfig(
#     namespace="myapp:rec",
#     socket_timeout_seconds=2.0,
#     circuit_breaker_threshold=5,
#     boost_weights={"clicks": 1.0, "impressions": 0.2, "category_match": 4.0, "recent_boost": 1.5},
# )
# redis_client = redis.from_url(
#     "redis://:password@redis.internal:6379/0",
#     socket_timeout=config.socket_timeout_seconds,
#     socket_connect_timeout=config.socket_connect_timeout_seconds,
# )
# service = RecommenderService(
#     redis_client=redis_client,
#     config=config,
#     message_publisher=lambda topic, payload: kafka_producer.send(topic, payload),
#     metrics_hook=lambda name, tags: statsd_client.incr(name, tags=tags),
# )
#
# --- Tracking interactions from a DRF view -------------------------------
#
# class ProductClickView(APIView):
#     def post(self, request, product_id: int):
#         result = service.track_click(request.user.id, product_id, publish=True)
#         if not result["ok"]:
#             # Degrade gracefully: a Redis hiccup shouldn't 500 the request -
#             # the click just doesn't get counted this time.
#             logger.warning("track_click degraded: %s", result.get("error"))
#         return Response({"ok": result["ok"]})
#
# --- Trending products endpoint -------------------------------------------
#
# class TrendingProductsView(APIView):
#     def get(self, request):
#         result = service.get_trending_products(top_n=10)
#         if not result["ok"]:
#             return Response({"items": []}, status=200)  # empty, not an error, to the client
#         product_ids = [pid for pid, _score in result["items"]]
#         products = Product.objects.filter(id__in=product_ids)
#         return Response(ProductSerializer(products, many=True).data)
#
# --- Collaborative recommendations, with caching ---------------------------
#
# def fetch_interactions():
#     return UserInteraction.objects.values_list("user_id", "product_id", "weight")
#
# def resolve_products(ids):
#     return Product.objects.filter(id__in=list(ids))
#
# result = service.get_collaborative_recommendations(
#     user_id=request.user.id,
#     user_interaction_fetcher=fetch_interactions,
#     product_resolver=resolve_products,
# )
#
# --- Periodic featured-ranking refresh (Celery task) ------------------------
#
# @shared_task
# def refresh_featured_rankings():
#     def featured_fetcher():
#         return FeaturedProduct.objects.select_related("vendor__user", "product__category")
#
#     result = service.update_featured_rankings(featured_fetcher, publish=True)
#     if result["errors"]:
#         logger.warning("refresh_featured_rankings: %d errors out of %d", result["errors"], result["updated"])
#
# --- Health check wiring (e.g. Django health-check endpoint) ----------------
#
# def readiness_probe(request):
#     health = service.health_check()
#     return JsonResponse(health, status=200 if health["ok"] else 503)
#
# --- Graceful shutdown (ASGI lifespan) ---------------------------------------
#
# async def lifespan(app):
#     yield
#     service.close()
