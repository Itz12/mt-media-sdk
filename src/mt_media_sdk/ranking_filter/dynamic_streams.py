# dynamic_streams.py
from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import sys
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Canonical home for these two type aliases is recommender_service.py (it has
# no cross-file dependencies of its own, so it's the natural foundation);
# imported defensively so this module still works standalone (e.g. isolated
# unit tests, or if the package layout changes) rather than hard-failing.
try:
    from .recommender_service import MessagePublisher, MetricsHook  # type: ignore
except ImportError:
    try:
        from recommender_service import MessagePublisher, MetricsHook  # type: ignore
    except ImportError:
        MessagePublisher = Callable[[str, Dict[str, Any]], None]
        MetricsHook = Callable[[str, Dict[str, Any]], None]


# ---------------------------------------------------------------------------
# Shared cache infrastructure
# ---------------------------------------------------------------------------
# This block (SimpleMemoryCache + Django-cache resolution) used to be
# copy-pasted near-identically into dynamic_featured.py too. Centralizing it
# here - dynamic_featured.py imports it rather than redefining it - means a
# fix here (like the settings.configured change below) automatically applies
# to both instead of needing to be made twice and risking drift.
class _SimpleMemoryCache:
    """In-memory cache fallback, used when Django's cache framework isn't
    configured (e.g. importing this module in isolation for unit tests).
    Deliberately minimal - just enough surface for this module's own usage
    and for tests to swap in a mock via `unittest.mock.patch`."""

    def __init__(self):
        self._store: Dict[str, Any] = {}

    def get(self, key: str, default: Any = None) -> Any:
        return self._store.get(key, default)

    def set(self, key: str, value: Any, timeout: Optional[int] = None) -> None:
        # tests often pass timeout positionally; preserve signature.
        self._store[key] = value

    def delete(self, key: str) -> None:
        if key in self._store:
            del self._store[key]


def _django_cache_available() -> bool:
    """
    Whether Django's cache framework can be used right now. Checks
    `settings.configured` rather than sniffing the DJANGO_SETTINGS_MODULE
    env var: that var can be set before configuration actually finishes, or
    left unset entirely when a caller uses `settings.configure(...)`
    programmatically (common in some test runners/scripts), so it's not a
    reliable signal either way. `settings.configured` is the check Django
    itself provides for exactly this "is it safe to touch settings yet"
    question, and - unlike accessing an actual setting - never raises
    ImproperlyConfigured on its own.
    """
    try:
        from django.conf import settings as _django_settings  # type: ignore
        return bool(_django_settings.configured)
    except Exception:
        return False


def _resolve_cache_backend(alias: Optional[str] = None):
    """Resolve the cache backend: Django's cache framework (a specific
    alias, configurable via the RANKING_CACHE_ALIAS env var, default
    "default") when Django is actually configured, otherwise an in-memory
    fallback so this module stays importable/usable standalone."""
    resolved_alias = alias or os.environ.get("RANKING_CACHE_ALIAS", "default")
    if _django_cache_available():
        try:
            from django.core.cache import caches  # type: ignore
            return caches[resolved_alias]
        except Exception:
            logger.debug(
                "Django cache backend '%s' unavailable; using in-memory fallback.",
                resolved_alias, exc_info=True,
            )
    return _SimpleMemoryCache()


# Module-level singleton, resolved once at import time (matching Django's own
# convention of settings being read once at process start) - kept as a
# simple, monkeypatchable module attribute specifically so existing tests
# using `unittest.mock.patch("dynamic_streams.cache", ...)` keep working
# unchanged.
cache = _resolve_cache_backend()

# Use Django's timezone.now() when Django is actually configured; otherwise
# fall back to timezone-aware UTC. Local import so importing this module
# doesn't require Django to be configured.
try:
    from django.utils.timezone import now as django_now  # type: ignore
except Exception:
    django_now = None

# Register this module under its bare name too, so `patch("dynamic_streams.cache")`
# works regardless of the full dotted import path (e.g.
# `media.ranking_filter.dynamic_streams`) actually used to import it. Wrapped
# defensively since sys.modules[__name__] should always succeed but there's
# no reason to let a defensive-programming nicety ever raise on import.
try:
    sys.modules.setdefault("dynamic_streams", sys.modules[__name__])
except Exception:
    logger.debug("Could not register legacy module alias 'dynamic_streams'.", exc_info=True)


def safe_now() -> datetime:
    """
    Return a timezone-aware 'now' without triggering Django's
    ImproperlyConfigured. Uses django_now() when Django is actually
    configured (checked the same robust way as the cache backend above);
    otherwise always returns timezone-aware UTC now.
    """
    if django_now and _django_cache_available():
        try:
            return django_now()
        except Exception:
            # Defensive: even with settings.configured True, calling
            # django_now() could theoretically still raise in an unusual
            # setup (e.g. USE_TZ misconfigured) - fall back rather than
            # propagate.
            pass
    return datetime.now(timezone.utc)


# Defaults
PREF_CACHE_TTL_SECONDS = 60 * 5
RESULT_CACHE_TTL_SECONDS = 30
DEFAULT_TOP_STREAMS = 5


@dataclass
class StreamPreferenceSnapshot:
    recent_categories: List[int]
    watched_hosts: List[int]


SerializerCallable = Callable[[Any], Dict[str, Any]]


# ---------------------------------------------------------------------------
# Shared ranking-mixin infrastructure
# ---------------------------------------------------------------------------
class RankingCacheMixin:
    """
    Shared infrastructure for ranking/filtering mixins
    (DynamicStreamFilterMixin here, DynamicFeaturedMixin in
    dynamic_featured.py): candidate-window sizing (with an upper bound -
    the original code had none, so an unusually large `top_n` turned
    directly into an unusually large, unbounded query), TTL jitter, a
    shared "does this look like a Django QuerySet" check, and a generic
    signature-hashing helper for building new cache keys.

    Deliberately does NOT touch the pre-existing per-mixin cache-key
    methods (_pref_cache_key, _result_cache_key, _qs_signature and their
    dynamic_featured.py equivalents) - those compute specific hash formats
    that may already have cached data live in production under them, and
    unifying their exact byte-for-byte output isn't worth the risk for the
    marginal DRY benefit. What's unified here is genuinely new/shared
    capability, not a behavior-preserving extraction of existing logic.
    """

    #: Upper bound on how many candidate rows a ranking query will fetch,
    #: regardless of top_n. Enforced centrally so neither mixin needs to
    #: remember to bound it independently.
    MAX_CANDIDATE_WINDOW = 500

    @classmethod
    def candidate_window(cls, top_n: int, *, multiplier: int = 5, minimum: int = 50) -> int:
        """How many candidate rows to fetch/evaluate before sorting and
        capping to top_n. Bounded by MAX_CANDIDATE_WINDOW so a caller (or a
        bug) passing a very large top_n can't turn into an effectively
        unbounded query."""
        window = max(int(top_n) * multiplier, minimum)
        return min(window, cls.MAX_CANDIDATE_WINDOW)

    @staticmethod
    def ttl_with_jitter(base_ttl: int, *, jitter_ratio: float = 0.1) -> int:
        """Add up to +/- jitter_ratio to base_ttl so many cache keys set
        around the same time (e.g. a burst of requests right after a
        deploy or cache flush) don't all expire in the same instant and
        cause a recomputation stampede. jitter_ratio is clamped to
        [0, 0.5] - larger values would make the TTL unpredictably close to
        (or past) zero."""
        ratio = max(0.0, min(0.5, jitter_ratio))
        if ratio <= 0 or base_ttl <= 0:
            return base_ttl
        jitter = base_ttl * ratio
        return max(1, int(base_ttl + random.uniform(-jitter, jitter)))  # noqa: S311

    @staticmethod
    def looks_like_queryset(obj: Any) -> bool:
        """Heuristic: "does this look like a Django QuerySet (supports
        .filter())  or a plain iterable/list (as tests commonly pass
        instead)". Both ranking mixins use this exact check rather than
        each writing their own hasattr probe."""
        return hasattr(obj, "filter") and callable(getattr(obj, "filter", None))

    @staticmethod
    def hash_signature(*parts: Any) -> str:
        """Short, stable signature for NEW cache keys, built from an
        arbitrary number of parts (strings used as-is, everything else
        JSON-serialized with sort_keys for determinism). Available for new
        cache-key construction; existing per-mixin cache-key methods keep
        their original hashing exactly as-is (see class docstring)."""
        raw = "|".join(
            p if isinstance(p, str) else json.dumps(p, sort_keys=True, default=str)
            for p in parts
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:12]


class DynamicStreamFilterMixin(RankingCacheMixin):
    """
    Mixin that ranks live streams for a user and returns structured results + meta.
    Works with real ORM QuerySets or simple lists / mocks used in unit tests.

    See the "Example usage" section at the bottom of this module for a
    complete DRF view, a preference-update signal handler, and a cache-
    warming management command.
    """

    BOOST_WEIGHTS = {
        "category_match": 3.0,
        "recent_stream": 2.0,
        "age_compatibility": 2.0,
        "watch_history": 4.0,
        "viewer_count": 0.01,
    }

    DEFAULT_TOP_STREAMS = DEFAULT_TOP_STREAMS

    def _pref_cache_key(self, user_id: int) -> str:
        return f"user:{user_id}:stream_prefs_v2"

    def _result_cache_key(
        self,
        user_id: Union[int, str],
        qs_signature: str,
        prefs_signature: str,
        top_n: int,
    ) -> str:
        sig = hashlib.sha256(
            f"{qs_signature}|{prefs_signature}|{top_n}".encode()
        ).hexdigest()[:12]
        return f"user:{user_id}:top_streams:{sig}"

    # -------------------------
    # Preference helpers
    # -------------------------
    def get_stream_preferences(self, user) -> StreamPreferenceSnapshot:
        try:
            if user is None or getattr(user, "id", None) is None:
                return StreamPreferenceSnapshot(recent_categories=[], watched_hosts=[])
            key = self._pref_cache_key(user.id)
            data = cache.get(key)
            if isinstance(data, Mapping):
                return StreamPreferenceSnapshot(
                    recent_categories=list(data.get("recent_categories") or []),
                    watched_hosts=list(data.get("watched_hosts") or []),
                )
        except Exception:
            logger.exception(
                "Failed to load stream preferences from cache for user=%s",
                getattr(user, "id", "<unknown>"),
            )
        return StreamPreferenceSnapshot(recent_categories=[], watched_hosts=[])

    def clear_stream_preferences(self, user) -> None:
        try:
            if user is None or getattr(user, "id", None) is None:
                return
            cache.delete(self._pref_cache_key(user.id))
        except Exception:
            logger.exception(
                "Failed to clear stream preferences for user=%s",
                getattr(user, "id", "<unknown>"),
            )

    def update_stream_preferences_for_user(
        self,
        user,
        *,
        add_category: Optional[int] = None,
        add_host: Optional[int] = None,
        max_categories: int = 10,
        max_hosts: int = 50,
        ttl_seconds: int = PREF_CACHE_TTL_SECONDS,
    ):
        if user is None or getattr(user, "id", None) is None:
            logger.debug("update_stream_preferences_for_user called with missing user")
            return
        try:
            key = self._pref_cache_key(user.id)
            data = cache.get(key) or {"recent_categories": [], "watched_hosts": []}
            if add_category is not None:
                lst = data.get("recent_categories", [])
                if add_category in lst:
                    lst.remove(add_category)
                lst.insert(0, add_category)
                data["recent_categories"] = lst[:max_categories]
            if add_host is not None:
                hosts = data.get("watched_hosts", [])
                if add_host in hosts:
                    hosts.remove(add_host)
                hosts.insert(0, add_host)
                data["watched_hosts"] = hosts[:max_hosts]
            cache.set(key, data, int(ttl_seconds))
        except Exception:
            logger.exception(
                "Failed to update stream preferences for user %s",
                getattr(user, "id", "<unknown>"),
            )

    # -------------------------
    # Serializer (override in subclass)
    # -------------------------
    def serialize_stream(self, stream_obj: Any) -> Dict[str, Any]:
        created = getattr(stream_obj, "created_at", None)
        return {
            "id": getattr(stream_obj, "id", None),
            "category": getattr(stream_obj, "category", None),
            "host_id": getattr(stream_obj, "host_id", None),
            "viewer_count": float(getattr(stream_obj, "viewer_count", 0) or 0),
            "created_at": (
                created.isoformat() if getattr(created, "isoformat", None) else None
            ),
            "boost": float(getattr(stream_obj, "boost", 0.0) or 0.0),
        }

    # -------------------------
    # DB expression builder (lazy import)
    # -------------------------
    def _build_boost_expression(
        self, prefs: StreamPreferenceSnapshot, user_profile: Any
    ):
        """
        Build a Django ORM expression (Case/When/ExpressionWrapper) for boost annotation.
        If the ORM isn't available, return (None, []) to signal fallback to Python computation.
        """
        try:
            from django.db.models import (
                Case,
                When,
                Value,
                FloatField,
                F,
                ExpressionWrapper,
            )  # local import
            from django.db.models.functions import Coalesce  # type: ignore
        except Exception:
            return None, []

        parts = []
        components: List[str] = []

        if prefs.recent_categories:
            parts.append(
                Case(
                    When(
                        category__in=prefs.recent_categories,
                        then=Value(float(self.BOOST_WEIGHTS["category_match"])),
                    ),
                    default=Value(0.0),
                    output_field=FloatField(),
                )
            )
            components.append("category_match")

        # safe cutoff using safe_now()
        recent_cutoff = safe_now() - timedelta(hours=1)
        parts.append(
            Case(
                When(
                    created_at__gte=recent_cutoff,
                    then=Value(float(self.BOOST_WEIGHTS["recent_stream"])),
                ),
                default=Value(0.0),
                output_field=FloatField(),
            )
        )
        components.append("recent_stream")

        if getattr(user_profile, "age", None) is not None:
            try:
                age_val = int(user_profile.age)
                parts.append(
                    Case(
                        When(
                            age_limit__lte=age_val,
                            then=Value(float(self.BOOST_WEIGHTS["age_compatibility"])),
                        ),
                        default=Value(0.0),
                        output_field=FloatField(),
                    )
                )
                components.append("age_compatibility")
            except Exception:
                logger.debug("User age invalid; skipping age_compatibility boost")

        if prefs.watched_hosts:
            parts.append(
                Case(
                    When(
                        host_id__in=prefs.watched_hosts,
                        then=Value(float(self.BOOST_WEIGHTS["watch_history"])),
                    ),
                    default=Value(0.0),
                    output_field=FloatField(),
                )
            )
            components.append("watch_history")

        try:
            viewer_expr = ExpressionWrapper(
                Coalesce(F("viewer_count"), Value(0.0))
                * Value(float(self.BOOST_WEIGHTS["viewer_count"])),
                output_field=FloatField(),
            )
            parts.append(viewer_expr)
            components.append("viewer_count")
        except Exception:
            logger.debug(
                "viewer_count expression unavailable; skipping viewer_count DB contribution"
            )

        if not parts:
            from django.db.models import Value, FloatField  # local import

            return Value(0.0, output_field=FloatField()), components

        total = parts[0]
        for p in parts[1:]:
            total = total + p
        return total, components

    # -------------------------
    # In-Python boost computation (fallback)
    # -------------------------
    def _compute_boost_in_python(
        self, obj: Any, prefs: StreamPreferenceSnapshot, user_profile: Any
    ) -> Tuple[float, List[str]]:
        score = 0.0
        components_hit: List[str] = []

        try:
            if (
                prefs.recent_categories
                and getattr(obj, "category", None) in prefs.recent_categories
            ):
                score += float(self.BOOST_WEIGHTS["category_match"])
                components_hit.append("category_match")
        except Exception:
            pass

        try:
            cutoff = safe_now() - timedelta(hours=1)
            created_at = getattr(obj, "created_at", None)
            if created_at and created_at >= cutoff:
                score += float(self.BOOST_WEIGHTS["recent_stream"])
                components_hit.append("recent_stream")
        except Exception:
            pass

        try:
            if getattr(user_profile, "age", None) is not None:
                age_val = int(user_profile.age)
                if getattr(obj, "age_limit", 0) <= age_val:
                    score += float(self.BOOST_WEIGHTS["age_compatibility"])
                    components_hit.append("age_compatibility")
        except Exception:
            pass

        try:
            if (
                prefs.watched_hosts
                and getattr(obj, "host_id", None) in prefs.watched_hosts
            ):
                score += float(self.BOOST_WEIGHTS["watch_history"])
                components_hit.append("watch_history")
        except Exception:
            pass

        try:
            vc = float(getattr(obj, "viewer_count", 0) or 0)
            score += vc * float(self.BOOST_WEIGHTS["viewer_count"])
            components_hit.append("viewer_count")
        except Exception:
            pass

        return float(score), components_hit

    # -------------------------
    # Public API: get_filtered_streams
    # -------------------------
    def _qs_signature(self, queryset) -> str:
        try:
            q = str(queryset.query)
        except Exception:
            q = repr(queryset)
        return hashlib.sha256(q.encode()).hexdigest()[:12]

    def get_filtered_streams(
        self,
        user,
        queryset,
        *,
        top_n: Optional[int] = None,
        require_profile: bool = True,
        return_objects: bool = False,
        serializer: Optional[SerializerCallable] = None,
        cache_ttl: int = RESULT_CACHE_TTL_SECONDS,
        force_refresh: bool = False,
        message_publisher: Optional[MessagePublisher] = None,
        metrics_hook: Optional[MetricsHook] = None,
    ) -> Tuple[Optional[List[Any]], Dict[str, Any]]:
        """
        Annotate/rank live streams and return (results, meta).
        Works with Django QuerySets, mocks, or plain iterables.
        """
        t0 = time.perf_counter()
        top_n = int(top_n or self.DEFAULT_TOP_STREAMS)
        serializer = serializer or self.serialize_stream

        # default meta (ensures 'cache_hit' always exists)
        meta: Dict[str, Any] = {"cache_hit": False, "cache_key": None, "elapsed_ms": 0}

        user_profile = getattr(user, "profile", None)
        if require_profile and not user_profile:
            meta["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
            return [], {
                "error": "user_profile_missing",
                "status": 400,
                "elapsed_ms": meta["elapsed_ms"],
                "cache_hit": False,
            }

        prefs = self.get_stream_preferences(user)
        prefs_sig = hashlib.sha256(
            json.dumps(
                {
                    "recent_categories": list(prefs.recent_categories or []),
                    "watched_hosts": list(prefs.watched_hosts or []),
                },
                sort_keys=True,
                default=str,
            ).encode()
        ).hexdigest()[:12]
        qs_sig = self._qs_signature(queryset)
        cache_key = self._result_cache_key(
            getattr(user, "id", "anon"), qs_sig, prefs_sig, top_n
        )

        # cache hit (skip when force_refresh True)
        if not force_refresh:
            try:
                cached = cache.get(cache_key)
                if cached is not None:
                    results = cached.get("results", [])
                    meta = dict(cached.get("meta", {}))
                    meta.update(
                        {
                            "cache_hit": True,
                            "cache_key": cache_key,
                            "elapsed_ms": int((time.perf_counter() - t0) * 1000),
                        }
                    )
                    # publish + metrics (non-fatal)
                    if message_publisher:
                        try:
                            message_publisher(
                                "streams.top.cached",
                                {
                                    "user_id": getattr(user, "id", None),
                                    "results": results,
                                    "meta": meta,
                                },
                            )
                        except Exception:
                            logger.exception(
                                "message_publisher raised while publishing cached streams"
                            )
                    if metrics_hook:
                        try:
                            metrics_hook(
                                "streams.top.cache_hit",
                                {"user_id": getattr(user, "id", None)},
                            )
                        except Exception:
                            logger.debug("metrics_hook raised on cache_hit")
                    return (results if not return_objects else None), meta
            except Exception:
                logger.exception(
                    "Failed reading cached top streams for user=%s",
                    getattr(user, "id", "<unknown>"),
                )

        # detect whether queryset looks like an ORM queryset or a plain iterable
        try:
            is_iterable_collection = not self.looks_like_queryset(queryset)
        except Exception:
            is_iterable_collection = True

        try:
            if is_iterable_collection:
                # plain iterable/list
                try:
                    items = list(queryset)
                except Exception:
                    items = []
                candidates = [s for s in items if getattr(s, "is_live", True)]
                num_candidates = len(candidates)
                enriched: List[Tuple[float, Any, Any]] = []
                for o in candidates:
                    b, _ = self._compute_boost_in_python(o, prefs, user_profile)
                    o.boost = float(b)
                    enriched.append((float(b), getattr(o, "created_at", None), o))
            else:
                # ORM-like flow
                try:
                    qs = queryset.filter(is_live=True)
                except Exception:
                    # if mock.filter returns a list (common in tests) or fails, coerce
                    try:
                        qs = [r for r in list(queryset) if getattr(r, "is_live", True)]
                    except Exception:
                        qs = []

                expr, components = self._build_boost_expression(prefs, user_profile)

                # If expr is available and qs appears to be an ORM queryset, try annotate+order
                try:
                    if expr is not None and hasattr(qs, "annotate"):
                        from django.db.models import (
                            ExpressionWrapper,
                            FloatField,
                        )  # local import

                        qs_ann = qs.annotate(boost=ExpressionWrapper(expr, output_field=FloatField()))  # type: ignore
                        qs_ord = qs_ann.order_by(
                            "-boost", "-viewer_count", "-created_at"
                        )
                        # Bounded window - previously max(top_n * 5, 50) with
                        # no ceiling, so an unusually large top_n turned
                        # directly into an unusually large query.
                        candidate_window = self.candidate_window(top_n)
                        candidates = list(qs_ord[:candidate_window])
                        num_candidates = len(candidates)
                        enriched = []
                        for o in candidates:
                            try:
                                b = float(getattr(o, "boost", 0.0) or 0.0)
                            except Exception:
                                b = 0.0
                            enriched.append(
                                (float(b), getattr(o, "created_at", None), o)
                            )
                    else:
                        # annotate unavailable -> compute in Python
                        candidates = list(qs)
                        num_candidates = len(candidates)
                        enriched = []
                        for o in candidates:
                            b, _ = self._compute_boost_in_python(o, prefs, user_profile)
                            o.boost = float(b)
                            enriched.append(
                                (float(b), getattr(o, "created_at", None), o)
                            )
                except Exception:
                    # If any step fails, fallback to Python boost computation
                    logger.exception(
                        "ORM annotation path failed; falling back to Python computation"
                    )
                    candidates = list(qs)
                    num_candidates = len(candidates)
                    enriched = []
                    for o in candidates:
                        b, _ = self._compute_boost_in_python(o, prefs, user_profile)
                        o.boost = float(b)
                        enriched.append((float(b), getattr(o, "created_at", None), o))

            # stable in-memory sorting and capping
            enriched.sort(
                key=lambda t: (float(t[0] or 0.0), t[1] if t[1] is not None else 0),
                reverse=True,
            )
            final_objs = [t[2] for t in enriched[:top_n]]

            if return_objects:
                results = final_objs
            else:
                results = []
                for o in final_objs:
                    try:
                        d = serializer(o)
                    except Exception:
                        logger.exception(
                            "Serializer raised for stream id=%s",
                            getattr(o, "id", "<unknown>"),
                        )
                        d = {"id": getattr(o, "id", None)}
                    d["boost"] = float(getattr(o, "boost", 0.0) or 0.0)
                    results.append(d)

            meta = {
                "cache_hit": False,
                "cache_key": cache_key,
                "qs_signature": qs_sig,
                "prefs_signature": prefs_sig,
                "components": list(
                    (components if "components" in locals() and components else [])
                ),
                "num_candidates": int(num_candidates),
                "top_n": top_n,
                "elapsed_ms": int((time.perf_counter() - t0) * 1000),
                "fallback": False,
            }

            # cache serializable payload (only when returning dicts)
            try:
                if not return_objects:
                    cache.set(
                        cache_key, {"results": results, "meta": meta}, self.ttl_with_jitter(int(cache_ttl))
                    )
            except Exception:
                logger.debug("Failed to set cache for key=%s", cache_key)

            if message_publisher:
                try:
                    message_publisher(
                        "streams.top.computed",
                        {
                            "user_id": getattr(user, "id", None),
                            "results": results,
                            "meta": meta,
                        },
                    )
                except Exception:
                    logger.exception(
                        "message_publisher failed while publishing computed streams"
                    )
            if metrics_hook:
                try:
                    metrics_hook(
                        "streams.top.computed",
                        {
                            "user_id": getattr(user, "id", None),
                            "num_candidates": meta["num_candidates"],
                            "top_n": top_n,
                        },
                    )
                except Exception:
                    logger.debug("metrics_hook raised on compute")

            return results, meta

        except Exception:
            logger.exception(
                "get_filtered_streams encountered unexpected error: %s",
                traceback.format_exc(),
            )
            # Robust fallback: handle both ORM and list-like querysets without assuming .order_by exists.
            try:
                if hasattr(queryset, "filter") and hasattr(
                    queryset.filter(is_live=True), "order_by"
                ):
                    fallback_qs = queryset.filter(is_live=True).order_by(
                        "-viewer_count", "-created_at"
                    )[:top_n]
                    fallback_objs = list(fallback_qs)
                else:
                    fallback_objs = [
                        o for o in list(queryset) if getattr(o, "is_live", True)
                    ]
                    fallback_objs = sorted(
                        fallback_objs,
                        key=lambda o: (
                            float(getattr(o, "viewer_count", 0) or 0),
                            getattr(o, "created_at", None) or 0,
                        ),
                        reverse=True,
                    )[:top_n]

                results = []
                for o in fallback_objs:
                    if return_objects:
                        results.append(o)
                    else:
                        try:
                            d = serializer(o)
                        except Exception:
                            d = {"id": getattr(o, "id", None)}
                        d["boost"] = float(getattr(o, "viewer_count", 0) or 0) * float(
                            self.BOOST_WEIGHTS.get("viewer_count", 0.01)
                        )
                        results.append(d)

                meta = {
                    "cache_hit": False,
                    "cache_key": None,
                    "components": [],
                    "num_candidates": len(fallback_objs),
                    "top_n": top_n,
                    "elapsed_ms": int((time.perf_counter() - t0) * 1000),
                    "fallback": True,
                }
                return results, meta
            except Exception:
                logger.exception("Fallback get_filtered_streams failed")
                return [], {
                    "error": "internal",
                    "status": 500,
                    "elapsed_ms": int((time.perf_counter() - t0) * 1000),
                    "cache_hit": False,
                }

    # -------------------------
    # Response injection helper
    # -------------------------
    def inject_streams_into_response(
        self,
        user,
        response_data: Dict[str, Any],
        queryset,
        *,
        limit: Optional[int] = None,
        serializer: Optional[SerializerCallable] = None,
        return_objects: bool = False,
        cache_ttl: int = RESULT_CACHE_TTL_SECONDS,
        force_refresh: bool = False,
        message_publisher: Optional[MessagePublisher] = None,
        metrics_hook: Optional[MetricsHook] = None,
    ) -> Dict[str, Any]:
        try:
            results, meta = self.get_filtered_streams(
                user,
                queryset,
                top_n=limit or self.DEFAULT_TOP_STREAMS,
                return_objects=return_objects,
                serializer=serializer,
                cache_ttl=cache_ttl,
                force_refresh=force_refresh,
                message_publisher=message_publisher,
                metrics_hook=metrics_hook,
            )
            resp = dict(response_data)
            resp["live_streams"] = results
            resp["_live_streams_meta"] = meta
            return resp
        except Exception:
            logger.exception("inject_streams_into_response failed")
            return response_data


# Helpers
def json_dumps_sorted(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


# ============================
# Example usage
# ============================
#
# --- Basic DRF view: posts with injected top live streams -------------------
#
# from rest_framework.pagination import PageNumberPagination
# from rest_framework.response import Response
# from rest_framework.views import APIView
#
# from .models import Stream, Post
# from .serializers import StreamSerializer, PostSerializer
# from .dynamic_streams import DynamicStreamFilterMixin
#
# class PostListView(DynamicStreamFilterMixin, APIView):
#     """Returns posts (paginated) and appends top live streams for the current user."""
#
#     def get(self, request, *args, **kwargs):
#         posts_qs = Post.objects.filter(is_active=True).order_by("-created_at")
#         paginator = PageNumberPagination()
#         page = paginator.paginate_queryset(posts_qs, request)
#         posts_serialized = PostSerializer(page, many=True).data
#         base_response = {"results": posts_serialized, "count": posts_qs.count()}
#
#         stream_qs = Stream.objects.filter(is_live=True)
#         final = self.inject_streams_into_response(
#             request.user, base_response, stream_qs, limit=5, serializer=StreamSerializer
#         )
#         return Response(final)
#
# --- A dedicated top-streams endpoint, with metrics/pub-sub wired in --------
#
# class TopStreamsView(DynamicStreamFilterMixin, APIView):
#     def get(self, request):
#         results, meta = self.get_filtered_streams(
#             request.user,
#             Stream.objects.filter(is_live=True),
#             top_n=int(request.query_params.get("limit", 5)),
#             message_publisher=lambda topic, payload: kafka_producer.send(topic, payload),
#             metrics_hook=lambda name, tags: statsd_client.incr(name, tags=tags),
#         )
#         if meta.get("error"):
#             return Response(meta, status=meta.get("status", 400))
#         return Response({"streams": results, "meta": meta})
#
# --- Updating preferences from a "watched stream" signal --------------------
#
# @receiver(post_save, sender=WatchEvent)
# def on_watch_event(sender, instance, created, **kwargs):
#     if not created:
#         return
#     mixin = DynamicStreamFilterMixin()
#     mixin.update_stream_preferences_for_user(
#         instance.user, add_category=instance.stream.category, add_host=instance.stream.host_id,
#     )
#
# --- Cache-warming management command (e.g. run every minute for active users) --
#
# class Command(BaseCommand):
#     def handle(self, *args, **options):
#         mixin = DynamicStreamFilterMixin()
#         stream_qs = Stream.objects.filter(is_live=True)
#         for user in User.objects.filter(is_active=True, last_login__gte=recent_cutoff):
#             mixin.get_filtered_streams(user, stream_qs, force_refresh=True)
#
# Testing tip: `unittest.mock.patch("dynamic_streams.cache", FakeCache())` works
# regardless of whether this module was imported via its bare name or a full
# dotted package path, since it registers itself under the bare name in
# sys.modules on import.
