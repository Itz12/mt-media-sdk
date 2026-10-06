# dynamic_featured.py
from __future__ import annotations

import hashlib
import json
import logging
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Shared cache infrastructure (SimpleMemoryCache fallback, Django-cache
# resolution via settings.configured, safe_now(), and the RankingCacheMixin
# base class with candidate-window/TTL-jitter helpers) lives in
# dynamic_streams.py - this used to be a near-identical ~30-line block
# copy-pasted into this file, which had already started to drift (slightly
# different docstrings, no guarantee a fix to one would reach the other).
# Importing it here means there's exactly one implementation to maintain.
try:
    from .dynamic_streams import cache, safe_now, RankingCacheMixin, django_now  # noqa: F401
except ImportError:
    from dynamic_streams import cache, safe_now, RankingCacheMixin, django_now  # type: ignore  # noqa: F401

# Canonical home for these two type aliases is recommender_service.py; see
# that module's docstring. Imported defensively so this module still works
# standalone if the package layout changes.
try:
    from .recommender_service import MessagePublisher, MetricsHook  # type: ignore
except ImportError:
    try:
        from recommender_service import MessagePublisher, MetricsHook  # type: ignore
    except ImportError:
        MessagePublisher = Callable[[str, Dict[str, Any]], None]
        MetricsHook = Callable[[str, Dict[str, Any]], None]

# Register this module under its own bare name too, mirroring
# dynamic_streams.py's identical pattern (for `patch("dynamic_featured.cache")`
# in tests, regardless of the full dotted import path actually used).
try:
    sys.modules.setdefault("dynamic_featured", sys.modules[__name__])
except Exception:
    logger.debug("Could not register legacy module alias 'dynamic_featured'.", exc_info=True)

DEFAULT_CACHE_TTL = 60  # seconds


@dataclass
class FeaturedConfig:
    category_match: float = 3.0
    recent_post: float = 1.0
    click_weight: float = 0.7
    impression_weight: float = 0.3
    age_match: float = 2.0
    gender_match: float = 1.0
    purchased_before: float = 4.0
    session_interaction: float = 2.0


class DynamicFeaturedMixin(RankingCacheMixin):
    """
    Compute a dynamic 'boost' score on a queryset of items and return top-N items
    personalized for a user.

    Public API:
      - get_featured_for_user(user, base_qs, top_n=10, ... ) -> (results_list, meta)

    See the "Example usage" section at the bottom of this module for a
    complete DRF view and a preference-update signal handler.
    """

    DEFAULT_CONFIG = FeaturedConfig()

    def _pref_cache_key(self, user_id: int) -> str:
        return f"user:{user_id}:featured_prefs_v1"

    def _result_cache_key(
        self,
        user_id: Union[int, str],
        qs_signature: str,
        prefs_signature: str,
        top_n: int,
    ) -> str:
        digest = hashlib.sha256(f"{qs_signature}|{prefs_signature}".encode()).hexdigest()[
            :12
        ]
        return f"user:{user_id}:featured_top:{top_n}:{digest}"

    # Default serializer: override in subclass or pass custom serializer
    def serialize_item_default(self, obj: Any) -> Dict[str, Any]:
        created = getattr(obj, "created_at", None)
        return {
            "id": getattr(obj, "id", None),
            "boost": float(getattr(obj, "boost", 0.0) or 0.0),
            "created_at": (
                created.isoformat() if getattr(created, "isoformat", None) else None
            ),
            "title": getattr(obj, "title", None) or getattr(obj, "name", None),
            "primary_image": getattr(obj, "primary_image_url", None)
            or getattr(obj, "image_url", None),
        }

    # Lightweight validation for extra_filters used by tests to assert invalid filters
    _ALLOWED_FILTER_PREFIXES = (
        "product__",
        "created_at",
        "id",
        "clicks",
        "impressions",
    )
    _ALLOWED_FILTER_EXACT = ("id", "created_at", "clicks", "impressions")

    def _validate_extra_filters(
        self, extra_filters: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        for k in extra_filters.keys():
            if any(k.startswith(pref) for pref in self._ALLOWED_FILTER_PREFIXES):
                continue
            if k in self._ALLOWED_FILTER_EXACT:
                continue
            return False, k
        return True, None

    def get_featured_for_user(
        self,
        user,
        base_qs,
        *,
        top_n: int = 10,
        extra_filters: Optional[Dict[str, Any]] = None,
        weights: Optional[FeaturedConfig] = None,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        require_profile: bool = True,
        return_objects: bool = False,
        serialize_item: Optional[Callable[[Any], Dict[str, Any]]] = None,
        message_publisher: Optional[MessagePublisher] = None,
        metrics_hook: Optional[MetricsHook] = None,
    ) -> Tuple[Optional[Iterable], Optional[Dict[str, Any]]]:
        """
        Compute top-N boosted results for a user.

        Returns (results, meta). On input validation error returns (None, error_meta).
        """
        t0 = time.perf_counter()
        weights = weights or self.DEFAULT_CONFIG
        serialize_item = serialize_item or self.serialize_item_default

        # basic user/profile validation
        if user is None or getattr(user, "id", None) is None:
            if require_profile:
                logger.warning("Missing user or user.id; aborting featured computation")
                return None, {"error": "missing_user", "status": 400}
            user_id = None
        else:
            user_id = user.id

        user_profile = getattr(user, "profile", None)
        if require_profile and not user_profile:
            logger.warning(
                "User %s has no profile; aborting personalized queryset.",
                getattr(user, "id", "<unknown>"),
            )
            return None, {"error": "user_profile_missing", "status": 400}

        # load preference snapshot from cache (best-effort)
        prefs: Dict[str, Any] = {}
        try:
            if user_id is not None:
                prefs = cache.get(self._pref_cache_key(int(user_id))) or {}
        except Exception:
            logger.debug("Cache GET for prefs failed for user %s", user_id)
            prefs = {}

        recent_categories: List[int] = list(prefs.get("recent_categories") or [])
        session_categories: List[int] = list(
            prefs.get("session_recent_categories") or []
        )
        purchased_ids: List[int] = list(prefs.get("purchased_ids") or [])

        # build signatures used for results caching
        try:
            qs_query_str = (
                str(base_qs.query) if hasattr(base_qs, "query") else repr(base_qs)
            )
        except Exception:
            qs_query_str = repr(base_qs)

        extra_filters_json = json.dumps(
            extra_filters or {}, sort_keys=True, default=str
        )
        prefs_sig = hashlib.sha256(
            json.dumps(prefs, sort_keys=True, default=str).encode()
        ).hexdigest()[:12]
        qs_sig = hashlib.sha256(
            f"{qs_query_str}|{extra_filters_json}".encode()
        ).hexdigest()[:12]

        user_id_str = str(user_id) if user_id is not None else "anon"
        cache_key = self._result_cache_key(user_id_str, qs_sig, prefs_sig, top_n)
        cached = None
        try:
            cached = cache.get(cache_key)
        except Exception:
            logger.debug(
                "Cache GET failed; continuing without cache for user %s", user_id
            )

        # If cached: return cached serialized results (and attempt to return objects if requested)
        if cached is not None:
            results_serialized = cached.get("results", [])
            meta = {
                "cache_hit": True,
                "cache_key": cache_key,
                "generated_at": cached.get("_meta", {}).get(
                    "generated_at", time.time()
                ),
                "elapsed_ms": int((time.perf_counter() - t0) * 1000),
                "num_candidates": cached.get("_meta", {}).get("num_candidates"),
            }

            # metrics hook
            if metrics_hook:
                try:
                    metrics_hook(
                        "featured.cache_hit", {"user_id": user_id, "top_n": top_n}
                    )
                except Exception:
                    logger.debug("metrics_hook raised on cache_hit")

            # If caller wants objects, attempt to rehydrate them from base_qs using IDs in the same order
            if return_objects:
                try:
                    ids = [
                        int(r.get("id"))
                        for r in results_serialized
                        if r.get("id") is not None
                    ]
                    if ids and hasattr(base_qs, "model"):
                        objs_qs = base_qs.model.objects.filter(id__in=ids)
                        objs_map = {getattr(o, "id", None): o for o in list(objs_qs)}
                        ordered_objs = [
                            objs_map.get(i) for i in ids if objs_map.get(i) is not None
                        ]
                        return ordered_objs, meta
                    return results_serialized, meta
                except Exception:
                    logger.exception(
                        "Failed to rehydrate cached objects; returning serialized payload"
                    )
                    return results_serialized, meta

            # publish via message_publisher if requested (non-fatal)
            if message_publisher:
                try:
                    message_publisher(
                        "featured.results",
                        {
                            "user_id": user_id,
                            "results": results_serialized,
                            "meta": meta,
                        },
                    )
                except Exception:
                    logger.exception(
                        "message_publisher failed after serving cached featured results"
                    )

            return results_serialized, meta

        # Validate extra_filters early so tests expecting invalid_filters receive it
        if extra_filters:
            ok, bad_key = self._validate_extra_filters(extra_filters)
            if not ok:
                return None, {
                    "error": "invalid_filters",
                    "status": 400,
                    "details": f"invalid filter key: {bad_key}",
                }

        # Apply extra filters defensively
        qs = base_qs
        if extra_filters:
            try:
                qs = qs.filter(**extra_filters)
            except Exception as exc:
                logger.exception("Invalid extra_filters provided: %s", exc)
                return None, {
                    "error": "invalid_filters",
                    "status": 400,
                    "details": str(exc),
                }

        # Build annotation expressions (do local imports so module import doesn't require Django)
        try:
            from django.db.models import (
                Case,
                ExpressionWrapper,
                F,
                FloatField,
                Value,
                When,
            )  # local import
            from django.db.models.functions import Coalesce  # local import

            engagement_expr = Coalesce(F("clicks"), Value(0.0)) * Value(
                float(weights.click_weight)
            ) + Coalesce(F("impressions"), Value(0.0)) * Value(
                float(weights.impression_weight)
            )

            total_expr = Value(0.0, output_field=FloatField())

            if recent_categories:
                total_expr = total_expr + Case(
                    When(
                        product__category__id__in=recent_categories,
                        then=Value(float(weights.category_match)),
                    ),
                    default=Value(0.0),
                    output_field=FloatField(),
                )

            if purchased_ids:
                total_expr = total_expr + Case(
                    When(
                        product__id__in=purchased_ids,
                        then=Value(float(weights.purchased_before)),
                    ),
                    default=Value(0.0),
                    output_field=FloatField(),
                )

            if session_categories:
                total_expr = total_expr + Case(
                    When(
                        product__category__id__in=session_categories,
                        then=Value(float(weights.session_interaction)),
                    ),
                    default=Value(0.0),
                    output_field=FloatField(),
                )

            # Use Django's now() when available and settings are configured, otherwise timezone-aware UTC
            try:
                recent_cutoff = (
                    django_now() if django_now else datetime.now(timezone.utc)
                ) - timedelta(days=7)
            except Exception:
                recent_cutoff = datetime.now(timezone.utc) - timedelta(days=7)

            total_expr = total_expr + Case(
                When(
                    created_at__gte=recent_cutoff,
                    then=Value(float(weights.recent_post)),
                ),
                default=Value(0.0),
                output_field=FloatField(),
            )

            # age match
            if getattr(user_profile, "age", None) is not None:
                try:
                    user_age = int(user_profile.age)
                    total_expr = total_expr + Case(
                        When(
                            product__target_age_min__lte=user_age,
                            product__target_age_max__gte=user_age,
                            then=Value(float(weights.age_match)),
                        ),
                        default=Value(0.0),
                        output_field=FloatField(),
                    )
                except Exception:
                    logger.debug("User age invalid; skipping age boost")

            # gender match
            if getattr(user_profile, "gender", None) is not None:
                total_expr = total_expr + Case(
                    When(
                        product__target_gender=user_profile.gender,
                        then=Value(float(weights.gender_match)),
                    ),
                    default=Value(0.0),
                    output_field=FloatField(),
                )

            # spending_score best-effort extraction
            spending_score = 0.0
            try:
                if callable(getattr(user_profile, "last_financial_behavior", None)):
                    fb = user_profile.last_financial_behavior()
                    if isinstance(fb, (list, tuple)) and len(fb) > 0:
                        spending_score = float(fb[0] or 0.0)
                    elif isinstance(fb, (int, float)):
                        spending_score = float(fb)
                elif hasattr(user_profile, "spending_score"):
                    spending_score = float(
                        user_profile.spending_score or 0.0
                    )
            except Exception:
                logger.debug("Failed to resolve spending_score; default=0")

            total_expr = total_expr + ExpressionWrapper(
                engagement_expr + Value(float(spending_score)),
                output_field=FloatField(),
            )

            # annotate and order
            annotate_qs = qs.annotate(
                boost=ExpressionWrapper(total_expr, output_field=FloatField())
            )
            ordered_qs = annotate_qs.order_by("-boost", "-created_at")

            # candidate window cap to limit DB work - bounded by
            # RankingCacheMixin.MAX_CANDIDATE_WINDOW (previously
            # max(top_n * 5, 50) with no ceiling at all).
            candidate_window = self.candidate_window(top_n)
            candidates_qs = ordered_qs[:candidate_window]

            # materialize and final in-Python sort for determinism
            evaluated = list(candidates_qs)
            num_candidates = len(evaluated)

            evaluated_payload = []
            for obj in evaluated:
                try:
                    payload = serialize_item(obj)
                except Exception:
                    logger.exception(
                        "serialize_item failed for obj id=%s",
                        getattr(obj, "id", "<unknown>"),
                    )
                    payload = {"id": getattr(obj, "id", None)}
                boost_val = getattr(obj, "boost", 0.0) or 0.0
                created_val = getattr(obj, "created_at", None)
                evaluated_payload.append((float(boost_val), created_val, obj, payload))

            evaluated_payload.sort(
                key=lambda t: (float(t[0] or 0.0), t[1] if t[1] is not None else 0),
                reverse=True,
            )

            final = evaluated_payload[: int(top_n)]

            if return_objects:
                results = [t[2] for t in final]
            else:
                results = [t[3] for t in final]

            meta = {
                "cache_hit": False,
                "cache_key": cache_key,
                "qs_signature": qs_sig,
                "prefs_signature": prefs_sig,
                "num_candidates": num_candidates,
                "top_n": top_n,
                "elapsed_ms": int((time.perf_counter() - t0) * 1000),
            }

            # cache serializable payload (only results, not model instances)
            try:
                serializable_results = results
                if return_objects:
                    serializable_results = [serialize_item(o) for o in results]
                cache_payload = {
                    "results": serializable_results,
                    "_meta": {
                        "num_candidates": num_candidates,
                        "generated_at": time.time(),
                    },
                }
                cache.set(cache_key, cache_payload, self.ttl_with_jitter(int(cache_ttl)))
            except Exception:
                logger.debug("Failed to set featured cache for key=%s", cache_key)

            # metrics hook (best-effort)
            if metrics_hook:
                try:
                    metrics_hook(
                        "featured.computed",
                        {
                            "user_id": getattr(user, "id", None),
                            "num_candidates": num_candidates,
                            "top_n": top_n,
                            "elapsed_ms": meta["elapsed_ms"],
                        },
                    )
                except Exception:
                    logger.debug("metrics_hook raised during compute")

            # message publishing (best-effort)
            if message_publisher:
                try:
                    message_publisher(
                        "featured.results",
                        {
                            "user_id": getattr(user, "id", None),
                            "results": results,
                            "meta": meta,
                        },
                    )
                except Exception:
                    logger.exception(
                        "message_publisher failed while publishing featured results"
                    )

            return results, meta

        except Exception as exc:
            logger.exception("Featured annotation build failed: %s", exc)
            # fallback: order by recency only
            try:
                fallback = qs.order_by("-created_at")[: int(top_n)]
                fallback_list = []
                for o in fallback:
                    try:
                        fallback_list.append(serialize_item(o))
                    except Exception:
                        fallback_list.append({"id": getattr(o, "id", None)})
                meta = {
                    "cache_hit": False,
                    "fallback": True,
                    "error": str(exc),
                    "elapsed_ms": int((time.perf_counter() - t0) * 1000),
                }
                return fallback_list, meta
            except Exception:
                logger.exception("Fallback ordering failed")
                return None, {"error": "internal", "status": 500}

    # Preference updater (safe to call from event handlers)
    def update_user_preferences(
        self,
        user,
        *,
        add_category: Optional[int] = None,
        add_purchased: Optional[int] = None,
        session_ttl_seconds: int = 300,
        max_recent: int = 20,
    ) -> None:
        """
        Write recent_categories / purchased_ids into cache.
        """
        if user is None or getattr(user, "id", None) is None:
            logger.debug("update_user_preferences called with missing user")
            return
        key = self._pref_cache_key(user.id)
        try:
            data = cache.get(key) or {
                "recent_categories": [],
                "session_recent_categories": [],
                "purchased_ids": [],
            }
            if add_category is not None:
                lst = data.get("recent_categories", [])
                if add_category in lst:
                    lst.remove(add_category)
                lst.insert(0, add_category)
                data["recent_categories"] = lst[:max_recent]

                s = data.get("session_recent_categories", [])
                if add_category in s:
                    s.remove(add_category)
                s.insert(0, add_category)
                session_limit = max(int(max_recent / 2), 10)
                data["session_recent_categories"] = s[:session_limit]

            if add_purchased is not None:
                p = data.get("purchased_ids", [])
                if add_purchased in p:
                    p.remove(add_purchased)
                p.insert(0, add_purchased)
                data["purchased_ids"] = p[:200]

            cache.set(key, data, int(max(60, session_ttl_seconds)))
        except Exception:
            logger.exception(
                "update_user_preferences failed for user %s",
                getattr(user, "id", "<unknown>"),
            )


# ============================
# Example usage
# ============================
#
# --- A featured-products DRF endpoint ----------------------------------------
#
# from rest_framework.response import Response
# from rest_framework.views import APIView
#
# from .models import FeaturedProduct
# from .serializers import FeaturedProductSerializer
# from .dynamic_featured import DynamicFeaturedMixin
#
# class FeaturedProductsView(DynamicFeaturedMixin, APIView):
#     def get(self, request):
#         base_qs = FeaturedProduct.objects.filter(is_active=True)
#         results, meta = self.get_featured_for_user(
#             request.user,
#             base_qs,
#             top_n=int(request.query_params.get("limit", 10)),
#             serialize_item=lambda obj: FeaturedProductSerializer(obj).data,
#             message_publisher=lambda topic, payload: kafka_producer.send(topic, payload),
#             metrics_hook=lambda name, tags: statsd_client.incr(name, tags=tags),
#         )
#         if results is None:
#             return Response(meta, status=meta.get("status", 400))
#         return Response({"featured": results, "meta": meta})
#
# --- Scoping to a specific category via extra_filters ------------------------
#
# results, meta = self.get_featured_for_user(
#     request.user, base_qs, extra_filters={"product__category_id": category_id},
# )
#
# --- Updating preferences after a purchase (signal handler) ------------------
#
# @receiver(post_save, sender=Order)
# def on_order_placed(sender, instance, created, **kwargs):
#     if not created:
#         return
#     mixin = DynamicFeaturedMixin()
#     for item in instance.items.all():
#         mixin.update_user_preferences(
#             instance.user,
#             add_category=item.product.category_id,
#             add_purchased=item.product_id,
#         )
#
# Testing tip: `unittest.mock.patch("dynamic_featured.cache", FakeCache())`
# works the same way as dynamic_streams.py's equivalent - see that module's
# example section for the underlying mechanism.
