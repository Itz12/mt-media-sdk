# test_dynamic_featured.py
import pytest
import types
from unittest.mock import patch
from datetime import datetime
from  mt_media_sdk.ranking_filter.dynamic_featured import DynamicFeaturedMixin


# -------------------------------
# Helper classes and fixtures
# -------------------------------


class FakeUser:
    def __init__(self, user_id=1, profile=None):
        self.id = user_id
        self.profile = profile


class FakeProfile:
    def __init__(self, age=None, gender=None, spending_score=None, fb_value=None):
        self.age = age
        self.gender = gender
        self.spending_score = spending_score
        self._fb = fb_value

    def last_financial_behavior(self):
        return self._fb


class FakeObj:
    """Simulates model instance"""

    def __init__(
        self,
        obj_id,
        created_at=None,
        clicks=0,
        impressions=0,
        product_category=1,
        product_id=1,
    ):
        self.id = obj_id
        self.created_at = created_at or datetime.now()
        self.clicks = clicks
        self.impressions = impressions
        self.product = types.SimpleNamespace(
            category=types.SimpleNamespace(id=product_category), id=product_id
        )
        self.boost = None
        self.title = f"Title {obj_id}"
        self.primary_image_url = f"http://img/{obj_id}.jpg"


class FakeQuerySet(list):
    """Mock queryset with annotate & filter"""

    def annotate(self, **kwargs):
        for obj in self:
            obj.boost = 0.0
        return self

    def order_by(self, *args):
        return self

    def filter(self, **kwargs):
        # simulate filtering by product__category__id or product__id
        results = []
        for obj in self:
            include = True
            for k, v in kwargs.items():
                if k.endswith("__in"):
                    field = k.split("__")[0]
                    val = getattr(
                        getattr(obj, field.split("__")[0]), field.split("__")[1], None
                    )
                    if val not in v:
                        include = False
                elif k.endswith("="):
                    pass
            if include:
                results.append(obj)
        return FakeQuerySet(results)


@pytest.fixture
def mixin():
    return DynamicFeaturedMixin()


@pytest.fixture
def user_with_profile():
    profile = FakeProfile(age=25, gender="M", spending_score=100, fb_value=[50])
    return FakeUser(user_id=42, profile=profile)


@pytest.fixture
def user_no_profile():
    return FakeUser(user_id=43, profile=None)


@pytest.fixture
def base_qs():
    return FakeQuerySet([FakeObj(i) for i in range(5)])


# -------------------------------
# Tests
# -------------------------------


def test_missing_profile_returns_error(mixin, user_no_profile, base_qs):
    results, meta = mixin.get_featured_for_user(user_no_profile, base_qs)
    assert results is None
    assert meta["error"] == "user_profile_missing"


def test_basic_compute(mixin, user_with_profile, base_qs):
    results, meta = mixin.get_featured_for_user(user_with_profile, base_qs, top_n=3)
    assert len(results) == 3
    for r in results:
        assert "id" in r and "boost" in r and "title" in r


def test_cache_hit(mixin, user_with_profile, base_qs):
    # prepopulate cache
    with patch("dynamic_featured.cache") as mock_cache:
        mixin._result_cache_key(
            user_with_profile.id, "dummy_qs", "dummy_prefs", 10
        )
        mock_cache.get.return_value = {
            "results": [{"id": 1}],
            "_meta": {"num_candidates": 1},
        }
        results, meta = mixin.get_featured_for_user(
            user_with_profile, base_qs, top_n=10
        )
        assert meta["cache_hit"] is True
        assert results[0]["id"] == 1


def test_extra_filters_invalid(mixin, user_with_profile, base_qs):
    # passing invalid filter keys
    results, meta = mixin.get_featured_for_user(
        user_with_profile, base_qs, extra_filters={"nonexistent_field__lt": 5}
    )
    assert results is None
    assert meta["error"] == "invalid_filters"


def test_return_objects_flag(mixin, user_with_profile, base_qs):
    results, meta = mixin.get_featured_for_user(
        user_with_profile, base_qs, top_n=2, return_objects=True
    )
    for obj in results:
        assert isinstance(obj, FakeObj)


def test_update_user_preferences_add_category(mixin, user_with_profile):
    with patch("dynamic_featured.cache") as mock_cache:
        mock_cache.get.return_value = {}
        mixin.update_user_preferences(user_with_profile, add_category=5)
        args, kwargs = mock_cache.set.call_args
        key, data, timeout = args
        assert 5 in data["recent_categories"]
        assert 5 in data["session_recent_categories"]


def test_update_user_preferences_add_purchased(mixin, user_with_profile):
    with patch("dynamic_featured.cache") as mock_cache:
        mock_cache.get.return_value = {}
        mixin.update_user_preferences(user_with_profile, add_purchased=7)
        args, kwargs = mock_cache.set.call_args
        key, data, timeout = args
        assert 7 in data["purchased_ids"]


def test_metrics_and_message_hooks(mixin, user_with_profile, base_qs):
    metrics_called = {}
    messages_called = {}

    def metrics_hook(name, payload):
        metrics_called[name] = payload

    def message_publisher(topic, payload):
        messages_called[topic] = payload

    results, meta = mixin.get_featured_for_user(
        user_with_profile,
        base_qs,
        metrics_hook=metrics_hook,
        message_publisher=message_publisher,
    )
    assert "featured.computed" in metrics_called
    assert "featured.results" in messages_called


def test_fallback_on_exception(mixin, user_with_profile, base_qs):
    # patch annotate to raise exception
    def fail_annotate(*args, **kwargs):
        raise Exception("forced")

    base_qs.annotate = fail_annotate
    results, meta = mixin.get_featured_for_user(user_with_profile, base_qs, top_n=2)
    assert "fallback" in meta and meta["fallback"] is True
    assert len(results) == 2
