# tests/test_dynamic_streams.py
import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
from  mt_media_sdk.ranking_filter.dynamic_streams import (
    DynamicStreamFilterMixin,
    StreamPreferenceSnapshot,
)


# ----------------------
# Fixtures
# ----------------------
@pytest.fixture
def user():
    class UserProfile:
        age = 25

    class User:
        id = 1
        profile = UserProfile()

    return User()


@pytest.fixture
def mixin():
    return DynamicStreamFilterMixin()


@pytest.fixture
def mock_queryset():
    # Mock queryset objects
    class Stream:
        def __init__(
            self,
            id,
            category,
            host_id,
            viewer_count,
            created_at,
            age_limit,
            is_live=True,
        ):
            self.id = id
            self.category = category
            self.host_id = host_id
            self.viewer_count = viewer_count
            self.created_at = created_at
            self.age_limit = age_limit
            self.is_live = is_live

    streams = [
        Stream(1, 10, 101, 50, datetime.now() - timedelta(minutes=10), 18),
        Stream(2, 20, 102, 30, datetime.now() - timedelta(minutes=5), 21),
        Stream(3, 10, 103, 100, datetime.now() - timedelta(minutes=2), 30),
    ]

    qs = Mock()
    qs.filter = Mock(
        side_effect=lambda **kwargs: [
            s
            for s in streams
            if all(
                getattr(s, k) == v or (k.endswith("__lte") and getattr(s, k[:-5]) <= v)
                for k, v in kwargs.items()
            )
        ]
    )
    qs.order_by = Mock(side_effect=lambda *args: streams)
    qs.select_related = Mock(return_value=qs)
    qs.only = Mock(return_value=qs)
    return qs, streams


# ----------------------
# Tests
# ----------------------
def test_preferences_update_and_clear(user, mixin):
    mixin.clear_stream_preferences(user)
    prefs = mixin.get_stream_preferences(user)
    assert prefs.recent_categories == []
    assert prefs.watched_hosts == []

    mixin.update_stream_preferences_for_user(user, add_category=5)
    prefs = mixin.get_stream_preferences(user)
    assert prefs.recent_categories == [5]

    mixin.update_stream_preferences_for_user(user, add_host=99)
    prefs = mixin.get_stream_preferences(user)
    assert prefs.watched_hosts == [99]


def test_build_boost_expression_components(user, mixin):
    snapshot = StreamPreferenceSnapshot(recent_categories=[10, 20], watched_hosts=[101])
    expr, components = mixin._build_boost_expression(snapshot, user.profile)
    assert "category_match" in components
    assert "watch_history" in components
    assert "viewer_count" in components


def test_qs_signature(mock_queryset, mixin):
    qs, _ = mock_queryset
    sig = mixin._qs_signature(qs)
    assert isinstance(sig, str)
    assert len(sig) == 12


@patch("dynamic_streams.cache")
def test_get_filtered_streams_serialization(mock_cache, user, mixin, mock_queryset):
    qs, streams = mock_queryset
    mock_cache.get.return_value = None  # cache miss

    results, meta = mixin.get_filtered_streams(user, qs, top_n=2)
    assert len(results) == 2
    assert all("id" in r for r in results)
    assert meta["num_candidates"] >= 2
    assert not meta["cache_hit"]


@patch("dynamic_streams.cache")
def test_get_filtered_streams_cache_hit(mock_cache, user, mixin, mock_queryset):
    qs, streams = mock_queryset
    cached_data = {"results": [{"id": 999}], "meta": {"num_candidates": 1}}
    mock_cache.get.return_value = cached_data

    results, meta = mixin.get_filtered_streams(user, qs)
    assert results == cached_data["results"]
    assert meta["cache_hit"]


@patch("dynamic_streams.cache")
def test_force_refresh_bypasses_cache(mock_cache, user, mixin, mock_queryset):
    qs, streams = mock_queryset
    cached_data = {"results": [{"id": 999}], "meta": {"num_candidates": 1}}
    mock_cache.get.return_value = cached_data

    results, meta = mixin.get_filtered_streams(user, qs, force_refresh=True)
    assert results != cached_data["results"]
    assert not meta["cache_hit"]


@patch("dynamic_streams.cache")
def test_inject_streams_into_response(mock_cache, user, mixin, mock_queryset):
    qs, streams = mock_queryset
    mock_cache.get.return_value = None
    response = {"status": "ok"}
    resp_with_streams = mixin.inject_streams_into_response(user, response, qs, limit=2)
    assert "live_streams" in resp_with_streams
    assert "_live_streams_meta" in resp_with_streams
    assert len(resp_with_streams["live_streams"]) == 2


def test_user_without_profile(mixin):
    class UserNoProfile:
        id = 2
        profile = None

    user = UserNoProfile()
    results, meta = mixin.get_filtered_streams(user, [])
    assert results == []
    assert meta["status"] == 400
    assert "user_profile_missing" in meta["error"]
