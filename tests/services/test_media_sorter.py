from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from mt_media_sdk.services.media_sorter import (
    MediaSortError,
    MediaSortLimitExceeded,
    infer_media_type_from_name,
    sort_media,
)


@pytest.fixture(autouse=True)
def clear_inference_cache():
    infer_media_type_from_name.cache_clear()
    yield
    infer_media_type_from_name.cache_clear()


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("photo.JPG", "image"),
        ("movie.mp4", "video"),
        ("sound.flac", "audio"),
        ("document.pdf", "pdf"),
        ("notes.md", "text"),
        ("bundle.zip", "archive"),
        ("unknown.custom", ""),
        ("", ""),
    ],
)
def test_inference_returns_canonical_categories(filename: str, expected: str) -> None:
    assert infer_media_type_from_name(filename) == expected


def test_generic_application_mime_does_not_escape_canonical_categories(monkeypatch) -> None:
    monkeypatch.setattr(
        "mt_media_sdk.services.media_sorter.mimetypes.guess_type",
        lambda *_args, **_kwargs: ("application/vnd.vendor", None),
    )
    assert infer_media_type_from_name("file.vendor") == ""


def test_sorting_is_stable_and_returns_remaining_count() -> None:
    items = [
        {"id": 1, "media_type": "image", "name": "first.jpg"},
        {"id": 2, "media_type": "image", "name": "second.jpg"},
        {"id": 3, "media_type": "video", "name": "movie.mp4"},
    ]
    top, remaining = sort_media(items, max_items=2)
    assert [item["id"] for item in top] == [1, 2]
    assert remaining == 1


def test_inferred_type_is_written_back_for_compatibility() -> None:
    item = {"id": 1, "name": "voice.mp3", "media_type": None}
    result, remaining = sort_media([item], max_items=5)
    assert item["media_type"] == "audio"
    assert result[0]["media_type"] == "audio"
    assert remaining == 0


def test_write_back_can_be_disabled() -> None:
    item = {"id": 1, "name": "voice.mp3"}
    result, _ = sort_media([item], max_items=5, write_back=False)
    assert "media_type" not in item
    assert result[0]["media_type"] == "audio"


def test_sensitive_and_heavy_metadata_is_redacted_and_json_safe() -> None:
    items = [
        {
            "id": 1,
            "name": "photo.png",
            "content": b"large",
            "authorization": "Bearer secret",
            "nested": {"when": object(), "items": list(range(100))},
        }
    ]
    result, _ = sort_media(items, max_items=5)
    meta = result[0]["meta"]
    assert "content" not in meta
    assert "authorization" not in meta
    json.dumps(result, allow_nan=False)


@dataclass
class MediaObject:
    filename: str
    id: int
    media_type: str | None = None


def test_objects_use_only_explicit_attributes() -> None:
    obj = MediaObject(filename="clip.webm", id=9)
    obj.secret = "must-not-leak"  # type: ignore[attr-defined]
    result, _ = sort_media([obj], max_items=5)
    assert result[0]["id"] == 9
    assert result[0]["media_type"] == "video"
    assert "secret" not in result[0]["meta"]


def test_objects_can_be_disabled() -> None:
    result, remaining = sort_media(
        [MediaObject(filename="clip.webm", id=9)],
        max_items=5,
        allow_objects=False,
    )
    assert result == []
    assert remaining == 0


def test_custom_order_is_applied_without_crashing_on_invalid_entries() -> None:
    result, _ = sort_media(
        [
            {"id": 1, "name": "photo.png"},
            {"id": 2, "name": "manual.pdf"},
        ],
        custom_order={"pdf": 0, "image": "invalid"},
        max_items=5,
    )
    assert result[0]["media_type"] == "pdf"


@pytest.mark.parametrize("value", [-1, None, "5", True])
def test_invalid_max_items_is_rejected(value) -> None:
    with pytest.raises(MediaSortError):
        sort_media([], max_items=value)


def test_scan_limit_prevents_unbounded_iterables(monkeypatch) -> None:
    monkeypatch.setenv("MEDIA_MAX_SORT_ITEMS", "3")
    with pytest.raises(MediaSortLimitExceeded):
        sort_media(({"id": index, "name": f"{index}.jpg"} for index in range(4)))
