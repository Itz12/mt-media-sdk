from __future__ import annotations

import json
import logging
import math
import mimetypes
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from functools import lru_cache
from pathlib import PurePath
from typing import Any

from .limits import MediaServiceLimits, validate_filename

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

DEFAULT_ORDER = {
    "image": 1,
    "video": 2,
    "audio": 3,
    "pdf": 4,
    "text": 5,
    "archive": 6,
}

_EXT_MAP = {
    "jpg": "image",
    "jpeg": "image",
    "png": "image",
    "gif": "image",
    "webp": "image",
    "bmp": "image",
    "tif": "image",
    "tiff": "image",
    "avif": "image",
    "heic": "image",
    "mp4": "video",
    "mov": "video",
    "avi": "video",
    "mkv": "video",
    "webm": "video",
    "m4v": "video",
    "mp3": "audio",
    "wav": "audio",
    "ogg": "audio",
    "flac": "audio",
    "m4a": "audio",
    "aac": "audio",
    "pdf": "pdf",
    "txt": "text",
    "md": "text",
    "csv": "text",
    "json": "text",
    "xml": "text",
    "yaml": "text",
    "yml": "text",
    "log": "text",
    "zip": "archive",
    "gz": "archive",
    "tgz": "archive",
    "tar": "archive",
    "7z": "archive",
}

_MIME_MAP = {
    "application/pdf": "pdf",
    "application/json": "text",
    "application/xml": "text",
    "application/zip": "archive",
    "application/gzip": "archive",
    "application/x-gzip": "archive",
}

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_PRIMITIVES = (str, bytes, bytearray, int, float, bool, list, tuple, set, frozenset)
_DEFAULT_EXCLUDED_META_KEYS = frozenset(
    {
        "content",
        "binary",
        "data",
        "raw",
        "body",
        "payload",
        "file",
        "stream",
        "password",
        "secret",
        "token",
        "authorization",
        "cookie",
        "cookies",
        "headers",
    }
)


class MediaSortError(ValueError):
    pass


class MediaSortLimitExceeded(MediaSortError):
    pass


@lru_cache(maxsize=4096)
def infer_media_type_from_name(name: str) -> str:
    """Infer one canonical media category from a filename or path.

    Unknown and generic ``application/*`` values return an empty string instead
    of leaking unstable MIME top-level categories into sorting policy.
    """

    if not isinstance(name, str):
        return ""
    candidate = name.strip()
    if not candidate or len(candidate) > 4096 or _CONTROL_RE.search(candidate):
        return ""
    filename = os.path.basename(candidate)
    try:
        guessed, _encoding = mimetypes.guess_type(filename, strict=False)
    except Exception:
        guessed = None
        logger.debug("mimetypes lookup failed", exc_info=True)
    if guessed:
        normalized = guessed.casefold()
        if normalized in _MIME_MAP:
            return _MIME_MAP[normalized]
        main = normalized.partition("/")[0]
        if main in {"image", "video", "audio", "text"}:
            return main
    suffix = PurePath(filename).suffix.casefold().removeprefix(".")
    return _EXT_MAP.get(suffix, "")


def _normalize_name(value: Any, limits: MediaServiceLimits) -> str | None:
    if value is None:
        return None
    try:
        return validate_filename(str(value), limits=limits)
    except ValueError:
        return None


def _safe_json_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 3:
        return "<truncated>"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        candidate = value.strip()
        if len(candidate) > 2048:
            return candidate[:2048]
        return candidate
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 64:
                result["__truncated__"] = True
                break
            key_text = str(key)[:128]
            result[key_text] = _safe_json_value(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_safe_json_value(item, depth=depth + 1) for item in value[:64]]
    if hasattr(value, "isoformat") and callable(value.isoformat):
        try:
            return value.isoformat()
        except Exception:
            return str(value)[:2048]
    return str(value)[:2048]


def _normalize_order(
    custom_order: Mapping[str, int] | None,
) -> dict[str, int]:
    order = dict(DEFAULT_ORDER)
    if not custom_order:
        return order
    if not isinstance(custom_order, Mapping):
        raise MediaSortError("custom_order must be a mapping")
    for raw_key, raw_value in custom_order.items():
        try:
            key = str(raw_key).strip().casefold()
            value = int(raw_value)
        except (TypeError, ValueError):
            logger.warning("Invalid custom_order entry ignored: %r=%r", raw_key, raw_value)
            continue
        if not key or len(key) > 64 or _CONTROL_RE.search(key):
            logger.warning("Invalid custom_order key ignored: %r", raw_key)
            continue
        if not -1_000_000 <= value <= 1_000_000:
            logger.warning("Out-of-range custom_order value ignored: %r", raw_value)
            continue
        order[key] = value
    return order


def sort_media(
    media_items: Iterable[Any],
    *,
    custom_order: Mapping[str, int] | None = None,
    default_sort_value: int = 999,
    max_items: int = 6,
    media_type_key: str = "media_type",
    name_keys: Sequence[str] = ("name", "filename", "file_name", "path"),
    allow_objects: bool = True,
    write_back: bool = True,
    max_scan_items: int | None = None,
    excluded_meta_keys: Sequence[str] = tuple(_DEFAULT_EXCLUDED_META_KEYS),
) -> tuple[list[dict[str, Any]], int]:
    """Return a stable, bounded, JSON-safe priority ordering.

    The function never reads file bodies and never serializes arbitrary object
    dictionaries. Only explicitly supported attributes are inspected.
    """

    if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 0:
        raise MediaSortError("max_items must be a non-negative integer")
    if isinstance(default_sort_value, bool) or not isinstance(default_sort_value, int):
        raise MediaSortError("default_sort_value must be an integer")
    if isinstance(media_items, (str, bytes, bytearray)) or not isinstance(
        media_items, Iterable
    ):
        raise MediaSortError("media_items must be a non-string iterable")
    if not isinstance(media_type_key, str) or not media_type_key.strip():
        raise MediaSortError("media_type_key must be a non-empty string")
    if not name_keys or any(not isinstance(item, str) or not item for item in name_keys):
        raise MediaSortError("name_keys must contain non-empty strings")

    limits = MediaServiceLimits.from_settings()
    scan_limit = limits.max_sort_items if max_scan_items is None else int(max_scan_items)
    if not 1 <= scan_limit <= limits.max_sort_items:
        raise MediaSortError(
            f"max_scan_items must be between 1 and {limits.max_sort_items}"
        )
    order = _normalize_order(custom_order)
    excluded = {str(item).casefold() for item in excluded_meta_keys}

    keyed: list[tuple[int, int, dict[str, Any]]] = []
    for index, raw in enumerate(media_items):
        if index >= scan_limit:
            raise MediaSortLimitExceeded(
                f"media_items exceeds the configured scan limit of {scan_limit}"
            )

        original: dict[str, Any] | None = raw if isinstance(raw, dict) else None
        working: dict[str, Any]
        if isinstance(raw, Mapping):
            working = dict(raw)
        elif allow_objects and not isinstance(raw, _PRIMITIVES):
            working = {}
            for key in (*name_keys, media_type_key, "id", "title"):
                try:
                    value = getattr(raw, key)
                except (AttributeError, TypeError, ValueError):
                    continue
                if not callable(value):
                    working[key] = value
        else:
            continue

        name: str | None = None
        for key in name_keys:
            candidate = _normalize_name(working.get(key), limits)
            if candidate:
                name = candidate
                break
        if name is None:
            name = _normalize_name(working.get("title"), limits)
        if name is not None:
            working["name"] = name

        raw_media_type = working.get(media_type_key)
        media_type = (
            str(raw_media_type).strip().casefold()
            if raw_media_type not in (None, "")
            else ""
        )
        if len(media_type) > 64 or _CONTROL_RE.search(media_type):
            media_type = ""
        if not media_type and name:
            media_type = infer_media_type_from_name(name)
            if original is not None and write_back and original.get(media_type_key) is None:
                original[media_type_key] = media_type or None
        working[media_type_key] = media_type or None

        meta: dict[str, Any] = {}
        for raw_key, value in working.items():
            key = str(raw_key)
            if key.casefold() in excluded:
                continue
            if key in {media_type_key}:
                continue
            if key.casefold() == "path" and isinstance(value, str):
                value = os.path.basename(value.replace("\\", "/"))
            meta[key[:128]] = _safe_json_value(value)
        safe = {
            "id": _safe_json_value(working.get("id")),
            "media_type": media_type or None,
            "name": name,
            "meta": meta,
        }
        # Assert the public result remains JSON serializable.
        json.dumps(safe, ensure_ascii=False, allow_nan=False)
        keyed.append((order.get(media_type, default_sort_value), index, safe))

    keyed.sort(key=lambda item: (item[0], item[1]))
    limited = [item[2] for item in keyed[:max_items]]
    return limited, max(0, len(keyed) - len(limited))


__all__ = [
    "DEFAULT_ORDER",
    "MediaSortError",
    "MediaSortLimitExceeded",
    "infer_media_type_from_name",
    "sort_media",
]
