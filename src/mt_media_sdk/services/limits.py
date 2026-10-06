from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SAFE_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$", flags=re.ASCII)


def _setting(name: str, default: Any) -> Any:
    sentinel = object()
    try:
        from django.conf import settings

        configured = getattr(settings, name, sentinel)
        if configured is not sentinel:
            return configured
    except Exception:
        pass
    return os.environ.get(name, default)


def setting_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = _setting(name, default)
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def setting_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = _setting(name, default)
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} must be numeric") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def setting_bool(name: str, default: bool) -> bool:
    raw = _setting(name, default)
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, int) and raw in {0, 1}:
        return bool(raw)
    if isinstance(raw, str):
        normalized = raw.strip().casefold()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise RuntimeError(f"{name} must be a strict boolean")


def setting_csv(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = _setting(name, default)
    if isinstance(raw, str):
        values = raw.split(",")
    elif isinstance(raw, (tuple, list, set, frozenset)):
        values = list(raw)
    else:
        raise RuntimeError(f"{name} must be a sequence of strings")
    result: list[str] = []
    seen: set[str] = set()
    for raw_value in values:
        if not isinstance(raw_value, str):
            raise RuntimeError(f"{name} must contain only strings")
        value = raw_value.strip()
        if not value or len(value) > 4096 or _CONTROL_RE.search(value):
            raise RuntimeError(f"{name} contains an invalid value")
        if value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class MediaServiceLimits:
    stream_chunk_bytes: int
    max_input_bytes: int
    max_output_bytes: int
    max_decompressed_bytes: int
    max_compression_ratio: float
    max_image_pixels: int
    max_pdf_pages: int
    max_files_per_request: int
    max_filename_length: int
    max_sort_items: int
    ffmpeg_timeout_seconds: int
    ffmpeg_max_stderr_bytes: int
    encryption_max_frame_bytes: int
    encryption_max_frames: int
    spool_memory_bytes: int

    @classmethod
    def from_settings(cls) -> "MediaServiceLimits":
        return cls(
            stream_chunk_bytes=setting_int(
                "MEDIA_STREAM_CHUNK_BYTES", 64 * 1024, 4 * 1024, 4 * 1024 * 1024
            ),
            max_input_bytes=setting_int(
                "MEDIA_MAX_INPUT_BYTES", 256 * 1024 * 1024, 1024, 10 * 1024**3
            ),
            max_output_bytes=setting_int(
                "MEDIA_MAX_OUTPUT_BYTES", 512 * 1024 * 1024, 1024, 20 * 1024**3
            ),
            max_decompressed_bytes=setting_int(
                "MEDIA_MAX_DECOMPRESSED_BYTES", 256 * 1024 * 1024, 1024, 20 * 1024**3
            ),
            max_compression_ratio=setting_float(
                "MEDIA_MAX_COMPRESSION_RATIO", 100.0, 1.0, 10000.0
            ),
            max_image_pixels=setting_int(
                "MEDIA_MAX_IMAGE_PIXELS", 50_000_000, 1_000, 1_000_000_000
            ),
            max_pdf_pages=setting_int("MEDIA_MAX_PDF_PAGES", 1000, 1, 100_000),
            max_files_per_request=setting_int(
                "MEDIA_MAX_FILES_PER_REQUEST", 100, 1, 10_000
            ),
            max_filename_length=setting_int(
                "MEDIA_MAX_FILENAME_LENGTH", 255, 16, 4096
            ),
            max_sort_items=setting_int("MEDIA_MAX_SORT_ITEMS", 100_000, 1, 5_000_000),
            ffmpeg_timeout_seconds=setting_int(
                "MEDIA_FFMPEG_TIMEOUT_SECONDS", 300, 1, 3600
            ),
            ffmpeg_max_stderr_bytes=setting_int(
                "MEDIA_FFMPEG_MAX_STDERR_BYTES", 64 * 1024, 1024, 10 * 1024 * 1024
            ),
            encryption_max_frame_bytes=setting_int(
                "MEDIA_ENCRYPTION_MAX_FRAME_BYTES", 8 * 1024 * 1024, 1024, 64 * 1024 * 1024
            ),
            encryption_max_frames=setting_int(
                "MEDIA_ENCRYPTION_MAX_FRAMES", 1_000_000, 1, 10_000_000
            ),
            spool_memory_bytes=setting_int(
                "MEDIA_SPOOL_MEMORY_BYTES", 8 * 1024 * 1024, 64 * 1024, 256 * 1024 * 1024
            ),
        )


def validate_filename(value: Any, *, limits: MediaServiceLimits | None = None) -> str:
    active = limits or MediaServiceLimits.from_settings()
    if not isinstance(value, str):
        raise ValueError("filename must be a string")
    candidate = value.strip().replace("\\", "/")
    if (
        not candidate
        or len(candidate) > active.max_filename_length
        or _CONTROL_RE.search(candidate)
    ):
        raise ValueError("filename is invalid")
    return Path(candidate).name


def validate_field_name(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("field name must be a string")
    candidate = value.strip()
    if _SAFE_FIELD_RE.fullmatch(candidate) is None:
        raise ValueError("field name is invalid")
    return candidate


def validate_storage_path(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("storage path must be a string")
    candidate = value.strip().replace("\\", "/")
    if not candidate or len(candidate) > 2048 or _CONTROL_RE.search(candidate):
        raise ValueError("storage path is invalid")
    path = PurePosixPath(candidate)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("storage path must be relative and traversal-free")
    return str(path)


def resolve_inside(base: str | os.PathLike[str], relative_path: str) -> Path:
    root = Path(base).expanduser().resolve()
    candidate = (root / validate_storage_path(relative_path)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("storage path escapes configured root") from exc
    return candidate
