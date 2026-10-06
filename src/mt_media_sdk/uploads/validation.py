"""Validation primitives for resumable chunked uploads.

The previous upload service imported ``UploadContext`` and
``ValidationPipeline`` from ``security.validators``, but those symbols did not
exist there.  Keeping initiation validation next to the upload workflow avoids a
cross-package import cycle and gives chunked uploads a stable validation
contract.
"""
from __future__ import annotations

import importlib
import inspect
import json
import mimetypes
import os
import re
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable, Mapping, Optional

from asgiref.sync import async_to_sync
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MIME_RE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$", re.I)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class UploadContext:
    filename: str
    mime_type: str
    size: int
    tenant_id: Optional[str] = None
    checksum: Optional[str] = None


def _setting(name: str, default: Any) -> Any:
    sentinel = object()
    try:
        configured = getattr(settings, name, sentinel)
        if configured is not sentinel:
            return configured
    except Exception:
        pass
    return os.environ.get(name, default)


async def _await_value(value: Any) -> Any:
    return await value


def _resolve_result(value: Any) -> Any:
    return async_to_sync(_await_value)(value) if inspect.isawaitable(value) else value


def _import_callable(path: str) -> Callable[..., Any]:
    module_name, separator, attribute = str(path or "").rpartition(".")
    if not separator:
        raise ImproperlyConfigured(f"{path!r} is not a dotted Python path")
    module = importlib.import_module(module_name)
    value = getattr(module, attribute)
    if not callable(value):
        raise ImproperlyConfigured(f"{path!r} must resolve to a callable")
    return value


def normalize_sha256(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = str(value).strip().casefold()
    if not normalized:
        return None
    if not _SHA256_RE.fullmatch(normalized):
        raise ValidationError("checksum must be a 64-character SHA-256 hex digest")
    return normalized


def normalize_filename(value: str) -> str:
    raw = str(value or "").strip().replace("\\", "/")
    name = raw.rsplit("/", 1)[-1]
    maximum = int(_setting("UPLOAD_MAX_FILENAME_LENGTH", 255))
    if not name or name in {".", ".."}:
        raise ValidationError("filename is required")
    if len(name) > maximum or _CONTROL_RE.search(name):
        raise ValidationError(f"filename must be at most {maximum} characters and contain no controls")
    if name.startswith(".") and not bool(_setting("UPLOAD_ALLOW_HIDDEN_FILENAMES", False)):
        raise ValidationError("hidden filenames are not allowed")
    return name


def normalize_mime_type(value: Optional[str], filename: str) -> str:
    candidate = str(value or "").strip().casefold()
    if not candidate:
        guessed, _ = mimetypes.guess_type(filename)
        candidate = str(guessed or "application/octet-stream").casefold()
    candidate = candidate.split(";", 1)[0].strip()
    if len(candidate) > 127 or not _MIME_RE.fullmatch(candidate):
        raise ValidationError("mime_type is invalid")

    blocked = {
        str(item).strip().casefold()
        for item in _setting(
            "UPLOAD_BLOCKED_MIME_TYPES",
            (
                "application/x-msdownload",
                "application/x-dosexec",
                "application/x-sh",
                "application/x-bat",
            ),
        )
        if str(item).strip()
    }
    if candidate in blocked:
        raise ValidationError(f"mime_type {candidate!r} is not permitted")
    if candidate == "application/octet-stream" and not bool(
        _setting("UPLOAD_ALLOW_OCTET_STREAM", False)
    ):
        raise ValidationError("an explicit supported mime_type is required")
    return candidate


def validate_json_metadata(value: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValidationError("metadata must be a JSON object")
    normalized = dict(value)
    try:
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError("metadata must contain only finite JSON values") from exc
    maximum = int(_setting("UPLOAD_MAX_METADATA_BYTES", 64 * 1024))
    if len(encoded) > maximum:
        raise ValidationError(f"metadata exceeds the {maximum}-byte limit")
    return normalized


class ValidationPipeline:
    """Validate upload metadata and run an optional project-specific hook."""

    def __init__(self, hook: Optional[Callable[[UploadContext], Any]] = None) -> None:
        self._hook = hook

    def run(self, context: UploadContext) -> UploadContext:
        filename = normalize_filename(context.filename)
        mime_type = normalize_mime_type(context.mime_type, filename)
        try:
            size = int(context.size)
        except (TypeError, ValueError) as exc:
            raise ValidationError("declared_size must be an integer") from exc
        if size <= 0:
            raise ValidationError("declared_size must be greater than zero")
        maximum = int(_setting("UPLOAD_MAX_DECLARED_SIZE_BYTES", 5 * 1024**3))
        if size > maximum:
            raise ValidationError(f"declared_size exceeds the {maximum}-byte service limit")
        checksum = normalize_sha256(context.checksum)

        validated = UploadContext(
            filename=filename,
            mime_type=mime_type,
            size=size,
            tenant_id=None if context.tenant_id is None else str(context.tenant_id),
            checksum=checksum,
        )

        hook = self._hook
        if hook is None:
            hook_path = str(_setting("UPLOAD_INITIATION_VALIDATOR", "") or "").strip()
            hook = _import_callable(hook_path) if hook_path else None
        if hook is not None:
            result = _resolve_result(hook(validated))
            if result is False:
                raise ValidationError("upload initiation was rejected by policy")
        return validated


def classify_media_type(mime_type: str) -> str:
    value = str(mime_type or "").casefold()
    if value.startswith("image/"):
        return "image"
    if value.startswith("audio/"):
        return "audio"
    if value.startswith("video/"):
        return "video"
    if value.startswith("text/") or value in {"application/json", "application/xml"}:
        return "text"
    if value in {
        "application/zip",
        "application/x-tar",
        "application/gzip",
        "application/x-7z-compressed",
    }:
        return "archive"
    return "document"


def validate_completed_stream(
    fileobj: BinaryIO,
    *,
    filename: str,
    mime_type: str,
    expected_size: int,
    expected_checksum: Optional[str],
) -> None:
    """Run final content validation without silently transforming bytes.

    A project hook can replace the default validator.  The default delegates to
    ``CustomValidator.validate_file`` when available.  If a sanitizer returns a
    transformed stream, its bytes must remain identical to the assembled upload;
    chunked uploads are integrity-preserving and never rewrite client content
    behind the declared checksum.
    """

    if not bool(_setting("UPLOAD_VALIDATE_COMPLETED_CONTENT", True)):
        return

    hook_path = str(_setting("UPLOAD_COMPLETED_VALIDATOR", "") or "").strip()
    if hook_path:
        hook = _import_callable(hook_path)
        result = _resolve_result(
            hook(
                fileobj=fileobj,
                filename=filename,
                mime_type=mime_type,
                expected_size=expected_size,
                expected_checksum=expected_checksum,
            )
        )
        if result is False:
            raise ValidationError("completed upload was rejected by policy")
        return

    try:
        from mt_media_sdk.security.validators import CustomValidator
    except (ImportError, AttributeError):
            if bool(_setting("UPLOAD_FINAL_VALIDATOR_FAIL_CLOSED", True)):
                raise ImproperlyConfigured(
                    "No completed-upload validator is available; configure "
                    "UPLOAD_COMPLETED_VALIDATOR or install the security validators"
                )
            return

    original_position = None
    try:
        original_position = fileobj.tell()
    except Exception:
        pass
    try:
        fileobj.seek(0)
    except Exception:
        pass

    validated = async_to_sync(CustomValidator.validate_file)(
        fileobj,
        classify_media_type(mime_type),
    )
    if validated is None:
        raise ValidationError("completed upload validation returned no file")

    # A different stream is allowed only when it contains exactly the same bytes.
    if validated is not fileobj:
        digest = __import__("hashlib").sha256()
        total = 0
        try:
            validated.seek(0)
        except Exception:
            pass
        while True:
            block = validated.read(1024 * 1024)
            if not block:
                break
            if isinstance(block, str):
                block = block.encode("utf-8")
            digest.update(block)
            total += len(block)
        if total != expected_size:
            raise ValidationError("content validation attempted to change the upload size")
        if expected_checksum and digest.hexdigest() != expected_checksum:
            raise ValidationError("content validation attempted to change uploaded bytes")

    try:
        fileobj.seek(original_position if original_position is not None else 0)
    except Exception:
        pass
