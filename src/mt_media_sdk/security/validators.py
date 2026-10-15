# media/security/validators.py
"""
Robust, security-hardened validator utilities.

Goals:
- Importable during tests even when Django settings are not configured.
- Defensive fallbacks when optional libs (bleach, python-magic, lxml, clamd) are missing.
- Secure temporary file persistence (atomic writes, safe perms).
- Clear separation of concerns and extensive inline comments for maintainability.

Changes in this revision (see inline comments at each site for detail):
  * FIXED A LIVE BUG: this module called `_sanitizer_validate_text(text,
    field_name)` - two positional args - but mt_media_sdk.security.sanitizer's
    `validate_text(input_text)` only accepted one. Every single call raised
    TypeError, was swallowed by a bare `except Exception`, and silently fell
    back to this module's local (weaker, differently-behaved) copy. The
    "prefer the sanitizer module" delegation had never actually run.
    sanitizer.validate_text now accepts field_name too, so delegation works.
  * FIXED A CORRECTNESS BUG: `ValidatorHandler.extract_media_files()` used
    to run every text field through `awaitable_bleach_clean()`, and then
    `validate_media_and_text()` ran the *same* string through
    `CustomValidator.validate_text()` again - double sanitization, which
    can double-escape HTML entities (`&` -> `&amp;` -> `&amp;amp;`) and
    apply the blacklist/strip logic twice with different effective results
    depending on pass order. Extraction now only *collects* string fields;
    sanitization happens exactly once, in validate_media_and_text().
  * FIXED A CORRECTNESS BUG: `request.FILES.items()` on Django's
    MultiValueDict returns only the *last* value per key, so a form field
    with multiple files under one name silently dropped all but one.
    Now iterates `.lists()` (with a plain-dict fallback for non-Django
    callers/tests).
  * FIXED AN ASYNC-SAFETY BUG: `get_max_file_size()` called the synchronous
    Django cache API (`cache.get`/`cache.set`) directly inside an `async
    def`, blocking the event loop, right next to a DB call that *was*
    correctly wrapped in `asyncio.to_thread`. Both are now offloaded
    consistently. It also no longer hammers a broken/misconfigured
    MediaLimit lookup on every single call - a short in-process circuit
    breaker backs off after a failure - and the model path is now
    configurable via `settings.MEDIA_LIMIT_MODEL_PATH` instead of a
    hardcoded `from mt_media_sdk.models import MediaLimit`.
  * FIXED A ROBUSTNESS GAP: `_read_all_bytes()` had no upper bound, so a
    stream that lies about its declared Content-Length could be read
    fully into memory. It now accepts a `max_bytes` cap. `validate_file()`
    also now computes this buffer at most once per call and reuses it
    across the archive/macro/image/ClamAV checks, instead of re-reading
    the whole stream from scratch for each one.
  * FIXED A DEAD-CODE GAP: `BLOCKED_MIME_TYPES` was defined but never
    referenced anywhere. `validate_file()` now checks it explicitly - a
    defense-in-depth reject that fires regardless of what a (possibly
    misconfigured) per-media-type allow-list says.
  * FIXED A GAP: settings-derived module "constants" (ARCHIVE_MAX_FILES,
    TEMP_UPLOAD_DIR, etc.) were resolved once at import time, so
    `override_settings` in tests (or any settings configured after this
    module first imports) silently had no effect. Internal logic now reads
    them live via `_cfg()`; the old names remain importable for
    compatibility.
  * NEW: image validation now actually runs (`is_supported_image` /
    decompression-bomb pixel cap) instead of only checking the declared
    MIME type - a corrupted or absurdly large "image" used to sail through
    untouched. NEW: Office documents are checked for an embedded
    `vbaProject.bin` even when the MIME type doesn't say macro-enabled
    (catches a renamed `.xlsm`).
  * NEW: `ValidatorHandler` enforces an aggregate per-request file count
    and combined byte-size cap (`MAX_FILES_PER_REQUEST` /
    `MAX_TOTAL_UPLOAD_BYTES`) - previously, many small files under
    individual limits could still exhaust server resources.
  * NEW: validated large files that were already spooled to disk by
    `validate_file()` (as a `TemporaryUploadedFile`) are moved into place
    with `shutil.move()` instead of being read back into memory and
    written out a second time.
  * `get_clamav_client()` gained the same kind of short circuit breaker as
    the MediaLimit lookup, so a clamd outage doesn't retry a slow
    connect+ping sequence on every single scan call.
"""

from __future__ import annotations

import asyncio
import html
import importlib
import io
import logging
import mimetypes
import os
import re
import shutil
import tempfile
import time
import uuid
import zipfile
from functools import lru_cache
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# Optional third-party libs (import defensively)
try:
    import bleach  # type: ignore
except Exception:
    bleach = None

try:
    import magic  # python-magic
except Exception:
    magic = None

try:
    from lxml import etree  # type: ignore
except Exception:
    etree = None

try:
    import rarfile  # type: ignore
except Exception:
    rarfile = None

try:
    from PIL import Image  # type: ignore
except Exception:
    Image = None

# Expose explicit flags so tests can monkeypatch feature availability
BLEACH_AVAILABLE = bool(bleach)
MAGIC_AVAILABLE = bool(magic)
LXML_AVAILABLE = etree is not None

# Django exceptions / helpers or lightweight substitutes for tests
try:
    from django.core.exceptions import ValidationError, ImproperlyConfigured  # type: ignore
    from django.core.cache import cache  # type: ignore
    from django.core.files.uploadedfile import (
        InMemoryUploadedFile,
        TemporaryUploadedFile,
        UploadedFile,
    )  # type: ignore
    from asgiref.sync import sync_to_async  # type: ignore
except Exception:

    class ValidationError(Exception):
        pass

    class ImproperlyConfigured(Exception):
        pass

    cache = None
    InMemoryUploadedFile = object
    TemporaryUploadedFile = object
    UploadedFile = io.BytesIO

    def sync_to_async(fn):
        return fn


# -------------------------
# Safe, live settings accessor
# -------------------------
def _safe_setting(name: str, default):
    """Return django.conf.settings.NAME or default without raising when
    settings are not configured. Re-reads settings on every call (rather
    than caching at import time) so `override_settings` and any settings
    configured after this module first imports actually take effect."""
    sentinel = object()
    try:
        from django.conf import settings as _settings  # type: ignore
        # Never initialize LazySettings from an SDK imported by settings.py.
        # That would capture a partially executed service configuration.
        if not _settings.configured:
            return os.environ.get(name, default)
        configured = getattr(_settings, name, sentinel)
        if configured is not sentinel:
            return configured
    except Exception:
        pass
    return os.environ.get(name, default)


_CFG_DEFAULTS: Dict[str, Any] = {
    "ARCHIVE_MAX_FILES": 1000,
    "ARCHIVE_MAX_TOTAL_UNCOMPRESSED": 500 * 1024 * 1024,
    "MAGIC_DETECT_BYTES": 2048,
    "STREAM_WRAP_MAX_BYTES": 50 * 1024 * 1024,
    "TEXT_MAX_LENGTH": 200_000,
    "MAX_FILES_PER_REQUEST": 50,
    "MAX_TOTAL_UPLOAD_BYTES": 250 * 1024 * 1024,
    "MEDIA_LIMIT_MODEL_PATH": "mt_media_sdk.models.MediaLimit",
    "MEDIA_LIMIT_NEGATIVE_CACHE_SECONDS": 30,
    "CLAMAV_CIRCUIT_BREAKER_SECONDS": 15,
}


def _cfg(name: str):
    if name == "TEMP_UPLOAD_DIR":
        return _safe_setting(name, tempfile.gettempdir())
    return _safe_setting(name, _CFG_DEFAULTS[name])


# -------------------------
# Configuration / constants (kept importable for backward compatibility;
# internal logic always calls _cfg(), not these frozen copies)
# -------------------------
BLOCKED_ARCHIVE_EXTS = {".exe", ".dll", ".bat", ".cmd", ".sh", ".js", ".jar", ".scr"}
BLOCKED_MIME_TYPES = {
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-sh",
    "application/x-bat",
}

# Markup/script-injection patterns only - see mt_media_sdk.security.sanitizer's
# changelog for why the old blanket SQL-keyword pattern was split out into
# its own, less false-positive-prone heuristic below.
BLACKLISTED_PATTERNS = [
    re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"(on\w+)\s*=", re.IGNORECASE),
    re.compile(r"(javascript:|data:text/html|vbscript:)", re.IGNORECASE),
]
_SQL_KEYWORDS_RE = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC|MERGE|TRUNCATE)\b",
    re.IGNORECASE,
)
# See mt_media_sdk.security.sanitizer's copy of this logic for the full rationale:
# bare quotes/semicolons only count alongside an actual keyword (to avoid
# flagging contractions like "I'll DELETE this; let's talk"); the
# tautology/comment-breakout shapes are distinctive enough to trigger on
# their own even without a keyword ('` OR '1'='1'`, `admin'--`).
_SQL_KEYWORD_COMPANION_RE = re.compile(r"(--|;|/\*|\*/)")
_SQL_TAUTOLOGY_RE = re.compile(
    r"""['"]\s*(OR|AND)\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?""", re.IGNORECASE
)
_SQL_COMMENT_BREAKOUT_RE = re.compile(r"""['"]\s*(--|#)""")


def _looks_like_sql_injection(text: str) -> bool:
    if _SQL_TAUTOLOGY_RE.search(text) or _SQL_COMMENT_BREAKOUT_RE.search(text):
        return True
    return bool(_SQL_KEYWORDS_RE.search(text) and _SQL_KEYWORD_COMPANION_RE.search(text))

ALLOWED_TAGS = ["b", "i", "u", "strong", "em", "a", "p", "ul", "ol", "li", "br", "span"]
ALLOWED_ATTRS = {"a": ["href", "title", "rel"], "span": ["class"]}

ARCHIVE_MAX_FILES = _cfg("ARCHIVE_MAX_FILES")
ARCHIVE_MAX_TOTAL_UNCOMPRESSED = _cfg("ARCHIVE_MAX_TOTAL_UNCOMPRESSED")
MAGIC_DETECT_BYTES = _cfg("MAGIC_DETECT_BYTES")
STREAM_WRAP_MAX_BYTES = _cfg("STREAM_WRAP_MAX_BYTES")
TEMP_UPLOAD_DIR = _cfg("TEMP_UPLOAD_DIR")
FILE_PERM = 0o600  # temporary files written will be set to this permission for privacy
_CLAMD_CONNECT_RETRIES = 2
_CLAMD_CONNECT_BACKOFF = 0.2  # seconds

# ---------- Optional ClamAV (defensive) ----------
try:
    from clamd import (
        ClamdNetworkSocket,
        ClamdUnixSocket,
        ConnectionError as ClamConnectionError,
        BufferTooLongError,
    )  # type: ignore

    CLAMD_IMPORT_AVAILABLE = True
except Exception:
    ClamdNetworkSocket = None
    ClamdUnixSocket = None

    class ClamConnectionError(Exception):
        pass

    class BufferTooLongError(Exception):
        pass

    CLAMD_IMPORT_AVAILABLE = False


def _make_clamd_client_once(use_tcp: bool, host: str, port: int, unix_socket: str):
    """Instantiate a fresh client. Called inside threads to avoid network/
    socket operations in the event loop."""
    try:
        if use_tcp:
            return ClamdNetworkSocket(host=host, port=port)
        return ClamdUnixSocket(path=unix_socket)
    except Exception:
        return None


def _safe_close(client) -> None:
    try:
        close = getattr(client, "close", None)
        if callable(close):
            close()
    except Exception:
        pass


# ---------- Local helper wrappers ----------
# Prefer to import real helper functions from .sanitizer when available; otherwise provide safe fallbacks.
try:
    from .sanitizer import (
        get_mime_type as _sanitizer_get_mime_type,
        sanitize_svg as _sanitizer_sanitize_svg,
        validate_text as _sanitizer_validate_text,
        scan_archive as _sanitizer_scan_archive,
        stream_to_seekable as _sanitizer_stream_to_seekable,
        contains_office_macro as _sanitizer_contains_office_macro,
        is_supported_image as _sanitizer_is_supported_image,
    )  # type: ignore
except Exception:
    _sanitizer_get_mime_type = None
    _sanitizer_sanitize_svg = None
    _sanitizer_validate_text = None
    _sanitizer_scan_archive = None
    _sanitizer_stream_to_seekable = None
    _sanitizer_contains_office_macro = None
    _sanitizer_is_supported_image = None


def get_mime_type(file_obj: Any, strict_extension_check: bool = False) -> str:
    """
    Robust mime type detection:
      - Prefer python-magic if available
      - Fallback to mimetypes.guess_type(file_name)
    For non-seekable streams we only use the sample bytes (we don't replace caller's stream).
    """
    if _sanitizer_get_mime_type:
        try:
            return _sanitizer_get_mime_type(file_obj, strict_extension_check=strict_extension_check)
        except Exception:
            logger.debug("sanitizer.get_mime_type failed, using fallback.")

    sample = b""
    pos = None
    try:
        pos = file_obj.tell()
    except Exception:
        pos = None

    try:
        sample = file_obj.read(_cfg("MAGIC_DETECT_BYTES"))
        if isinstance(sample, str):
            sample = sample.encode("utf-8")
    except Exception:
        sample = b""

    try:
        if pos is not None:
            file_obj.seek(pos)
        else:
            file_obj.seek(0)
    except Exception:
        pass

    if magic is not None:
        try:
            m = magic.Magic(mime=True)
            detected = m.from_buffer(sample or b"")
            if detected:
                return detected
        except Exception:
            logger.debug("python-magic failed; falling back to extension detection.")

    file_name = getattr(file_obj, "name", "") or ""
    guessed, _ = mimetypes.guess_type(file_name)
    return guessed or "application/octet-stream"


def sanitize_svg(file_like: Any) -> bytes:
    """Sanitize SVG using lxml when available. Delegates to
    mt_media_sdk.security.sanitizer.sanitize_svg when importable (preferred: it
    has the DOCTYPE/entity + dangerous-CSS hardening)."""
    if _sanitizer_sanitize_svg:
        return _sanitizer_sanitize_svg(file_like)

    if etree is None:
        raise ValidationError("Server missing XML parser for SVG sanitization.")

    if isinstance(file_like, bytes):
        raw = file_like
    else:
        try:
            file_like.seek(0)
        except Exception:
            pass
        raw = file_like.read()
        if isinstance(raw, str):
            raw = raw.encode("utf-8")

    if not raw:
        raise ValidationError("Empty SVG content")
    if re.search(rb"<!(DOCTYPE|ENTITY)", raw, re.IGNORECASE):
        raise ValidationError("SVG contains a DOCTYPE/ENTITY declaration, which is not allowed.")

    parser = etree.XMLParser(
        resolve_entities=False, no_network=True, remove_comments=True, recover=True, huge_tree=False,
    )
    try:
        root = etree.fromstring(raw, parser=parser)
    except Exception as e:
        logger.debug("SVG parse failed: %s", e)
        raise ValidationError("Malformed SVG")

    dangerous = {"script", "foreignobject", "iframe", "object", "embed"}
    for node in list(root.iter()):
        try:
            name = etree.QName(node.tag).localname.lower()
        except Exception:
            name = str(node.tag).lower()
        if name in dangerous:
            parent = node.getparent()
            if parent is not None:
                parent.remove(node)

    for el in root.iter():
        for attr in list(el.attrib):
            local = attr.split("}")[-1].lower()
            if local.startswith("on"):
                el.attrib.pop(attr, None)
                continue
            if local in ("href", "xlink:href"):
                val = el.attrib.get(attr, "")
                if isinstance(val, str) and val.strip().lower().startswith(("javascript:", "data:")):
                    el.attrib.pop(attr, None)

    out = etree.tostring(root, encoding="utf-8", xml_declaration=True)
    return out


def validate_text(text: Optional[str], field_name: str = "text", *, max_length: Optional[int] = None) -> str:
    """
    Sanitize text input. Delegates to mt_media_sdk.security.sanitizer.validate_text
    when importable (preferred - see that module's changelog for the
    smarter SQL heuristic and length cap). This local copy mirrors the
    same behaviour for standalone use when sanitizer.py isn't importable:
      - Remove blacklisted (script/on*=/javascript:) patterns
      - Reject content only when a SQL keyword *and* an injection-shaped
        companion token both appear, rather than on a bare keyword
      - Use bleach when available using ALLOWED_TAGS/ALLOWED_ATTRS
      - Fallback to html.escape
    """
    if _sanitizer_validate_text:
        try:
            return _sanitizer_validate_text(text, field_name, max_length=max_length)
        except ValidationError:
            raise
        except Exception:
            logger.debug("sanitizer.validate_text failed; using local fallback.")

    if text is None:
        return ""
    if not isinstance(text, str):
        raise ValidationError(f"Expected text for {field_name}")

    limit = max_length if max_length is not None else _cfg("TEXT_MAX_LENGTH")
    if limit and len(text) > limit:
        raise ValidationError(f"{field_name} exceeds the maximum allowed length of {limit} characters.")

    if _looks_like_sql_injection(text):
        logger.warning("validate_text: rejected suspected SQL-injection-shaped input (field=%s)", field_name)
        return ""

    cleaned = text
    for patt in BLACKLISTED_PATTERNS:
        cleaned = patt.sub("", cleaned)

    if bleach is not None:
        try:
            return bleach.clean(cleaned, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True).strip()
        except Exception:
            logger.debug("bleach.clean failed; escaping instead.")

    return html.escape(cleaned).strip()


# -------------------------
# Small helpers: safe filename, atomic temp writing
# -------------------------
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def safe_filename(name: str, max_len: int = 100) -> str:
    """Produce a filesystem-safe filename (ASCII-ish). Replace unsafe chars and limit length."""
    if not name:
        return uuid.uuid4().hex
    base = os.path.basename(name)
    while base.startswith("."):
        base = base[1:]
    safe = _SAFE_FILENAME_RE.sub("_", base)
    return safe[:max_len] or uuid.uuid4().hex


def _atomic_write_bytes(target_dir: str, final_name: str, data: bytes) -> str:
    """Write bytes to a temp file in target_dir then atomically move to final path.
    Returns final path. Sets restrictive permissions on final file."""
    os.makedirs(target_dir, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(prefix="upload-", dir=target_dir, delete=False)
    tmp_path = tmp.name
    try:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
    finally:
        tmp.close()

    final_path = os.path.join(target_dir, final_name)
    os.replace(tmp_path, final_path)
    try:
        os.chmod(final_path, FILE_PERM)
    except Exception:
        logger.debug("Could not set file permissions for %s", final_path)
    return final_path


# -------------------------
# Archive / Zip safety checks (local fallback only - prefer
# mt_media_sdk.security.sanitizer.scan_archive, which also covers RAR/TAR/7z)
# -------------------------
def _safe_extract_check_zip(zip_bytes: bytes) -> None:
    """
    Local fallback archive check, used only when mt_media_sdk.security.sanitizer
    isn't importable. Validates zip content without extracting to disk: no
    password protection, no zip-slip paths, bounded file count/size, a
    compression-ratio bomb heuristic, and a blocked-extension/nested-
    archive check.
    """
    try:
        with zipfile.ZipFile(BytesIO(zip_bytes), "r") as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1:
                    raise ValidationError("Password-protected archives are not allowed.")

            names = zf.namelist()
            max_files = _cfg("ARCHIVE_MAX_FILES")
            max_total = _cfg("ARCHIVE_MAX_TOTAL_UNCOMPRESSED")
            if len(names) > max_files:
                raise ValidationError(f"Archive contains too many files ({len(names)}).")

            total_uncompressed = 0
            for info in zf.infolist():
                fname = info.filename
                if fname.startswith(("/", "\\")) or ".." in fname.replace("\\", "/"):
                    raise ValidationError("Archive contains invalid filename.")
                lower = fname.lower()
                if any(lower.endswith(ext) for ext in BLOCKED_ARCHIVE_EXTS):
                    raise ValidationError(f"Blocked file inside archive: {fname}")
                if lower.endswith((".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz")):
                    raise ValidationError(f"Nested archive detected: {fname}")

                if info.compress_size and info.file_size / max(info.compress_size, 1) > 100:
                    raise ValidationError(f"Suspicious compression ratio in {fname}; possible archive bomb.")

                total_uncompressed += info.file_size
                if total_uncompressed > max_total:
                    raise ValidationError("Archive total uncompressed size exceeds allowed limit.")
    except zipfile.BadZipFile:
        raise ValidationError("Invalid or corrupt ZIP archive.")
    except ValidationError:
        raise
    except Exception as e:
        logger.exception("Archive validation failed: %s", e)
        raise ValidationError("Archive validation failed.")


# -------------------------
# Small file helpers
# -------------------------
def _get_file_length(file_obj: UploadedFile | BytesIO) -> int:
    """Return reliable length; non-destructive attempt to restore file pointer."""
    try:
        if hasattr(file_obj, "size"):
            return int(file_obj.size or 0)
        pos = None
        try:
            pos = file_obj.tell()
        except Exception:
            pos = None
        file_obj.seek(0, os.SEEK_END)
        length = file_obj.tell()
        if pos is not None:
            try:
                file_obj.seek(pos)
            except Exception:
                pass
        else:
            try:
                file_obj.seek(0)
            except Exception:
                pass
        return int(length)
    except Exception:
        logger.debug("Could not determine file length for %s", getattr(file_obj, "name", "<unknown>"))
        return 0


def _read_all_bytes(file_obj: UploadedFile | BytesIO, max_bytes: Optional[int] = None) -> bytes:
    """
    Read whole content without assuming text; attempts to restore the
    pointer where possible. When max_bytes is given, reads in bounded
    chunks and raises ValidationError if the stream exceeds it, instead of
    unconditionally buffering an arbitrary (possibly attacker-controlled)
    amount of data into memory.
    """
    try:
        if hasattr(file_obj, "read"):
            try:
                file_obj.seek(0)
            except Exception:
                pass

            if max_bytes is None:
                data = file_obj.read()
            else:
                chunks: List[bytes] = []
                total = 0
                while True:
                    chunk = file_obj.read(1024 * 1024)
                    if not chunk:
                        break
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8")
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValidationError(f"Content exceeds the {max_bytes}-byte read limit.")
                    chunks.append(chunk)
                data = b"".join(chunks)

            if isinstance(data, str):
                data = data.encode("utf-8")
            try:
                file_obj.seek(0)
            except Exception:
                pass
            return data or b""
    except ValidationError:
        raise
    except Exception:
        logger.exception("Failed to read bytes from file-like object.")
    return b""


def _is_archive_mime(mime: str) -> bool:
    return mime in DEFAULT_MIME_TYPES.get("archive", [])


def _contains_macro(buffer: bytes) -> bool:
    """Delegates to sanitizer.contains_office_macro when available; falls
    back to the same zip-inspection logic inline otherwise."""
    if _sanitizer_contains_office_macro:
        try:
            return _sanitizer_contains_office_macro(buffer)
        except Exception:
            return False
    try:
        with zipfile.ZipFile(BytesIO(buffer)) as zf:
            return any(n.lower().endswith("vbaproject.bin") for n in zf.namelist())
    except Exception:
        return False


# ---------- Default MIME / size maps ----------
DEFAULT_MAX_FILE_SIZES = {
    "image": 10 * 1024 * 1024,
    "audio": 10 * 1024 * 1024,
    "video": 50 * 1024 * 1024,
    "text": 5 * 1024 * 1024,
    "document": 10 * 1024 * 1024,
    "archive": 20 * 1024 * 1024,
}

DEFAULT_MIME_TYPES = {
    "image": [
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/bmp",
        "image/svg+xml",
        "image/x-icon",
    ],
    "audio": [
        "audio/mpeg",
        "audio/wav",
        "audio/ogg",
        "audio/aac",
        "audio/flac",
        "audio/x-m4a",
    ],
    "video": [
        "video/mp4",
        "video/webm",
        "video/quicktime",
        "video/x-msvideo",
        "video/x-matroska",
    ],
    "text": ["text/plain", "text/csv", "text/xml", "text/markdown", "application/json"],
    "document": [
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ],
    "archive": [
        "application/zip",
        "application/x-tar",
        "application/gzip",
        "application/x-7z-compressed",
    ],
}

OFFICE_MACRO_MIME_TYPES = {
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
}


# -------------------------
# Main validator
# -------------------------
class CustomValidator:
    DEFAULT_MAX_FILE_SIZES = DEFAULT_MAX_FILE_SIZES
    DEFAULT_MIME_TYPES = DEFAULT_MIME_TYPES
    OFFICE_MACRO_MIME_TYPES = OFFICE_MACRO_MIME_TYPES

    # In-process circuit breaker: once a MediaLimit lookup fails, stop
    # retrying it (and hitting a possibly-broken DB) for a short window.
    _media_limit_unavailable_until: float = 0.0

    @staticmethod
    @lru_cache(maxsize=8)
    def _resolve_model_class(dotted_path: str):
        """Resolve a 'module.Class' string to the class object. Cached
        since the import path never changes at runtime; tries Django's
        import_string first, then falls back to plain importlib so this
        still works in non-Django test contexts."""
        try:
            from django.utils.module_loading import import_string  # type: ignore
            return import_string(dotted_path)
        except Exception:
            try:
                module_path, _, cls_name = dotted_path.rpartition(".")
                mod = importlib.import_module(module_path)
                return getattr(mod, cls_name)
            except Exception:
                return None

    @classmethod
    async def get_max_file_size(cls, media_type: str) -> int:
        """Resolve configured limit (cache/model) then fallback to defaults."""
        cache_key = f"media_limit_{media_type}"
        from asgiref.sync import sync_to_async

        try:
            if cache is not None:
                cached = await sync_to_async(cache.get, thread_sensitive=True)(cache_key)
                if cached:
                    return int(cached)
        except Exception:
            logger.debug("Cache unavailable or error reading cache for media limits.", exc_info=True)

        now = time.monotonic()
        if now < cls._media_limit_unavailable_until:
            return cls.DEFAULT_MAX_FILE_SIZES.get(media_type, 0)

        try:
            model_path = _safe_setting("MEDIA_LIMIT_MODEL_PATH", _CFG_DEFAULTS["MEDIA_LIMIT_MODEL_PATH"])
            MediaLimit = cls._resolve_model_class(model_path)
            if MediaLimit is None:
                raise ImportError(f"Could not resolve {model_path}")

            # Django ORM connections are thread-affine. asyncio.to_thread()
            # uses arbitrary pool workers and can strand/lock a connection
            # when this validator is entered through async_to_sync from a
            # request thread. Use asgiref's thread-sensitive bridge so the
            # query runs in Django's designated sync thread.
            limits = await sync_to_async(
                lambda: MediaLimit.objects.first(), thread_sensitive=True
            )()
            if limits and hasattr(limits, media_type):
                val = int(getattr(limits, media_type))
                try:
                    if cache is not None:
                        await sync_to_async(cache.set, thread_sensitive=True)(
                            cache_key, val, 24 * 3600
                        )
                except Exception:
                    logger.debug("Failed to populate cache for %s", cache_key, exc_info=True)
                return val
        except Exception:
            backoff = float(_cfg("MEDIA_LIMIT_NEGATIVE_CACHE_SECONDS"))
            logger.debug(
                "MediaLimit model not available or error reading it; backing off for %ss.",
                backoff, exc_info=True,
            )
            cls._media_limit_unavailable_until = time.monotonic() + backoff

        return cls.DEFAULT_MAX_FILE_SIZES.get(media_type, 0)

    @classmethod
    async def validate_file(cls, file_obj: UploadedFile | BytesIO, media_type: str) -> UploadedFile | BytesIO:
        """
        Validate file-like object and return sanitized/converted file-like.
        - rejects empty files
        - enforces size limits
        - MIME detection using get_mime_type(), rejecting BLOCKED_MIME_TYPES outright
        - image validity + decompression-bomb pixel cap
        - SVG sanitization
        - Archive validation
        - Office macro heuristic (catches a mis-labeled .xlsm etc.)
        - Best-effort ClamAV scanning (if enabled)
        - Converts large InMemoryUploadedFile -> TemporaryUploadedFile safely
        """
        try:
            if file_obj is None:
                raise ValidationError("No file provided.")

            if _sanitizer_stream_to_seekable:
                try:
                    file_obj = await asyncio.to_thread(_sanitizer_stream_to_seekable, file_obj)
                except ValidationError:
                    raise
                except Exception:
                    logger.debug("stream_to_seekable normalization failed; continuing with original object.")

            size = _get_file_length(file_obj)
            if size == 0:
                raise ValidationError("File is empty.")

            max_size = await cls.get_max_file_size(media_type)
            if max_size and size > max_size:
                raise ValidationError(f"File too large. Max allowed is {max_size} bytes.")

            try:
                mime_type = get_mime_type(file_obj)
            except Exception:
                buffer = _read_all_bytes(file_obj, max_bytes=max_size or None)
                if not buffer:
                    raise ValidationError("Could not read uploaded file for MIME detection.")
                mime_type = get_mime_type(BytesIO(buffer))

            if not mime_type:
                raise ValidationError("Could not determine MIME type for uploaded file.")
            if mime_type in BLOCKED_MIME_TYPES:
                raise ValidationError(f"File type is not permitted: {mime_type}.")
            if mime_type in cls.OFFICE_MACRO_MIME_TYPES:
                raise ValidationError("Macro-enabled Office files are not allowed.")

            allowed = cls.DEFAULT_MIME_TYPES.get(media_type, [])
            if mime_type not in allowed:
                raise ValidationError(f"Unsupported media type: {mime_type}.")

            # Several checks below need the *whole* file; compute the
            # buffer once, lazily, and reuse it instead of re-reading the
            # stream from scratch for each one.
            shared_buffer: Optional[bytes] = None

            def _buffer() -> bytes:
                nonlocal shared_buffer
                if shared_buffer is None:
                    shared_buffer = _read_all_bytes(file_obj, max_bytes=max_size or None)
                return shared_buffer

            # Office macro heuristic: catches a macro-enabled file renamed
            # to a "safe" extension/mime that slipped past the check above.
            if media_type == "document" and mime_type in (
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ):
                try:
                    if await asyncio.to_thread(_contains_macro, _buffer()):
                        raise ValidationError("Macro-enabled Office files are not allowed.")
                except ValidationError:
                    raise
                except Exception:
                    logger.debug("Macro heuristic check failed; continuing.", exc_info=True)

            # Image validation: reject corrupt files and decompression bombs.
            if media_type == "image" and mime_type != "image/svg+xml" and Image is not None:
                checker = _sanitizer_is_supported_image or is_supported_image
                try:
                    ok = await asyncio.to_thread(checker, BytesIO(_buffer()))
                    if not ok:
                        raise ValidationError("File does not appear to be a valid image.")
                except ValidationError:
                    raise
                except Exception:
                    logger.debug("Image verification failed unexpectedly; continuing without it.", exc_info=True)

            # SVG sanitization
            if mime_type == "image/svg+xml":
                try:
                    svg_bytes = await asyncio.to_thread(sanitize_svg, _buffer())
                except ValidationError:
                    raise
                except Exception:
                    logger.exception("SVG sanitization failed.")
                    raise ValidationError("SVG sanitization failed.")
                if not svg_bytes:
                    raise ValidationError("SVG sanitization removed all content; nothing safe to keep.")
                file_obj = BytesIO(svg_bytes)
                file_obj.name = getattr(file_obj, "name", "sanitized.svg")
                shared_buffer = svg_bytes  # keep downstream checks (ClamAV) in sync

            # Archive validation
            if _is_archive_mime(mime_type):
                try:
                    if _sanitizer_scan_archive:
                        await asyncio.to_thread(_sanitizer_scan_archive, BytesIO(_buffer()))
                    else:
                        _safe_extract_check_zip(_buffer())
                except ValidationError:
                    raise
                file_obj = BytesIO(_buffer())
                file_obj.name = getattr(file_obj, "name", f"archive-{uuid.uuid4().hex}.zip")

            # Optional ClamAV scanning (best-effort)
            try:
                if os.getenv("CLAMAV_ENABLED", "false").lower() == "true" and CLAMD_IMPORT_AVAILABLE:
                    buffer = _buffer()
                    if buffer:
                        scan = await _clamav_instream_scan(buffer)
                        if scan:
                            for _, v in scan.items():
                                if isinstance(v, tuple) and v and v[0] == "FOUND":
                                    raise ValidationError("Uploaded file is infected.")
                    if hasattr(file_obj, "seek"):
                        try:
                            file_obj.seek(0)
                        except Exception:
                            pass
            except ValidationError:
                raise
            except Exception:
                logger.debug("ClamAV scan failed or unavailable; continuing (scan inconclusive).")

            # Convert large InMemoryUploadedFile -> TemporaryUploadedFile
            if isinstance(file_obj, InMemoryUploadedFile):
                try:
                    from django.conf import settings as djsettings  # type: ignore
                    memory_limit = getattr(djsettings, "FILE_UPLOAD_MAX_MEMORY_SIZE", 2621440)
                except Exception:
                    memory_limit = 2621440

                try:
                    file_size = int(getattr(file_obj, "size", 0))
                except Exception:
                    file_size = _get_file_length(file_obj)

                if file_size > memory_limit:
                    data = _read_all_bytes(file_obj)
                    final_name = (
                        f"{uuid.uuid4().hex}_"
                        f"{safe_filename(getattr(file_obj, 'name', 'upload'))}"
                    )
                    try:
                        temporary = TemporaryUploadedFile(
                            final_name,
                            getattr(file_obj, "content_type", "application/octet-stream"),
                            len(data),
                            getattr(file_obj, "charset", None),
                        )
                        temporary.write(data)
                        temporary.seek(0)
                        return temporary
                    except Exception as exc:
                        raise ValidationError(
                            "Unable to create a secure temporary upload."
                        ) from exc

            if not hasattr(file_obj, "name"):
                file_obj.name = f"upload-{uuid.uuid4().hex}"
            else:
                file_obj.name = safe_filename(file_obj.name)

            return file_obj

        except ValidationError:
            raise
        except Exception as exc:
            logger.exception("Unexpected error validating file: %s", exc)
            raise ValidationError("File validation failed.")

    @staticmethod
    async def validate_text(text: str) -> str:
        """Sanitize text and optionally (best-effort) run ClamAV file scan of the text blob."""
        if text is None:
            raise ValidationError("No text provided.")
        try:
            sanitized = await asyncio.to_thread(validate_text, text, "text")
        except ValidationError:
            raise
        except Exception:
            logger.exception("Text validation failed.")
            raise ValidationError("Text validation failed.")

        try:
            if os.getenv("CLAMAV_ENABLED", "false").lower() == "true" and CLAMD_IMPORT_AVAILABLE:
                with tempfile.NamedTemporaryFile(mode="w+b", delete=False) as tmp:
                    try:
                        tmp.write(sanitized.encode("utf-8"))
                        tmp.flush()
                        tmp_name = tmp.name
                    finally:
                        tmp.close()
                try:
                    scan = await _clamav_file_scan(tmp_name)
                    if scan:
                        for _, v in (scan.items() if isinstance(scan, dict) else []):
                            if isinstance(v, tuple) and v and v[0] == "FOUND":
                                raise ValidationError("Text input appears infected.")
                finally:
                    try:
                        os.unlink(tmp_name)
                    except Exception:
                        pass
        except ValidationError:
            raise
        except Exception:
            logger.debug("ClamAV text scan skipped or failed; continuing.")

        return sanitized


def is_supported_image(file_obj: Any) -> bool:
    """Local fallback used only when mt_media_sdk.security.sanitizer isn't
    importable. Same decompression-bomb-aware behaviour: verify via
    Pillow, rejecting anything over IMAGE_MAX_PIXELS before any decode."""
    if Image is None:
        return False
    try:
        img = Image.open(file_obj)
        max_pixels = int(_safe_setting("IMAGE_MAX_PIXELS", 89_478_485))
        w, h = img.size
        if max_pixels and w * h > max_pixels:
            logger.warning("Rejected image %sx%s: exceeds pixel cap", w, h)
            return False
        img.verify()
        try:
            file_obj.seek(0)
        except Exception:
            pass
        return True
    except Exception:
        return False


# -------------------------
# Auxiliary ClamAV helpers (re-used above)
# -------------------------
_clamav_circuit_open_until: float = 0.0


def get_clamav_client() -> Optional[Any]:
    """
    Return a fresh/healthy clamd client or None.
    - Avoids returning a long-lived socket object that may be shared unsafely.
    - Retries a couple of times to tolerate transient clamd restarts.
    - Backs off via a short in-process circuit breaker after every attempt
      fails, so a clamd outage doesn't cost a slow connect+ping sequence on
      every single scan call during the outage.
    """
    global _clamav_circuit_open_until
    try:
        if os.getenv("CLAMAV_ENABLED", "false").lower() != "true" or not CLAMD_IMPORT_AVAILABLE:
            return None

        if time.monotonic() < _clamav_circuit_open_until:
            return None

        _use_tcp = os.getenv("CLAMAV_USE_TCP", "false").lower() == "true"
        host = os.getenv("CLAMAV_TCP_ADDR", "127.0.0.1")
        port = int(os.getenv("CLAMAV_TCP_PORT", 3310))
        unix_socket = os.getenv("CLAMAV_UNIX_SOCKET", "/var/run/clamav/clamd.ctl")

        for _attempt in range(_CLAMD_CONNECT_RETRIES):
            client = _make_clamd_client_once(_use_tcp, host, port, unix_socket)
            if not client:
                time.sleep(_CLAMD_CONNECT_BACKOFF)
                continue
            ping = getattr(client, "ping", None)
            if callable(ping):
                try:
                    ping()
                    return client
                except Exception:
                    _safe_close(client)
                    time.sleep(_CLAMD_CONNECT_BACKOFF)
                    continue
            return client

        breaker_seconds = float(_cfg("CLAMAV_CIRCUIT_BREAKER_SECONDS"))
        _clamav_circuit_open_until = time.monotonic() + breaker_seconds
    except Exception:
        logger.debug("Could not create a healthy ClamAV client.", exc_info=True)
    return None


async def _clamav_instream_scan(buffer: bytes) -> Optional[Dict[str, Any]]:
    """Instream scan a bytes buffer; if buffer is too large, fallback to
    writing to a tempfile and using file-scan. Runs blocking code in a
    thread pool."""
    if os.getenv("CLAMAV_ENABLED", "false").lower() != "true" or not CLAMD_IMPORT_AVAILABLE:
        return None
    if not buffer:
        return None

    if len(buffer) > _cfg("STREAM_WRAP_MAX_BYTES"):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(buffer)
            tmp.flush()
            tmp_path = tmp.name
        try:
            return await _clamav_file_scan(tmp_path)
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    def _scan_in_thread():
        client = get_clamav_client()
        if not client:
            return None
        try:
            instream = getattr(client, "instream", None)
            if not callable(instream):
                return None
            try:
                return instream(BytesIO(buffer))
            except BufferTooLongError:
                return None
            except Exception:
                logger.debug("ClamAV instream exception", exc_info=True)
                return None
        finally:
            _safe_close(client)

    res = await asyncio.to_thread(_scan_in_thread)
    if res is None and len(buffer) <= _cfg("STREAM_WRAP_MAX_BYTES"):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(buffer)
            tmp.flush()
            tmp_path = tmp.name
        try:
            return await _clamav_file_scan(tmp_path)
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
    return res


async def _clamav_file_scan(path: str) -> Optional[Dict[str, Any]]:
    """Scan a file path with clamd. Runs blocking client calls in a thread
    pool. Creates and closes a client per call."""
    if os.getenv("CLAMAV_ENABLED", "false").lower() != "true" or not CLAMD_IMPORT_AVAILABLE:
        return None

    def _scan_in_thread():
        client = get_clamav_client()
        if not client:
            return None
        try:
            scan = getattr(client, "scan", None)
            if not callable(scan):
                return None
            return scan(path)
        except Exception:
            logger.debug("ClamAV file scan error", exc_info=True)
            return None
        finally:
            _safe_close(client)

    return await asyncio.to_thread(_scan_in_thread)


# -------------------------
# Async bleach wrapper used elsewhere
# -------------------------
async def awaitable_bleach_clean(value: Any) -> str:
    """Run bleach.clean in a threadpool (async-safe) with a tight allowlist
    and fallback. Length-capped like validate_text, for the same reason
    (defense against regex/processing cost on unbounded input)."""

    def _clean(v):
        s = v if isinstance(v, str) else str(v)
        limit = _cfg("TEXT_MAX_LENGTH")
        if limit and len(s) > limit:
            raise ValidationError(f"Input exceeds the maximum allowed length of {limit} characters.")
        try:
            if BLEACH_AVAILABLE and bleach is not None:
                return bleach.clean(s, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
            return html.escape(s)
        except ValidationError:
            raise
        except Exception:
            return s

    return await asyncio.to_thread(_clean, value)


class ValidatorHandler:
    """
    Facade used by views/tests to extract files & texts and run validations.
    - extract_media_files: classifies files from request.FILES (handling
      multi-file fields correctly) and *collects* string-valued text
      fields - it no longer sanitizes them itself, to avoid the
      double-sanitization bug described in this module's changelog.
    - validate_media_and_text: the single place text gets sanitized and
      files get validated, persisting validated files to TEMP_UPLOAD_DIR
      and returning a structured results dict used by tests.
    """

    @property
    def max_files_per_request(self) -> int:
        return int(_cfg("MAX_FILES_PER_REQUEST"))

    @property
    def max_total_upload_bytes(self) -> int:
        return int(_cfg("MAX_TOTAL_UPLOAD_BYTES"))

    async def extract_media_files(self, request) -> Tuple[Dict[str, List[UploadedFile]], List[Tuple[str, str]]]:
        media_files: Dict[str, List[UploadedFile]] = {
            "images": [], "videos": [], "audios": [], "documents": [], "archives": [],
        }
        texts: List[Tuple[str, str]] = []
        total_files = 0
        total_bytes = 0

        files_multidict = getattr(request, "FILES", {})
        # Django's MultiValueDict.items() silently returns only the *last*
        # value per key; .lists() returns every value. Plain dicts (tests /
        # non-Django callers) fall back to a single-item list per key.
        if hasattr(files_multidict, "lists"):
            file_iter = files_multidict.lists()
        else:
            file_iter = ((k, [v]) for k, v in dict(files_multidict).items())

        for _key, file_list in file_iter:
            for f in file_list:
                total_files += 1
                if total_files > self.max_files_per_request:
                    raise ValidationError(
                        f"Too many files in one request (max {self.max_files_per_request})."
                    )
                total_bytes += _get_file_length(f)
                if total_bytes > self.max_total_upload_bytes:
                    raise ValidationError(
                        f"Combined upload size exceeds the {self.max_total_upload_bytes}-byte request limit."
                    )
                try:
                    content_type = getattr(f, "content_type", "") or ""
                    if isinstance(content_type, str) and content_type.startswith("image/"):
                        media_files["images"].append(f)
                    elif isinstance(content_type, str) and content_type.startswith("video/"):
                        media_files["videos"].append(f)
                    elif isinstance(content_type, str) and content_type.startswith("audio/"):
                        media_files["audios"].append(f)
                    elif isinstance(content_type, str) and content_type in DEFAULT_MIME_TYPES.get("archive", []):
                        media_files["archives"].append(f)
                    else:
                        media_files["documents"].append(f)
                except Exception:
                    logger.debug("Failed to classify file %s", getattr(f, "name", "<unknown>"))

        data_iter = getattr(request, "data", getattr(request, "POST", {})) or {}
        try:
            items = list(data_iter.items())
        except Exception:
            items = []

        for key, value in items:
            values = value if isinstance(value, (list, tuple)) else [value]
            for v in values:
                if isinstance(v, str):
                    texts.append((key, v))
                else:
                    logger.debug("Skipping non-string field '%s' in text-sanitization pass.", key)

        return media_files, texts

    async def validate_media_and_text(self, request) -> Dict[str, Any]:
        """
        Validate all media & text from a request.
        Returns:
          {
            "images": [...], "videos": [...], "audios": [...], "documents": [...], "archives": [...],
            "texts": [{"field": "...", "content": "..."}], "errors": [{"type": ..., ...}]
          }
        Each successful file entry contains: name, status="success", size, tmp_path
        """
        results: Dict[str, Any] = {
            "images": [], "videos": [], "audios": [], "documents": [], "archives": [],
            "texts": [], "errors": [],
        }

        try:
            media_files, texts = await self.extract_media_files(request)
        except ValidationError as e:
            results["errors"].append({"type": "request", "error": str(e)})
            return results
        except Exception:
            logger.exception("Failed extracting media files.")
            raise ValidationError("Failed to process uploaded content.")

        for field_name, raw_text in texts:
            try:
                cleaned = await CustomValidator.validate_text(raw_text)
                results["texts"].append({"field": field_name, "content": cleaned})
            except ValidationError as e:
                logger.warning("Text validation failed for field '%s': %s", field_name, e)
                results["errors"].append({"type": "text", "field": field_name, "error": str(e)})

        tasks = []
        mapping = []
        for group_name, flist in media_files.items():
            for f in flist:
                media_kind = "archive" if group_name == "archives" else (
                    group_name[:-1] if group_name.endswith("s") else group_name
                )
                tasks.append(CustomValidator.validate_file(f, media_kind))
                mapping.append((group_name, f))

        if tasks:
            validated = await asyncio.gather(*tasks, return_exceptions=True)
            tmp_dir = _cfg("TEMP_UPLOAD_DIR")
            os.makedirs(tmp_dir, exist_ok=True)

            for (group_name, orig_file), val in zip(mapping, validated, strict=False):
                entry: Dict[str, Any] = {"name": getattr(orig_file, "name", None)}
                if isinstance(val, ValidationError):
                    entry.update({"status": "failed", "error": str(val)})
                    results["errors"].append({"type": "file", "file": entry["name"], "error": str(val)})
                elif isinstance(val, Exception):
                    entry.update({"status": "failed", "error": "internal error"})
                    logger.exception("File validation unexpected error for %s", entry["name"])
                    results["errors"].append({"type": "file", "file": entry["name"], "error": "internal error"})
                else:
                    try:
                        final_path = await asyncio.to_thread(self._persist_validated_file, val, tmp_dir)
                        size = _get_file_length(val)
                        entry.update({"status": "success", "size": size, "tmp_path": final_path})
                        results[group_name].append(entry)
                    except Exception:
                        logger.exception("Failed to persist validated file %s", entry.get("name"))
                        results["errors"].append(
                            {"type": "file", "file": entry.get("name"), "error": "failed to persist file"}
                        )

        return results

    @staticmethod
    def _persist_validated_file(val, tmp_dir: str) -> str:
        """
        Move/write the validated file into tmp_dir exactly once. If
        CustomValidator.validate_file already spooled it to disk (a
        TemporaryUploadedFile, or anything exposing temporary_file_path()),
        reuse that path via an atomic move instead of reading the whole
        file back into memory and writing it out again - large media used
        to be written to disk twice.
        """
        safe_name = safe_filename(getattr(val, "name", f"upload-{uuid.uuid4().hex}"))
        tmp_name = f"{uuid.uuid4().hex}_{os.path.basename(safe_name)}"
        final_path = os.path.join(tmp_dir, tmp_name)

        temp_path_fn = getattr(val, "temporary_file_path", None)
        if callable(temp_path_fn):
            try:
                existing_path = temp_path_fn()
                if existing_path and os.path.exists(existing_path):
                    os.makedirs(tmp_dir, exist_ok=True)
                    shutil.move(existing_path, final_path)
                    try:
                        os.chmod(final_path, FILE_PERM)
                    except Exception:
                        pass
                    return final_path
            except Exception:
                logger.debug(
                    "temporary_file_path() reuse failed; falling back to a full read+write.", exc_info=True
                )

        data = _read_all_bytes(val)
        return _atomic_write_bytes(tmp_dir, tmp_name, data)


# ---------------------------------------------------------------------------
# Storage-hook bridges
# ---------------------------------------------------------------------------
# mt_media_sdk.storage.storage_settings defines dotted-path extension points that
# get resolved at Django startup via settings.STORAGE_VIRUS_SCAN_HOOK /
# STORAGE_BUCKET_VALIDATOR / STORAGE_METRICS_SINK / STORAGE_PRIVATE_URL_SIGNER
# / STORAGE_HEALTH_PROBE. This module implements the two that are naturally
# security/validation concerns rather than storage plumbing:
#
#   STORAGE_VIRUS_SCAN_HOOK  = "mt_media_sdk.security.validators:scan_uploaded_file"
#   STORAGE_BUCKET_VALIDATOR = "mt_media_sdk.security.validators:validate_bucket"
#
# (STORAGE_METRICS_SINK and STORAGE_PRIVATE_URL_SIGNER are project-specific
# integrations - wherever your metrics/CDN-signing code actually lives - and
# deliberately aren't implemented here. STORAGE_HEALTH_PROBE lives in
# mt_media_sdk.storage.storage_bootstrap:probe_storage_bucket, alongside the rest
# of the storage-health machinery it needs.)
def scan_uploaded_file(
    file_path,
    *,
    object_key: Optional[str] = None,
    bucket_name: Optional[str] = None,
) -> None:
    """
    Implements mt_media_sdk.storage.storage_settings.VirusScanHook. Called after a
    file has already been persisted to storage (see StorageSettings.
    run_virus_scan_hook), so it scans a real path on disk - deliberately
    synchronous (the Protocol's __call__ returns None, not an awaitable),
    using get_clamav_client() directly rather than the async
    _clamav_file_scan wrapper used elsewhere in this module, since a
    storage hook has no guarantee it's being called from inside an event
    loop.

    Raises ValidationError when the scan finds an infection. Returns
    silently (does not raise) when scanning is disabled entirely
    (CLAMAV_ENABLED != "true") or the scanner is transiently unreachable -
    matching this module's existing best-effort posture elsewhere (see
    CustomValidator.validate_file's ClamAV step) rather than turning a
    scanner outage into a hard storage-layer failure that blocks every
    upload.
    """
    if os.getenv("CLAMAV_ENABLED", "false").lower() != "true" or not CLAMD_IMPORT_AVAILABLE:
        logger.debug("scan_uploaded_file: scanning disabled or clamd unavailable; skipping %s", file_path)
        return

    client = get_clamav_client()
    if not client:
        logger.warning("scan_uploaded_file: ClamAV unavailable; proceeding without scanning %s", file_path)
        return

    try:
        scan_fn = getattr(client, "scan", None)
        result = scan_fn(str(file_path)) if callable(scan_fn) else None
    except Exception as exc:
        logger.warning("scan_uploaded_file: scan errored for %s: %s", file_path, exc, exc_info=True)
        return
    finally:
        _safe_close(client)

    if not result:
        return
    for _scanned_path, outcome in (result.items() if isinstance(result, dict) else []):
        if isinstance(outcome, tuple) and outcome and outcome[0] == "FOUND":
            raise ValidationError(
                f"Uploaded file failed virus scan (object_key={object_key!r}, bucket={bucket_name!r}): {outcome}"
            )


def validate_bucket(bucket, settings) -> None:
    """
    Implements mt_media_sdk.storage.storage_settings.BucketValidator. Runs at
    startup for every remote bucket, *in addition to*
    StorageBucketSpec.validate() (which already covers name/URL/timeout/
    ACL syntax) - this checks cross-cutting policy that depends on
    *environment*, which a bucket-local .validate() can't see on its own:

      * In production, a bucket name containing "test"/"dev"/"staging"/
        "sandbox" almost always means a misconfigured env var pointing
        prod at the wrong bucket, not an intentionally-named production
        bucket - this fails loudly instead of silently uploading real
        user data to a throwaway bucket.
      * A private-urls bucket (media, backups) should have server-side
        encryption configured - StorageBucketSpec.s3_object_parameters()
        defaults to AES256, but this re-confirms it wasn't overridden away.
      * A private-urls bucket using a custom_domain with
        querystring_auth=False gets a URL that's only stamped with
        "?expires=N", not cryptographically signed (see
        StorageSettings._build_url_from_bucket) - safe only if the domain
        itself enforces auth (e.g. CloudFront signed cookies/a private
        edge function). That's a legitimate setup, so this warns rather
        than fails, but it's worth surfacing loudly since it's easy to
        end up here by accident and get a false sense of "signed".
    """
    from mt_media_sdk.storage.storage_settings import StorageValidationError

    name = (bucket.bucket_name or "").lower()
    if getattr(settings, "is_production", False) and any(
        marker in name for marker in ("test", "dev", "staging", "sandbox")
    ):
        raise StorageValidationError(
            f"{bucket.alias} bucket name '{bucket.bucket_name}' looks like a non-production bucket "
            "(contains 'test'/'dev'/'staging'/'sandbox') but the environment is production. "
            "If this really is the intended production bucket, rename it or adjust this check."
        )

    if getattr(bucket, "private_urls", False):
        # s3_object_parameters() applies StorageBucketSpec's own
        # ServerSideEncryption default (AES256) - checking the raw
        # object_parameters field directly would flag every bucket that
        # relies on that default rather than setting SSE explicitly, which
        # is the common case, not an exception.
        get_params = getattr(bucket, "s3_object_parameters", None)
        params = get_params() if callable(get_params) else dict(getattr(bucket, "object_parameters", {}) or {})
        sse = params.get("ServerSideEncryption")
        if sse not in ("AES256", "aws:kms"):
            raise StorageValidationError(
                f"{bucket.alias} is a private-urls bucket but ServerSideEncryption is '{sse}', "
                "not 'AES256' or 'aws:kms'."
            )
        if bucket.custom_domain and not bucket.querystring_auth:
            logger.warning(
                "%s: private_urls bucket serves URLs via custom_domain with querystring_auth=False - "
                "these URLs carry an '?expires=' hint but are NOT cryptographically signed by this "
                "module. Only safe if %s itself enforces access control (e.g. CloudFront signed "
                "cookies). If that's not the case, set querystring_auth=True instead.",
                bucket.alias, bucket.custom_domain,
            )
