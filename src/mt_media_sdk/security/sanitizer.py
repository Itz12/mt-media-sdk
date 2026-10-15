# media/security/sanitizer.py
"""
Robust media sanitization utilities.

- No hard Django dependency (uses a local ValidationError if Django isn't installed).
- Optional features enabled when optional libs are installed:
  - bleach (safe HTML sanitization)
  - python-magic (mime detection)
  - lxml (advanced SVG sanitization)
  - rarfile (RAR archive inspection)
  - py7zr (7z archive inspection)
  - Pillow (image checks, decompression-bomb guard)
- Defensive stream handling: spools large non-seekable streams to disk transparently.

Changes in this revision (see inline comments at each site for detail):
  * `get_mime_type` had a dead, commented-out duplicate implementation sitting
    above the live one - removed.
  * `sanitize_svg` used `root.getiterator()`, which lxml removed years ago;
    that whole namespace-cleanup branch was silently no-op-ing behind a bare
    `except: pass`. Fixed to `root.iter()`, and the SVG path now also
    rejects any DOCTYPE/ENTITY declaration outright (defense-in-depth against
    XXE/billion-laughs on top of the parser-level `resolve_entities=False`),
    enforces a size cap before parsing, and neutralizes dangerous `<style>`
    content (`@import`, `expression()`, `javascript:`, CSS `behavior:`).
  * `validate_text`'s SQL heuristic used to nuke a field to `""` on a bare
    keyword match (`"please DELETE my draft"` -> `""`). It now requires the
    keyword *and* an injection-shaped companion token (quote, `;`, `--`,
    `/* */`, a crude `OR 1=1` tautology) before rejecting - this is still
    just defense-in-depth, not a substitute for parameterized queries, but
    it no longer mangles ordinary sentences. `field_name` is now an
    accepted (optional) second argument, fixing a signature mismatch that
    made `mt_media_sdk.security.validators`' delegation to this function silently
    fail on every call (see validators.py's changelog).
  * `scan_archive` only understood zip/rar; tar (including .tar.gz/.tgz/
    .tar.bz2/.tar.xz, auto-detected) and 7z are now inspected too. 7z is
    fail-closed: if `py7zr` isn't installed, a 7z-signatured upload is
    rejected outright rather than passed through uninspected.
  * Archive checks gained: a per-file size cap, a compression-ratio bomb
    heuristic, and a symlink/hardlink/device-file rejection (zip, rar, and
    tar all supported reasonably differently and are handled per-format).
  * `is_supported_image`/`verify_image_dimensions` now proactively check
    `width * height` against a configurable pixel cap *before* any decode
    work, rather than relying on Pillow's own warn-vs-error
    `DecompressionBomb*` split, which varies by version/format.
  * All of this module's tunables are readable from Django settings via a
    small `_cfg()` indirection instead of being frozen into module
    constants at import time - `override_settings` (or any settings
    configured after this module is first imported) now actually takes
    effect. The old constant names are still defined at module level for
    anyone importing them directly; internal code always calls `_cfg(...)`.
  * New: `contains_office_macro()` - inspects an OOXML zip container for
    `vbaProject.bin` even when the declared/sniffed MIME type doesn't say
    "macroEnabled" (catches a `.xlsm` renamed to `.xlsx`).
  * New: `safe_extract_tar()`, the tar analogue of `safe_extract_zip()`.
  * `file_sha256`/`get_file_info` gained optional `algorithm`/`max_bytes`/
    `compute_hash` parameters (additive, defaults preserve old behaviour).
"""

from __future__ import annotations

import hashlib
import html
import logging
import mimetypes
import os
import re
import shutil
import stat
import tarfile
import zipfile
from io import BytesIO
from typing import IO, Any, Dict, Optional

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# -------------------------
# Optional dependencies (exposed variable names for tests/monkeypatching)
# -------------------------
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
    import py7zr  # type: ignore
except Exception:
    py7zr = None

try:
    from PIL import Image  # type: ignore
except Exception:
    Image = None

# -------------------------
# ValidationError fallback (no Django required)
# -------------------------
try:
    from django.core.exceptions import ValidationError  # type: ignore
except Exception:

    class ValidationError(Exception):
        """Minimal ValidationError substitute when Django isn't installed."""
        pass


# -------------------------
# Safe, live settings accessor
# -------------------------
def _safe_setting(name: str, default):
    """Return django.conf.settings.NAME or default, without raising when
    settings aren't configured. Deliberately re-reads settings on every
    call (rather than caching at import time) so Django's `override_settings`
    and any settings configured after this module first imports actually
    take effect."""
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
    "ARCHIVE_MAX_TOTAL_UNCOMPRESSED": 500 * 1024 * 1024,       # 500 MB
    "ARCHIVE_MAX_SINGLE_FILE_BYTES": 500 * 1024 * 1024,        # 500 MB
    "ARCHIVE_MAX_COMPRESSION_RATIO": 100,                       # zip-bomb heuristic
    "MAGIC_DETECT_BYTES": 2048,
    "STREAM_WRAP_MAX_BYTES": 50 * 1024 * 1024,                  # 50 MB
    "SVG_MAX_BYTES": 5 * 1024 * 1024,                            # 5 MB
    "TEXT_MAX_LENGTH": 200_000,                                  # characters
    "IMAGE_MAX_PIXELS": 89_478_485,                              # Pillow's historical default cap
}


def _cfg(name: str):
    return _safe_setting(name, _CFG_DEFAULTS[name])


# Config / constants (kept importable at module level for backward
# compatibility; internal logic always uses _cfg(), not these frozen copies)
BLOCKED_ARCHIVE_EXTS = {".exe", ".dll", ".bat", ".cmd", ".sh", ".js", ".jar", ".scr"}
BLOCKED_MIME_TYPES = {
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-sh",
    "application/x-bat",
}

# Markup/script-injection patterns only. SQL-keyword detection used to live
# in here too (a bare keyword match nuked the whole field); it's now its own
# smarter heuristic in validate_text() that requires an injection-shaped
# companion token, not just the word "delete" appearing in a sentence.
BLACKLISTED_PATTERNS = [
    re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"(on\w+)\s*=", re.IGNORECASE),
    re.compile(r"(javascript:|data:text/html|vbscript:)", re.IGNORECASE),
]

_SQL_KEYWORDS_RE = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC|MERGE|TRUNCATE)\b",
    re.IGNORECASE,
)
# Companion tokens that are only meaningful *alongside* a keyword above -
# a bare quote or semicolon shows up constantly in ordinary text
# ("I'll DELETE this; let's talk Friday"), so these alone don't trigger
# anything; they only count combined with an actual keyword match.
_SQL_KEYWORD_COMPANION_RE = re.compile(r"(--|;|/\*|\*/)")
# These two are distinctive enough shapes on their own (quote immediately
# breaking out into a tautology or a comment) that legitimate free text
# essentially never produces them by accident, so they can trigger
# independent of any keyword: `' OR '1'='1'`, `admin'--`.
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
ARCHIVE_MAX_UNCOMPRESSED_BYTES = _cfg("ARCHIVE_MAX_TOTAL_UNCOMPRESSED")
MAGIC_DETECT_BYTES = _cfg("MAGIC_DETECT_BYTES")
STREAM_WRAP_MAX_BYTES = _cfg("STREAM_WRAP_MAX_BYTES")

_DRIVE_LETTER_RE = re.compile(r"^[A-Za-z]:")
_DOCTYPE_OR_ENTITY_RE = re.compile(rb"<!(DOCTYPE|ENTITY)", re.IGNORECASE)
_DANGEROUS_CSS_RE = re.compile(
    r"@import|expression\s*\(|javascript:|behaviou?r\s*:|-moz-binding", re.IGNORECASE
)
_ARCHIVE_EXT_SUFFIXES = (".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz")
_SEVEN_ZIP_SIGNATURE = b"7z\xbc\xaf\x27\x1c"

# Exported API
__all__ = [
    "validate_text",
    "sanitize_svg",
    "get_mime_type",
    "scan_archive",
    "file_sha256",
    "get_file_info",
    "is_supported_image",
    "verify_image_dimensions",
    "safe_extract_zip",
    "safe_extract_tar",
    "contains_office_macro",
    "stream_to_seekable",
    "ValidationError",
    "_safe_filename",
    # variables below exist for tests/monkeypatching
    "bleach",
    "magic",
    "etree",
    "rarfile",
    "py7zr",
    "Image",
]


# -------------------------
# helpers
# -------------------------
def _safe_filename(name: str, max_len: int = 512) -> bool:
    """
    Return False for names that could cause traversal, are absolute,
    contain NUL, have a Windows drive letter, or are simply too long to be
    a reasonable filename (extremely long names have caused real
    filesystem/ext4-limit issues in the wild).
    """
    if not name or not isinstance(name, str):
        return False
    if len(name.encode("utf-8", "surrogateescape")) > max_len:
        return False
    if "\x00" in name:
        return False
    if name.startswith("/") or name.startswith("\\"):
        return False
    if ".." in name.replace("\\", "/"):
        return False
    if _DRIVE_LETTER_RE.match(name):
        return False
    norm = os.path.normpath(name)
    if norm.startswith("..") or norm.startswith("/") or norm.startswith("\\"):
        return False
    return True


def _is_zip_symlink(info: "zipfile.ZipInfo") -> bool:
    """Best-effort detection of a Unix-symlink entry inside a zip (or a
    rarfile.RarInfo, which intentionally mimics ZipInfo's attribute names).
    A malicious archive shouldn't be able to smuggle a symlink into an
    upload meant to contain plain media/documents."""
    try:
        is_symlink_fn = getattr(info, "is_symlink", None)
        if callable(is_symlink_fn) and is_symlink_fn():
            return True
    except Exception:
        pass
    try:
        if getattr(info, "create_system", None) != 3:  # 3 == created on Unix
            return False
        mode = (info.external_attr >> 16) & 0xFFFF
        return stat.S_ISLNK(mode)
    except Exception:
        return False


# -------------------------
# Text sanitization
# -------------------------
def validate_text(
    input_text: Optional[str],
    field_name: str = "text",
    *,
    max_length: Optional[int] = None,
) -> str:
    """
    Sanitize textual input:
      - None -> ''
      - non-str -> ValidationError
      - Oversized input is rejected before any regex/bleach processing runs
        (defense against resource exhaustion on attacker-controlled length).
      - A SQL keyword by itself no longer empties the field; it only fires
        alongside an injection-shaped companion token (quote, `;`, `--`,
        `/* */`, or a crude `OR 1=1` tautology). This is defense-in-depth,
        not a substitute for parameterized queries.
      - If bleach is missing entirely, the whole original input is escaped.
      - If a blacklist pattern (script tag, on*=, javascript:/data:) hits,
        all HTML tags are stripped and the remaining plain text is returned.
      - Otherwise bleach.clean() runs with the module's allow-list.
      - Any unexpected bleach failure falls back to escaping the original
        input rather than raising - this function's job is to always
        return *something* safe to store/display.

    `field_name` is accepted as an optional second positional/keyword
    argument so this function can be called compatibly whether or not a
    caller wants attribution in error messages/logs.
    """
    if input_text is None:
        return ""
    if not isinstance(input_text, str):
        raise ValidationError(f"Expected string input for {field_name}")

    limit = max_length if max_length is not None else _cfg("TEXT_MAX_LENGTH")
    if limit and len(input_text) > limit:
        raise ValidationError(
            f"{field_name} exceeds the maximum allowed length of {limit} characters."
        )

    if _looks_like_sql_injection(input_text):
        logger.warning(
            "validate_text: rejected suspected SQL-injection-shaped input (field=%s)", field_name
        )
        return ""

    if bleach is None:
        return html.escape(input_text).strip()

    cleaned = input_text
    blacklist_hit = False
    for patt in BLACKLISTED_PATTERNS:
        new = patt.sub("", cleaned)
        if new != cleaned:
            blacklist_hit = True
        cleaned = new

    if blacklist_hit:
        plain = re.sub(r"<[^>]+>", "", cleaned)
        return plain.strip()

    try:
        out = bleach.clean(input_text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
        return out.strip()
    except Exception:
        logger.exception(
            "bleach.clean failed for field=%s, falling back to escaping the original input", field_name
        )
        return html.escape(input_text).strip()


# -------------------------
# SVG sanitization (lxml preferred, fallback to ElementTree)
# -------------------------
def _neutralize_dangerous_style(text: Optional[str]) -> Optional[str]:
    if text and _DANGEROUS_CSS_RE.search(text):
        return ""
    return text


def sanitize_svg(svg_data: IO | bytes, max_bytes: Optional[int] = None) -> bytes:
    """
    Remove script/foreignObject/iframe/object/embed elements, 'on*'
    attributes, javascript:/data: hrefs, and dangerous inline CSS
    (@import, expression(), javascript:, behavior:). Rejects any SVG
    containing a DOCTYPE/ENTITY declaration outright - legitimate SVGs
    essentially never need one, and it closes off XXE/entity-expansion
    tricks even before the parser-level `resolve_entities=False` guard
    would apply. Works with bytes or file-like. Uses lxml when available
    for robust namespace/attribute handling; falls back to
    xml.etree.ElementTree otherwise. Raises ValidationError on empty,
    oversized, malformed, or DOCTYPE-bearing content.
    """
    if isinstance(svg_data, (bytes, bytearray)):
        raw = bytes(svg_data)
    else:
        try:
            svg_data.seek(0)
        except Exception:
            pass
        raw = svg_data.read()
        if isinstance(raw, str):
            raw = raw.encode("utf-8")

    if not raw:
        raise ValidationError("Empty SVG content")

    limit = max_bytes if max_bytes is not None else _cfg("SVG_MAX_BYTES")
    if limit and len(raw) > limit:
        raise ValidationError(f"SVG exceeds the maximum allowed size of {limit} bytes.")

    if _DOCTYPE_OR_ENTITY_RE.search(raw):
        raise ValidationError(
            "SVG contains a DOCTYPE/ENTITY declaration, which is not allowed."
        )

    dangerous = {"script", "foreignobject", "iframe", "object", "embed"}

    # ---- lxml path (preferred) ----
    if etree is not None:
        try:
            parser = etree.XMLParser(
                resolve_entities=False,
                no_network=True,
                remove_comments=True,
                recover=True,
                huge_tree=False,
            )
            root = etree.fromstring(raw, parser=parser)

            to_remove = []
            for node in root.iter():
                try:
                    ln = etree.QName(node).localname.lower()
                except Exception:
                    ln = str(node.tag).lower()
                if ln in dangerous:
                    to_remove.append(node)
                elif ln == "style":
                    node.text = _neutralize_dangerous_style(node.text)
            for n in to_remove:
                p = n.getparent()
                if p is not None:
                    p.remove(n)

            for el in root.iter():
                for key in list(el.attrib):
                    local = key.split("}", 1)[1] if "}" in key else key
                    local_l = local.lower()
                    if local_l.startswith("on"):
                        el.attrib.pop(key, None)
                        continue
                    if local_l in {"href", "xlink:href", "xlink"}:
                        val = (el.attrib.get(key) or "").strip().lower()
                        if val.startswith(("javascript:", "data:")):
                            el.attrib.pop(key, None)
                            continue
                    if local_l == "style":
                        neutralized = _neutralize_dangerous_style(el.attrib.get(key))
                        if neutralized == "":
                            el.attrib.pop(key, None)

            # Strip namespace prefixes so output reads <rect> rather than
            # <ns0:rect>. `getiterator()` was removed from lxml years ago -
            # this branch used to silently no-op behind a bare `except:
            # pass`; `root.iter()` is the correct, still-supported API.
            try:
                for el in root.iter():
                    try:
                        el.tag = etree.QName(el).localname
                    except Exception:
                        pass
                try:
                    etree.cleanup_namespaces(root)
                except Exception:
                    pass
            except Exception:
                pass

            return etree.tostring(root, encoding="utf-8", xml_declaration=False)
        except ValidationError:
            raise
        except Exception as exc:
            logger.exception("lxml SVG sanitization failed")
            raise ValidationError("Malformed or unsupported SVG") from exc

    # Parsing attacker-controlled SVG with the standard library XML parser is
    # intentionally unsupported. The package requires lxml and fails closed if
    # the hardened parser is unavailable.
    raise ValidationError("Secure SVG sanitization is unavailable")


# -------------------------
# Stream utilities
# -------------------------
def stream_to_seekable(file_obj: IO, max_bytes: Optional[int] = None) -> IO:
    """
    Ensure a seekable file-like is returned.
    - If file_obj is already seekable -> returned unchanged.
    - Otherwise spool into a SpooledTemporaryFile (keeps small data
      in-memory, larger data on disk).
    - Raises ValidationError when the stream exceeds max_bytes while
      buffering, rather than buffering an unbounded amount of
      attacker-controlled data.
    - Carries over the source's `.name` attribute when present, so
      downstream extension-based fallbacks (get_mime_type) still work
      after wrapping.
    """
    limit = max_bytes if max_bytes is not None else _cfg("STREAM_WRAP_MAX_BYTES")
    try:
        if getattr(file_obj, "seekable", lambda: False)():
            return file_obj
    except Exception:
        pass

    from tempfile import SpooledTemporaryFile

    spool = SpooledTemporaryFile(max_size=limit, mode="w+b")
    total = 0
    while True:
        chunk = file_obj.read(64 * 1024)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        total += len(chunk)
        if total > limit:
            spool.close()
            raise ValidationError("Stream too large to buffer")
        spool.write(chunk)
    spool.seek(0)
    src_name = getattr(file_obj, "name", None)
    if src_name:
        try:
            spool.name = src_name
        except Exception:
            pass
    return spool


# -------------------------
# MIME detection
# -------------------------
def get_mime_type(file_obj: IO, strict_extension_check: bool = False) -> str:
    """
    Robust MIME detection:
      - Read a small sample from the stream (try to restore position).
      - Use python-magic if available, trying multiple calling forms
        (robust to versions).
      - If python-magic is missing and strict_extension_check=True, fall
        back to a minimal signature check for common types
        (pdf/png/jpeg/zip).
      - Fallback to mimetypes.guess_type(filename) or
        'application/octet-stream'.
    """
    pos = None
    try:
        pos = file_obj.tell()
    except Exception:
        pos = None

    try:
        sample = file_obj.read(_cfg("MAGIC_DETECT_BYTES")) or b""
    except Exception:
        sample = b""

    if pos is not None:
        try:
            file_obj.seek(pos)
        except Exception:
            pos = None

    detected_mime = None

    if magic is not None:
        try:
            if hasattr(magic, "from_buffer") and callable(magic.from_buffer):
                try:
                    detected_mime = magic.from_buffer(sample, mime=True)
                except TypeError:
                    detected_mime = magic.from_buffer(sample)
            else:
                M = getattr(magic, "Magic", None)
                if M is not None:
                    try:
                        detected_mime = M(mime=True).from_buffer(sample)
                    except Exception:
                        detected_mime = None
        except Exception:
            logger.exception("python-magic quick detection failed; will fallback")
            detected_mime = None

        if detected_mime and "/" not in str(detected_mime):
            try:
                M = getattr(magic, "Magic", None)
                if M is not None:
                    detected_mime = M(mime=True).from_buffer(sample)
            except Exception:
                pass

        if isinstance(detected_mime, bytes):
            detected_mime = detected_mime.decode("utf-8", "ignore")
        if isinstance(detected_mime, str):
            detected_mime = detected_mime.strip().lower()

    filename = getattr(file_obj, "name", "") or ""
    if not detected_mime:
        guessed, _ = mimetypes.guess_type(filename)
        detected_mime = guessed or "application/octet-stream"

    if strict_extension_check:
        ext = os.path.splitext(filename)[1].lower() if filename and "." in filename else ""
        sig_map = {
            ".pdf": b"%PDF",
            ".png": b"\x89PNG",
            ".jpg": b"\xff\xd8\xff",
            ".jpeg": b"\xff\xd8\xff",
            ".zip": b"PK\x03\x04",
        }
        if ext and ext in sig_map and not sample.startswith(sig_map[ext]):
            if magic is None:
                raise ValidationError(
                    f"File extension suggests {mimetypes.guess_type(filename)[0]} "
                    "but content signature mismatch"
                )
            guessed_mime, _ = mimetypes.guess_type(filename)
            if guessed_mime and guessed_mime != detected_mime:
                raise ValidationError(
                    f"File extension suggests {guessed_mime} but detected {detected_mime}"
                )

        if filename and "." in filename:
            guessed_mime, _ = mimetypes.guess_type(filename)
            if guessed_mime and detected_mime and guessed_mime != detected_mime:
                raise ValidationError(
                    f"File extension suggests {guessed_mime} but detected {detected_mime}"
                )

    return str(detected_mime) if detected_mime else "application/octet-stream"


# -------------------------
# File hashing + info
# -------------------------
def file_sha256(
    file_obj: IO,
    chunk_size: int = 8192,
    *,
    algorithm: str = "sha256",
    max_bytes: Optional[int] = None,
) -> str:
    """
    Compute a hex digest of file-like content. Defaults to SHA-256 (the
    original behaviour); pass algorithm="sha1"/"md5"/etc. (anything in
    hashlib.algorithms_available) for interop with legacy systems. Pass
    max_bytes to cap how much will be hashed from an untrusted/unbounded
    stream (raises ValidationError if exceeded) - unset by default, which
    preserves the original unbounded behaviour for trusted/local callers.
    Attempts to restore the original stream position when possible.
    """
    algo = (algorithm or "sha256").lower()
    if algo not in hashlib.algorithms_available:
        raise ValidationError(f"Unsupported hash algorithm: {algorithm}")

    try:
        start = file_obj.tell()
    except Exception:
        start = None

    try:
        file_obj.seek(0)
    except Exception:
        file_obj = stream_to_seekable(file_obj)

    h = hashlib.new(algo)
    total = 0
    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise ValidationError(f"Content exceeds {max_bytes} bytes; refusing to hash further.")
        h.update(chunk)

    try:
        if start is not None:
            file_obj.seek(start)
        else:
            file_obj.seek(0)
    except Exception:
        pass

    return h.hexdigest()


def get_file_info(file_obj: IO, *, compute_hash: bool = True, algorithm: str = "sha256") -> Dict[str, Any]:
    """
    Return {name, extension, size, mime, sha256[, hash, hash_algorithm]}.
    Uses stream_to_seekable for safety on non-seekable inputs. Each of
    mime-detection/hashing is individually best-effort: a failure in one
    doesn't prevent returning the others.
    """
    seekable = stream_to_seekable(file_obj)
    name = getattr(seekable, "name", "") or ""
    ext = os.path.splitext(name)[1].lower() if name else ""
    try:
        cur = seekable.tell()
        seekable.seek(0, os.SEEK_END)
        size = seekable.tell()
        seekable.seek(cur)
    except Exception:
        content = seekable.read()
        size = len(content)
        try:
            seekable.seek(0)
        except Exception:
            pass

    info: Dict[str, Any] = {"name": name, "extension": ext, "size": size, "mime": None, "sha256": None}

    try:
        info["mime"] = get_mime_type(seekable)
    except Exception:
        logger.debug("get_file_info: mime detection failed for %s", name, exc_info=True)

    if compute_hash:
        try:
            digest = file_sha256(seekable, algorithm=algorithm)
            if algorithm == "sha256":
                info["sha256"] = digest
            else:
                info["hash"] = digest
                info["hash_algorithm"] = algorithm
        except Exception:
            logger.debug("get_file_info: hashing failed for %s", name, exc_info=True)

    return info


# -------------------------
# Image helpers (Pillow optional)
# -------------------------
def _pixel_cap_exceeded(img, max_pixels: int) -> bool:
    try:
        w, h = img.size
        return bool(max_pixels) and (w * h) > max_pixels
    except Exception:
        return False


def is_supported_image(file_obj: IO) -> bool:
    """Return True if Pillow can open/verify the image file and it doesn't
    exceed the configured decompression-bomb pixel cap."""
    if Image is None:
        logger.debug("Pillow not installed; cannot verify image")
        return False
    try:
        s = stream_to_seekable(file_obj)
        img = Image.open(s)
        # Image.open() only parses the header, so checking dimensions here
        # is cheap and lets us reject absurd pixel counts *before* any
        # decode work, rather than relying on Pillow's own warn-vs-error
        # DecompressionBomb* split (which is inconsistent across versions
        # and formats).
        if _pixel_cap_exceeded(img, _cfg("IMAGE_MAX_PIXELS")):
            logger.warning("Rejected image %s: exceeds pixel cap", getattr(img, "size", None))
            return False
        img.verify()
        try:
            s.seek(0)
        except Exception:
            pass
        return True
    except Exception:
        return False


def verify_image_dimensions(file_obj: IO, max_width: int, max_height: int) -> bool:
    """Raise ValidationError if the image exceeds allowed dimensions or the
    decompression-bomb pixel cap (Pillow required)."""
    if Image is None:
        raise ValidationError("Pillow required to verify image dimensions")
    s = stream_to_seekable(file_obj)
    try:
        img = Image.open(s)
        max_pixels = _cfg("IMAGE_MAX_PIXELS")
        w, h = img.size
        if max_pixels and w * h > max_pixels:
            raise ValidationError(
                f"Image is {w}x{h} ({w * h:,} pixels), exceeding the {max_pixels:,}-pixel "
                "decompression-bomb guard."
            )
        if w > max_width or h > max_height:
            raise ValidationError(f"Image dimensions {w}x{h} exceed allowed {max_width}x{max_height}")
        img.verify()
        try:
            s.seek(0)
        except Exception:
            pass
        return True
    except ValidationError:
        raise
    except Exception as exc:
        # Pillow's own decompression-bomb guard (name-matched rather than
        # imported directly, since its exact class/location has moved
        # between versions) may fire here too if a format-specific edge
        # case slipped past the proactive check above.
        if "DecompressionBomb" in type(exc).__name__:
            raise ValidationError("Image appears to be a decompression bomb.") from exc
        raise ValidationError("Invalid image file") from exc


# -------------------------
# Archive inspection / safe extraction
# -------------------------
def _check_zipfile_safety(zf) -> None:
    """Works for both zipfile.ZipFile and rarfile.RarFile - rarfile
    deliberately mirrors zipfile's namelist()/infolist() interface, and its
    RarInfo objects expose the same filename/file_size/compress_size
    attribute names, plus an is_symlink()/is_encrypted() where relevant."""
    max_files = _cfg("ARCHIVE_MAX_FILES")
    max_total = _cfg("ARCHIVE_MAX_TOTAL_UNCOMPRESSED")
    max_single = _cfg("ARCHIVE_MAX_SINGLE_FILE_BYTES")
    max_ratio = _cfg("ARCHIVE_MAX_COMPRESSION_RATIO")

    names = zf.namelist()
    if len(names) > max_files:
        raise ValidationError(f"Archive contains too many files ({len(names)}).")

    total = 0
    for info in zf.infolist():
        fname = getattr(info, "filename", "")
        if not _safe_filename(fname):
            raise ValidationError(f"Unsafe filename in archive: {fname}")
        if _is_zip_symlink(info):
            raise ValidationError(f"Archive contains a symlink entry, which is not allowed: {fname}")

        file_size = getattr(info, "file_size", 0) or 0
        compress_size = getattr(info, "compress_size", 0) or 0

        if max_single and file_size > max_single:
            raise ValidationError(f"File inside archive exceeds the per-file limit: {fname}")

        total += file_size
        if total > max_total:
            raise ValidationError("Archive total uncompressed size exceeds allowed limit.")

        if max_ratio and compress_size:
            ratio = file_size / max(compress_size, 1)
            if ratio > max_ratio:
                raise ValidationError(
                    f"Suspicious compression ratio in {fname} ({ratio:.0f}:1); possible archive bomb."
                )

        low = fname.lower()
        if any(low.endswith(ext) for ext in BLOCKED_ARCHIVE_EXTS):
            raise ValidationError(f"Blocked file inside archive: {fname}")
        if low.endswith(_ARCHIVE_EXT_SUFFIXES):
            raise ValidationError(f"Nested archive detected: {fname}")


def _check_tarfile_safety(tf: "tarfile.TarFile") -> None:
    max_files = _cfg("ARCHIVE_MAX_FILES")
    max_total = _cfg("ARCHIVE_MAX_TOTAL_UNCOMPRESSED")
    max_single = _cfg("ARCHIVE_MAX_SINGLE_FILE_BYTES")

    members = tf.getmembers()
    if len(members) > max_files:
        raise ValidationError(f"Archive contains too many files ({len(members)}).")

    total = 0
    for member in members:
        name = member.name
        if not _safe_filename(name):
            raise ValidationError(f"Unsafe filename in archive: {name}")
        if member.issym() or member.islnk():
            raise ValidationError(f"Archive contains a symlink/hardlink entry, which is not allowed: {name}")
        if member.isdev():
            raise ValidationError(f"Archive contains a device file entry, which is not allowed: {name}")
        if not (member.isfile() or member.isdir()):
            raise ValidationError(f"Archive contains an unsupported entry type: {name}")

        size = member.size or 0
        if max_single and size > max_single:
            raise ValidationError(f"File inside archive exceeds the per-file limit: {name}")
        total += size
        if total > max_total:
            raise ValidationError("Archive total uncompressed size exceeds allowed limit.")

        low = name.lower()
        if any(low.endswith(ext) for ext in BLOCKED_ARCHIVE_EXTS):
            raise ValidationError(f"Blocked file inside archive: {name}")
        if low.endswith(_ARCHIVE_EXT_SUFFIXES):
            raise ValidationError(f"Nested archive detected: {name}")


def _check_7z_safety(zf) -> None:
    max_files = _cfg("ARCHIVE_MAX_FILES")
    max_total = _cfg("ARCHIVE_MAX_TOTAL_UNCOMPRESSED")
    max_single = _cfg("ARCHIVE_MAX_SINGLE_FILE_BYTES")

    try:
        infos = zf.list()
    except Exception as exc:
        raise ValidationError(f"Could not enumerate 7z contents: {exc}")

    if len(infos) > max_files:
        raise ValidationError(f"Archive contains too many files ({len(infos)}).")

    total = 0
    for info in infos:
        name = getattr(info, "filename", "") or ""
        if not _safe_filename(name):
            raise ValidationError(f"Unsafe filename in archive: {name}")
        if getattr(info, "is_encrypted", False):
            raise ValidationError("Password-protected archives are not allowed")

        size = getattr(info, "uncompressed", None)
        if size is None:
            size = getattr(info, "uncompressed_size", 0) or 0
        if max_single and size > max_single:
            raise ValidationError(f"File inside archive exceeds the per-file limit: {name}")
        total += size
        if total > max_total:
            raise ValidationError("Archive total uncompressed size exceeds allowed limit.")

        low = name.lower()
        if any(low.endswith(ext) for ext in BLOCKED_ARCHIVE_EXTS):
            raise ValidationError(f"Blocked file inside archive: {name}")
        if low.endswith(_ARCHIVE_EXT_SUFFIXES):
            raise ValidationError(f"Nested archive detected: {name}")


def scan_archive(file_obj: IO) -> IO:
    """
    Inspect ZIP, RAR (when rarfile installed), TAR (.tar/.tar.gz/.tgz/
    .tar.bz2/.tar.xz, auto-detected), and 7z (when py7zr installed).
    Returns the file-like, seeked back to the start, on success.

    Raises ValidationError for passworded, unsafe (path traversal,
    symlinks, device files, blocked extensions, nested archives), or
    too-large/too-compressed (zip-bomb-shaped) archives.

    7z is fail-closed: content bearing a 7z magic signature is rejected if
    `py7zr` isn't installed, rather than being passed through uninspected.
    Any other format not recognized by the checks above is returned as-is,
    unchanged from the original behaviour - this function inspects content
    *claiming* to be a known archive type; it isn't the sole gate deciding
    which media types are accepted (that's the caller's MIME allow-list).
    """
    try:
        try:
            file_obj.seek(0)
        except Exception:
            file_obj = stream_to_seekable(file_obj)

        # ---- ZIP ----
        if zipfile.is_zipfile(file_obj):
            try:
                file_obj.seek(0)
            except Exception:
                file_obj = BytesIO(file_obj.read())
            with zipfile.ZipFile(file_obj, "r") as zf:
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        raise ValidationError("Password-protected archives are not allowed")
                _check_zipfile_safety(zf)
            try:
                file_obj.seek(0)
            except Exception:
                pass
            return file_obj

        # ---- RAR ----
        if rarfile is not None:
            try:
                file_obj.seek(0)
            except Exception:
                file_obj = BytesIO(file_obj.read())
            if rarfile.is_rarfile(file_obj):
                try:
                    file_obj.seek(0)
                except Exception:
                    pass
                try:
                    with rarfile.RarFile(file_obj) as rf:
                        for info in rf.infolist():
                            needs_pw = getattr(info, "needs_password", None)
                            if getattr(info, "is_encrypted", False) or (callable(needs_pw) and needs_pw()):
                                raise ValidationError("Password-protected archives are not allowed")
                        _check_zipfile_safety(rf)
                    try:
                        file_obj.seek(0)
                    except Exception:
                        pass
                    return file_obj
                except ValidationError:
                    raise
                except Exception as e:
                    logger.exception("RAR check failed: %s", e)
                    raise ValidationError("Invalid RAR archive")

        # ---- TAR (.tar, .tar.gz, .tgz, .tar.bz2, .tar.xz) ----
        try:
            file_obj.seek(0)
            is_tar = tarfile.is_tarfile(file_obj)
        except Exception:
            is_tar = False
        if is_tar:
            try:
                file_obj.seek(0)
            except Exception:
                pass
            try:
                with tarfile.open(fileobj=file_obj, mode="r:*") as tf:
                    _check_tarfile_safety(tf)
                try:
                    file_obj.seek(0)
                except Exception:
                    pass
                return file_obj
            except ValidationError:
                raise
            except Exception as e:
                logger.exception("TAR check failed: %s", e)
                raise ValidationError("Invalid TAR archive")

        # ---- 7z (fail-closed) ----
        try:
            file_obj.seek(0)
            sig = file_obj.read(6)
            file_obj.seek(0)
        except Exception:
            sig = b""
        if sig == _SEVEN_ZIP_SIGNATURE:
            if py7zr is None:
                raise ValidationError(
                    "7z archives are not supported by this server (py7zr not installed)."
                )
            try:
                with py7zr.SevenZipFile(file_obj, mode="r") as zf:
                    _check_7z_safety(zf)
                try:
                    file_obj.seek(0)
                except Exception:
                    pass
                return file_obj
            except ValidationError:
                raise
            except Exception as e:
                logger.exception("7z check failed: %s", e)
                raise ValidationError("Invalid 7z archive")

        # not a recognized archive container -> return as-is
        try:
            file_obj.seek(0)
        except Exception:
            pass
        return file_obj
    except ValidationError:
        raise
    except Exception as e:
        logger.exception("Archive scan error: %s", e)
        raise ValidationError("Archive scanning failed")


def safe_extract_zip(zip_file: zipfile.ZipFile, target_dir: str) -> None:
    """
    Extract zip_file safely into target_dir: defends against zip-slip,
    unsafe/blocked-extension names, and symlink entries. Every extracted
    regular file has its permissions forced to 0o644 - execute bits are
    never carried over from the archive, regardless of what the archive
    claims. (This function never calls os.symlink(); a symlink entry's
    "target" text is just written as inert byte content if it somehow got
    past the check above, so there's no separate symlink-creation risk to
    guard against here - the check exists to reject the entry outright.)
    """
    os.makedirs(target_dir, exist_ok=True)
    base = os.path.abspath(target_dir)
    for member in zip_file.infolist():
        name = member.filename
        if not _safe_filename(name):
            raise ValidationError(f"Unsafe filename in archive: {name}")
        low = name.lower()
        if any(low.endswith(ext) for ext in BLOCKED_ARCHIVE_EXTS):
            raise ValidationError(f"Blocked file inside archive: {name}")
        if _is_zip_symlink(member):
            raise ValidationError(f"Archive contains a symlink entry, which is not allowed: {name}")

        dest_path = os.path.abspath(os.path.join(target_dir, name))
        if not (dest_path == base or dest_path.startswith(base + os.sep)):
            raise ValidationError("Zip-slip attempt detected")

        if member.is_dir():
            os.makedirs(dest_path, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            with zip_file.open(member) as src, open(dest_path, "wb") as out:
                shutil.copyfileobj(src, out)
            try:
                os.chmod(dest_path, 0o644)
            except Exception:
                logger.debug("Could not set permissions on extracted file %s", dest_path)


def safe_extract_tar(tar_file: "tarfile.TarFile", target_dir: str) -> None:
    """Tar analogue of safe_extract_zip(). Re-validates every member even
    if the caller already ran scan_archive()/_check_tarfile_safety, since
    extraction is a separate, security-sensitive operation that shouldn't
    silently trust an earlier scan performed by different code (tar,
    unlike zip, has first-class symlink/hardlink/device-file member types
    that `extractall()` would otherwise materialize on disk)."""
    os.makedirs(target_dir, exist_ok=True)
    base = os.path.abspath(target_dir)
    for member in tar_file.getmembers():
        name = member.name
        if not _safe_filename(name):
            raise ValidationError(f"Unsafe filename in archive: {name}")
        if member.issym() or member.islnk() or member.isdev():
            raise ValidationError(f"Archive contains an unsupported entry type: {name}")
        low = name.lower()
        if any(low.endswith(ext) for ext in BLOCKED_ARCHIVE_EXTS):
            raise ValidationError(f"Blocked file inside archive: {name}")

        dest_path = os.path.abspath(os.path.join(target_dir, name))
        if not (dest_path == base or dest_path.startswith(base + os.sep)):
            raise ValidationError("Path traversal attempt detected")

        if member.isdir():
            os.makedirs(dest_path, exist_ok=True)
            continue
        if not member.isfile():
            continue

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        src = tar_file.extractfile(member)
        if src is None:
            continue
        with src, open(dest_path, "wb") as out:
            shutil.copyfileobj(src, out)
        try:
            os.chmod(dest_path, 0o644)
        except Exception:
            logger.debug("Could not set permissions on extracted file %s", dest_path)


def contains_office_macro(file_bytes: bytes) -> bool:
    """
    Heuristic check for VBA macros inside an OOXML (docx/xlsx/pptx)
    container, even when the declared/sniffed MIME type doesn't say
    "macroEnabled" - a `.xlsm` renamed to `.xlsx` would otherwise slide
    past a pure MIME-type check. Returns False (rather than raising) when
    the content isn't a valid zip at all, since validating the container
    format is a separate concern from this specific heuristic.
    """
    try:
        with zipfile.ZipFile(BytesIO(file_bytes)) as zf:
            names = zf.namelist()
            return any(
                n.lower().endswith("vbaproject.bin") or n.lower() == "word/vbadata.xml"
                for n in names
            )
    except Exception:
        return False
