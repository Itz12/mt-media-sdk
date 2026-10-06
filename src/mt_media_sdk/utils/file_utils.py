# mediaservice/utils/file_utils.py
from __future__ import annotations

import os
import tempfile
import shutil
import uuid
import logging
from io import BytesIO
from typing import Union, Optional, BinaryIO
from pathlib import Path
import hashlib

from django.conf import settings
from django.core.files.uploadedfile import (
    InMemoryUploadedFile,
    TemporaryUploadedFile,
    UploadedFile,
)
from django.core.files import File as DjangoFile
from django.core.files.storage import default_storage, Storage
from django.utils.crypto import get_random_string

logger = logging.getLogger(__name__)

# ---------- Exceptions ----------


class FileUtilsError(Exception):
    """Base for file utils errors."""


class FileWriteError(FileUtilsError):
    """Raised when writing a temporary file fails."""


class FileNotFoundError(FileUtilsError):
    """Raised when a required file path does not exist."""


class InvalidParameterError(FileUtilsError):
    """Raised on invalid caller inputs (bad filenames, bad directories)."""


# ---------- Configuration helpers ----------


def _ensure_dir(path: Path, mode: int = 0o700) -> None:
    """
    Ensure directory exists and attempt to set secure permissions on POSIX.
    Non-fatal if chmod fails (will be logged).
    """
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            path.chmod(mode)
        except Exception:
            logger.debug("Could not set permissions on %s", str(path), exc_info=True)


def get_temp_dir() -> str:
    """
    Determine the staging temp directory to use for uploads.

    Preference order:
      1. settings.TEMP_UPLOAD_DIR (absolute)
      2. settings.MEDIA_ROOT / "temp"
      3. system tempdir

    Ensures directory exists and uses restrictive perms where possible.
    Returns absolute path string.
    """
    candidate = getattr(settings, "TEMP_UPLOAD_DIR", None)
    if candidate:
        tmp = Path(candidate)
    else:
        media_root = getattr(settings, "MEDIA_ROOT", None)
        if media_root:
            tmp = Path(media_root) / "temp"
        else:
            tmp = Path(tempfile.gettempdir())

    try:
        _ensure_dir(tmp)
    except Exception:
        logger.exception("Failed to ensure temp directory %s; falling back to system tmpdir", str(tmp))
        tmp = Path(tempfile.gettempdir())
        _ensure_dir(tmp)
    return str(tmp.resolve())


# ---------- Filename helpers ----------


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Remove path separators and disallowed characters from filename.
    Keep alphanumerics, spaces, dot, dash and underscore. Truncate to max_length.
    Prevents path traversal and weird unicode control characters.
    """
    if not filename:
        filename = "file"
    # strip any directory components
    base = os.path.basename(filename)
    # remove any null bytes
    base = base.replace("\x00", "")
    # whitelist characters
    allowed = []
    for ch in base:
        # common safe characters
        if ch.isalnum() or ch in " .-_":
            allowed.append(ch)
    clean = "".join(allowed).strip()
    if not clean:
        clean = get_random_string(8)
    if len(clean) > max_length:
        # preserve extension if present
        root, ext = os.path.splitext(clean)
        ext = ext[:20]
        root = root[: max_length - len(ext)]
        clean = f"{root}{ext}"
    return clean


def _ensure_relative_subdir(subdir: str) -> str:
    """
    Ensure the provided media_subdir is a safe relative path (no absolute paths,
    no '..' components). Raises InvalidParameterError if invalid.
    """
    if not subdir:
        raise InvalidParameterError("media_subdir must be a non-empty relative path.")
    p = Path(subdir)
    if p.is_absolute():
        raise InvalidParameterError("media_subdir must be relative, not absolute.")
    # Prevent traversal
    for part in p.parts:
        if part in ("..", ""):
            raise InvalidParameterError("media_subdir contains illegal path components.")
    return str(p.as_posix())


# ---------- Checksum utilities ----------


def compute_sha256_from_path(path: str, chunk_size: int = 8192) -> str:
    """
    Compute sha256 checksum of a file at path.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Path does not exist: {path}")
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_sha256_from_fileobj(fobj: BinaryIO, chunk_size: int = 8192) -> str:
    """
    Compute sha256 checksum from an open file-like object (will attempt to seek back to 0).
    """
    h = hashlib.sha256()
    try:
        fobj.seek(0)
    except Exception:
        pass
    for chunk in iter(lambda: fobj.read(chunk_size), b""):
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        h.update(chunk)
    try:
        fobj.seek(0)
    except Exception:
        pass
    return h.hexdigest()


# ---------- Temp file writer & context manager ----------


def _open_atomic_tempfile(dirpath: str, prefix: str, suffix: str = "") -> str:
    """
    Create a NamedTemporaryFile that is not auto-deleted and return its path.
    This ensures atomic write to a temp file that caller can move later.
    """
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=dirpath)
    os.close(fd)
    return path


def write_temp_file(
    file_obj: Union[TemporaryUploadedFile, InMemoryUploadedFile, UploadedFile, BytesIO, bytes, BinaryIO],
    file_id: Optional[str] = None,
    temp_dir: Optional[str] = None,
    max_size: Optional[int] = None,
    chunk_size: int = 64 * 1024,
) -> str:
    """
    Write the provided file-like or UploadedFile into a uniquely named temp file
    placed under temp_dir (or configured temp dir) and return the absolute path.

    - Supports Django UploadedFile variants, BytesIO, raw bytes, and generic binary file-like objects.
    - max_size: optional, will raise FileWriteError if exceeded during streaming.
    - Ensures file permissions are restricted (POSIX) when possible.
    - Caller MUST remove the returned file when finished (use delete_temp_file()).

    Raises:
      - FileWriteError on failure
      - InvalidParameterError for invalid inputs
    """
    if file_obj is None:
        raise InvalidParameterError("file_obj must be provided.")

    file_id = file_id or uuid.uuid4().hex
    temp_dir = temp_dir or get_temp_dir()
    os.makedirs(temp_dir, exist_ok=True)
    safe_file_id = sanitize_filename(file_id, max_length=64)
    orig_name = getattr(file_obj, "name", None) or getattr(file_obj, "filename", None) or f"upload-{safe_file_id}"
    safe_name = sanitize_filename(orig_name, max_length=200)
    temp_suffix = f"_{safe_name}"
    tmp_path = _open_atomic_tempfile(temp_dir, prefix=f"{safe_file_id}_", suffix=temp_suffix)

    bytes_written = 0

    try:
        # If TemporaryUploadedFile, it already exists on disk; try to move atomically
        if isinstance(file_obj, TemporaryUploadedFile):
            try:
                src = file_obj.temporary_file_path()
            except Exception:
                src = None
            if src and os.path.exists(src):
                try:
                    os.replace(src, tmp_path)
                except Exception:
                    shutil.copyfile(src, tmp_path)
                    try:
                        os.remove(src)
                    except Exception:
                        logger.debug("Failed cleaning original temporary uploaded file %s", src)
                # secure perms
                try:
                    if os.name == "posix":
                        os.chmod(tmp_path, 0o600)
                except Exception:
                    logger.debug("Could not chmod temp file %s", tmp_path, exc_info=True)
                return tmp_path

        # For chunked types
        if hasattr(file_obj, "chunks"):
            try:
                with open(tmp_path, "wb") as dst:
                    for chunk in file_obj.chunks(chunk_size):
                        if not chunk:
                            continue
                        if isinstance(chunk, str):
                            chunk = chunk.encode("utf-8")
                        bytes_written += len(chunk)
                        if max_size and bytes_written > max_size:
                            raise FileWriteError(f"File exceeds max_size {max_size} bytes.")
                        dst.write(chunk)
            except Exception as exc:
                raise FileWriteError(f"Failed streaming chunks to temp file: {exc}") from exc
            finally:
                try:
                    if os.name == "posix":
                        os.chmod(tmp_path, 0o600)
                except Exception:
                    logger.debug("Could not chmod temp file %s", tmp_path, exc_info=True)
            return tmp_path

        # If has read()
        if hasattr(file_obj, "read"):
            try:
                with open(tmp_path, "wb") as dst:
                    try:
                        file_obj.seek(0)
                    except Exception:
                        pass
                    for chunk in iter(lambda: file_obj.read(chunk_size), b""):
                        if not chunk:
                            break
                        if isinstance(chunk, str):
                            chunk = chunk.encode("utf-8")
                        bytes_written += len(chunk)
                        if max_size and bytes_written > max_size:
                            raise FileWriteError(f"File exceeds max_size {max_size} bytes.")
                        dst.write(chunk)
            except Exception as exc:
                raise FileWriteError(f"Failed writing file-like object to temp file: {exc}") from exc
            finally:
                try:
                    if os.name == "posix":
                        os.chmod(tmp_path, 0o600)
                except Exception:
                    logger.debug("Could not chmod temp file %s", tmp_path, exc_info=True)
            return tmp_path

        # If raw bytes/bytearray
        if isinstance(file_obj, (bytes, bytearray)):
            if max_size and len(file_obj) > max_size:
                raise FileWriteError(f"File exceeds max_size {max_size} bytes.")
            try:
                with open(tmp_path, "wb") as dst:
                    dst.write(file_obj)
            except Exception as exc:
                raise FileWriteError(f"Failed writing bytes to temp file: {exc}") from exc
            try:
                if os.name == "posix":
                    os.chmod(tmp_path, 0o600)
            except Exception:
                logger.debug("Could not chmod temp file %s", tmp_path, exc_info=True)
            return tmp_path

        raise InvalidParameterError("Unsupported file_obj type for write_temp_file.")
    except Exception:
        # Ensure partial file cleanup on failure
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            logger.debug("Failed to remove partial temp file %s", tmp_path, exc_info=True)
        raise


class staged_temp_file:
    """
    Context manager helper wrapping write_temp_file for convenience.

    Example:
        with staged_temp_file(uploaded_file) as tmp_path:
            do_stuff(tmp_path)
    The file will NOT be removed automatically unless `cleanup=True`.
    """
    def __init__(
        self,
        file_obj: Union[TemporaryUploadedFile, InMemoryUploadedFile, UploadedFile, BytesIO, bytes, BinaryIO],
        file_id: Optional[str] = None,
        temp_dir: Optional[str] = None,
        max_size: Optional[int] = None,
        cleanup: bool = True,
    ):
        self.file_obj = file_obj
        self.file_id = file_id
        self.temp_dir = temp_dir
        self.max_size = max_size
        self.cleanup = cleanup
        self.path: Optional[str] = None

    def __enter__(self) -> str:
        self.path = write_temp_file(self.file_obj, file_id=self.file_id, temp_dir=self.temp_dir, max_size=self.max_size)
        return self.path

    def __exit__(self, exc_type, exc, tb):
        if self.cleanup and self.path:
            try:
                if os.path.exists(self.path):
                    os.remove(self.path)
            except Exception:
                logger.debug("Failed to cleanup staged temp file %s", self.path, exc_info=True)


# ---------- Move to final storage ----------


def final_media_path(
    temp_path: str,
    media_subdir: str,
    storage: Optional[Storage] = None,
    prefer_local_move: bool = True,
    allow_overwrite: bool = False,
) -> str:
    """
    Move a temp_path into storage under media_subdir and return storage path.

    Behavior:
      - Validate temp_path exists.
      - Ensure media_subdir is safe (relative path, no traversal).
      - If storage is None, uses django default_storage.
      - If default_storage is local FileSystemStorage and MEDIA_ROOT is configured,
        attempt os.replace or shutil.move for atomic/local moves to keep paths local and performant.
      - Otherwise, uses storage.save streaming the file into backend (S3/GCS).
    Returns:
      - If storage is local FS and provides .path, returns absolute filesystem path.
      - Else returns storage name (relative key returned by storage.save).
    Raises:
      - FileNotFoundError if temp_path missing
      - FileWriteError on failure to persist
    """
    storage = storage or default_storage
    if not os.path.exists(temp_path):
        raise FileNotFoundError(f"Temp path does not exist: {temp_path}")

    media_subdir = _ensure_relative_subdir(media_subdir)
    basename = os.path.basename(temp_path)
    # Keep unique dest name
    dest_name = f"{uuid.uuid4().hex}_{sanitize_filename(basename, max_length=200)}"
    # If storage appears to be local filesystem and MEDIA_ROOT defined, prefer local move
    media_root = getattr(settings, "MEDIA_ROOT", None)

    # Helper to try local move
    if prefer_local_move and media_root and getattr(storage, "__class__", None).__module__.startswith("django.core.files.storage"):
        try:
            dest_dir = os.path.join(media_root, media_subdir)
            os.makedirs(dest_dir, exist_ok=True)
            final_local = os.path.join(dest_dir, dest_name)
            # Attempt atomic replace on same filesystem
            try:
                os.replace(temp_path, final_local)
            except Exception:
                shutil.move(temp_path, final_local)
            # Restrict perms if possible
            try:
                if os.name == "posix":
                    os.chmod(final_local, 0o600)
            except Exception:
                logger.debug("Could not chmod final file %s", final_local, exc_info=True)
            return final_local
        except Exception:
            logger.debug("Local move path failed, will fall back to storage.save", exc_info=True)

    # Fallback to storage.save (stream into configured storage backend)
    try:
        storage_name = os.path.join(media_subdir, dest_name)
        # If storage implements get_available_name, use it to avoid collisions
        try:
            available_name = storage.get_available_name(storage_name) if hasattr(storage, "get_available_name") else storage_name
        except Exception:
            available_name = storage_name

        with open(temp_path, "rb") as fh:
            django_file = DjangoFile(fh, name=os.path.basename(available_name))
            saved_name = storage.save(available_name if allow_overwrite else available_name, django_file)

        # Remove temp file now that it's saved remotely/local copy exists
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            logger.debug("Failed to remove temp file after storage.save: %s", temp_path, exc_info=True)

        # If storage provides path() (FileSystemStorage) return absolute path
        if hasattr(storage, "path"):
            try:
                return storage.path(saved_name)
            except Exception:
                logger.debug("storage.path failed for %s", saved_name, exc_info=True)
        return saved_name
    except Exception as exc:
        logger.exception("Failed to persist temp file %s into storage: %s", temp_path, exc)
        raise FileWriteError(f"Could not persist temp file into storage: {exc}") from exc


# ---------- Save into Django model FileField/ImageField ----------


def save_filefield_from_path(instance, field_name: str, path: str, original_name: Optional[str] = None, remove_source: bool = False) -> None:
    """
    Given a model instance and FileField name, open the file at path and save it into the field
    using Django's storage API. Optionally remove the source file after successful save.

    - Field name must exist on instance.
    - This calls the field.save(...) method which triggers storage backend behavior.
    """
    if not hasattr(instance, field_name):
        raise InvalidParameterError(f"Instance has no file field named '{field_name}'")

    if not os.path.exists(path):
        raise FileNotFoundError(f"File does not exist: {path}")

    original_name = original_name or os.path.basename(path)
    original_name = sanitize_filename(original_name, max_length=200)
    try:
        with open(path, "rb") as fh:
            django_file = DjangoFile(fh, name=original_name)
            # Use save(save=True) to persist model; for bigger workflows you may want save=False then instance.save()
            getattr(instance, field_name).save(original_name, django_file, save=True)
    except Exception:
        logger.exception("Failed to save file to model.%s from path %s", field_name, path)
        raise

    if remove_source:
        try:
            os.remove(path)
        except Exception:
            logger.debug("Failed to remove source file %s after save", path, exc_info=True)


# ---------- Delete temp helper ----------


def delete_temp_file(path: Optional[str]) -> None:
    """
    Remove a temp file if it exists. Logs but does not raise on failure.
    """
    if not path:
        return
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        logger.exception("Failed to delete temp file %s", path)


# ---------- Usage examples (small) ----------
#
# 1) Stage an uploaded file, compute checksum, persist to storage and attach to model:
#
# with staged_temp_file(uploaded_file) as tmp_path:
#     checksum = compute_sha256_from_path(tmp_path)
#     stored = final_media_path(tmp_path, media_subdir="uploads/images")
#     save_filefield_from_path(my_model_instance, "file", stored, original_name="avatar.jpg", remove_source=False)
#
# 2) Short utility to check size inline:
#
# tmp = write_temp_file(uploaded_file, max_size=10 * 1024 * 1024)
# try:
#     # process tmp
#     pass
# finally:
#     delete_temp_file(tmp)
#
# Notes:
# - Ensure MEDIA_ROOT is writable if you expect local file moves.
# - Default behavior prefers local moves for speed when MEDIA_ROOT is configured.
# - The module intentionally raises explicit FileUtilsError subclasses so callers can handle
#   user-facing API errors (e.g., return 400 when max_size exceeded).
