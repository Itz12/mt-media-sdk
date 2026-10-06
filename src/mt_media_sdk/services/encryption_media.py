from __future__ import annotations

import contextlib
import logging
import os
import secrets
import struct
import tempfile
from io import BytesIO
from pathlib import Path
from typing import IO, Any, BinaryIO, Union

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from .limits import (
    MediaServiceLimits,
    resolve_inside,
    setting_bool,
    setting_csv,
    setting_int,
    validate_storage_path,
)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

try:
    from celery import shared_task

    _HAS_CELERY = True
except Exception:
    _HAS_CELERY = False

    def shared_task(*args: Any, **kwargs: Any):
        def decorator(function):
            return function

        return decorator

try:
    from django.core.files.storage import default_storage
except Exception:
    default_storage = None

Source = Union[str, os.PathLike[str], IO[bytes], bytes, bytearray]
Cipher = Union[Fernet, MultiFernet]

_MAGIC = b"MTME"
_VERSION = 2
_HEADER = struct.Struct(">4sBI16s")
_FRAME_HEADER = struct.Struct(">QBI")  # sequence, flags, encrypted length
_FINAL_FLAG = 0x01
_LEGACY_LENGTH = struct.Struct(">I")


class MediaEncryptionError(Exception):
    pass


class CorruptEncryptedMedia(MediaEncryptionError):
    pass


class UnsafeMediaPath(MediaEncryptionError):
    pass


def _safe_setting(name: str, default: Any) -> Any:
    sentinel = object()
    try:
        from django.conf import settings

        configured = getattr(settings, name, sentinel)
        if configured is not sentinel:
            return configured
    except Exception:
        pass
    return os.environ.get(name, default)


def _configured_keys() -> tuple[bytes, ...]:
    configured = _safe_setting("MEDIA_ENCRYPTION_KEYS", None)
    values: list[Any]
    if configured:
        if isinstance(configured, str):
            values = [item.strip() for item in configured.split(",") if item.strip()]
        elif isinstance(configured, (tuple, list)):
            values = list(configured)
        else:
            raise RuntimeError("MEDIA_ENCRYPTION_KEYS must be a sequence")
    else:
        legacy = _safe_setting("ENCRYPTION_KEY", None)
        values = [legacy] if legacy else []
    if not values:
        raise RuntimeError(
            "Configure MEDIA_ENCRYPTION_KEYS or ENCRYPTION_KEY through the project secret manager"
        )
    keys: list[bytes] = []
    for value in values:
        try:
            key = bytes(value) if isinstance(value, (bytes, bytearray)) else str(value).encode("ascii")
            Fernet(key)
        except Exception as exc:
            raise RuntimeError("A configured media encryption key is invalid") from exc
        if key not in keys:
            keys.append(key)
    return tuple(keys)


def get_fernet_from_settings() -> Cipher:
    ciphers = [Fernet(key) for key in _configured_keys()]
    return ciphers[0] if len(ciphers) == 1 else MultiFernet(ciphers)


def generate_development_key() -> bytes:
    return Fernet.generate_key()


def _open_source(source: Source, storage=None) -> tuple[BinaryIO, bool]:
    if isinstance(source, (bytes, bytearray)):
        return BytesIO(bytes(source)), True
    if isinstance(source, (str, os.PathLike)):
        local = Path(source)
        if local.is_file():
            return local.open("rb"), True
        if storage is not None and all(hasattr(storage, name) for name in ("exists", "open")):
            storage_path = validate_storage_path(str(source))
            if storage.exists(storage_path):
                return storage.open(storage_path, "rb"), True
        raise FileNotFoundError(f"source not found: {source}")
    if not callable(getattr(source, "read", None)):
        raise TypeError("source must be bytes, a path, or a binary stream")
    try:
        source.seek(0)
    except Exception:
        pass
    return source, False


def _encrypt_stream(source: BinaryIO, destination: BinaryIO, cipher: Cipher) -> None:
    limits = MediaServiceLimits.from_settings()
    chunk_size = setting_int(
        "MEDIA_ENCRYPTION_STREAM_CHUNK_BYTES",
        limits.stream_chunk_bytes,
        4096,
        min(limits.encryption_max_frame_bytes // 2, 4 * 1024 * 1024),
    )
    stream_id = secrets.token_bytes(16)
    destination.write(_HEADER.pack(_MAGIC, _VERSION, chunk_size, stream_id))
    sequence = 0
    total_plaintext = 0
    while True:
        chunk = source.read(chunk_size)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        total_plaintext += len(chunk)
        if total_plaintext > limits.max_input_bytes:
            raise MediaEncryptionError("plaintext exceeds MEDIA_MAX_INPUT_BYTES")
        authenticated = stream_id + struct.pack(">QB", sequence, 0) + bytes(chunk)
        token = cipher.encrypt(authenticated)
        if len(token) > limits.encryption_max_frame_bytes:
            raise MediaEncryptionError("encrypted frame exceeds configured limit")
        destination.write(_FRAME_HEADER.pack(sequence, 0, len(token)))
        destination.write(token)
        sequence += 1
        if sequence > limits.encryption_max_frames:
            raise MediaEncryptionError("encrypted stream contains too many frames")
    final_payload = stream_id + struct.pack(">QB", sequence, _FINAL_FLAG)
    final_token = cipher.encrypt(final_payload)
    destination.write(_FRAME_HEADER.pack(sequence, _FINAL_FLAG, len(final_token)))
    destination.write(final_token)


def _decrypt_v2(source: BinaryIO, destination: BinaryIO, cipher: Cipher) -> None:
    limits = MediaServiceLimits.from_settings()
    header = source.read(_HEADER.size)
    if len(header) != _HEADER.size:
        raise CorruptEncryptedMedia("truncated encrypted media header")
    magic, version, chunk_size, stream_id = _HEADER.unpack(header)
    if magic != _MAGIC or version != _VERSION:
        raise CorruptEncryptedMedia("unsupported encrypted media format")
    if not 4096 <= chunk_size <= limits.encryption_max_frame_bytes:
        raise CorruptEncryptedMedia("invalid encrypted media chunk size")
    expected_sequence = 0
    total_plaintext = 0
    final_seen = False
    while True:
        frame_header = source.read(_FRAME_HEADER.size)
        if not frame_header:
            break
        if len(frame_header) != _FRAME_HEADER.size:
            raise CorruptEncryptedMedia("truncated encrypted frame header")
        sequence, flags, token_length = _FRAME_HEADER.unpack(frame_header)
        if sequence != expected_sequence:
            raise CorruptEncryptedMedia("encrypted frames are missing or out of order")
        if flags not in {0, _FINAL_FLAG}:
            raise CorruptEncryptedMedia("encrypted frame flags are invalid")
        if not 1 <= token_length <= limits.encryption_max_frame_bytes:
            raise CorruptEncryptedMedia("encrypted frame length is invalid")
        token = source.read(token_length)
        if len(token) != token_length:
            raise CorruptEncryptedMedia("encrypted frame is truncated")
        try:
            plaintext = cipher.decrypt(token)
        except InvalidToken as exc:
            raise CorruptEncryptedMedia("encrypted media authentication failed") from exc
        prefix = stream_id + struct.pack(">QB", sequence, flags)
        if not plaintext.startswith(prefix):
            raise CorruptEncryptedMedia("encrypted frame binding is invalid")
        content = plaintext[len(prefix) :]
        if flags == _FINAL_FLAG:
            if content:
                raise CorruptEncryptedMedia("final encrypted frame is invalid")
            final_seen = True
            expected_sequence += 1
            if source.read(1):
                raise CorruptEncryptedMedia("trailing data follows final encrypted frame")
            break
        total_plaintext += len(content)
        if total_plaintext > limits.max_output_bytes:
            raise MediaEncryptionError("decrypted media exceeds MEDIA_MAX_OUTPUT_BYTES")
        destination.write(content)
        expected_sequence += 1
        if expected_sequence > limits.encryption_max_frames:
            raise CorruptEncryptedMedia("encrypted media contains too many frames")
    if not final_seen:
        raise CorruptEncryptedMedia("encrypted media is missing its final authenticated frame")


def _decrypt_legacy(source: BinaryIO, destination: BinaryIO, cipher: Cipher) -> None:
    if not setting_bool("MEDIA_ENCRYPTION_ALLOW_LEGACY_FORMAT", False):
        raise CorruptEncryptedMedia("legacy encrypted media is disabled")
    limits = MediaServiceLimits.from_settings()
    total = 0
    frames = 0
    while True:
        raw_length = source.read(_LEGACY_LENGTH.size)
        if not raw_length:
            break
        if len(raw_length) != _LEGACY_LENGTH.size:
            raise CorruptEncryptedMedia("legacy encrypted stream is truncated")
        (token_length,) = _LEGACY_LENGTH.unpack(raw_length)
        if not 1 <= token_length <= limits.encryption_max_frame_bytes:
            raise CorruptEncryptedMedia("legacy encrypted frame length is invalid")
        token = source.read(token_length)
        if len(token) != token_length:
            raise CorruptEncryptedMedia("legacy encrypted frame is truncated")
        try:
            plaintext = cipher.decrypt(token)
        except InvalidToken as exc:
            raise CorruptEncryptedMedia("legacy encrypted media authentication failed") from exc
        total += len(plaintext)
        frames += 1
        if total > limits.max_output_bytes or frames > limits.encryption_max_frames:
            raise MediaEncryptionError("legacy encrypted media exceeds configured limits")
        destination.write(plaintext)


def _write_encrypted_stream_from_fileobj(
    in_fobj: IO[bytes], out_fobj: IO[bytes], fernet: Cipher
) -> None:
    try:
        in_fobj.seek(0)
    except Exception:
        pass
    _encrypt_stream(in_fobj, out_fobj, fernet)


def _read_and_decrypt_stream_to_fileobj(
    in_fobj: IO[bytes], out_fobj: IO[bytes], fernet: Cipher
) -> None:
    try:
        in_fobj.seek(0)
    except Exception:
        pass
    prefix = in_fobj.read(len(_MAGIC))
    try:
        in_fobj.seek(0)
    except Exception:
        raise CorruptEncryptedMedia("encrypted stream must be seekable")
    if prefix == _MAGIC:
        _decrypt_v2(in_fobj, out_fobj, fernet)
    else:
        _decrypt_legacy(in_fobj, out_fobj, fernet)


class _DeletingFile:
    def __init__(self, path: str, mode: str = "rb"):
        self._path = path
        self._file = open(path, mode)

    def __getattr__(self, name: str):
        return getattr(self._file, name)

    def close(self) -> None:
        try:
            self._file.close()
        finally:
            with contextlib.suppress(OSError):
                os.remove(self._path)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


class EncryptionFileHandler:
    def __init__(self, fernet: Cipher | None = None, storage=None):
        self._fernet = fernet
        self.storage = storage if storage is not None else default_storage

    @property
    def fernet(self) -> Cipher:
        """Resolve key material only when an encryption operation needs it."""
        if self._fernet is None:
            self._fernet = get_fernet_from_settings()
        return self._fernet

    @staticmethod
    def _require_storage(storage, *methods: str) -> None:
        if storage is None or any(not callable(getattr(storage, name, None)) for name in methods):
            raise RuntimeError("a compatible Django storage backend is required")

    def _write_to_filesystem_storage_direct(
        self, tmp_src_path: str, dest_storage_path: str
    ) -> str:
        base_location = getattr(self.storage, "_location", None) or getattr(
            self.storage, "location", None
        )
        if not base_location:
            raise RuntimeError("filesystem storage does not expose a location")
        destination = resolve_inside(base_location, dest_storage_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and not setting_bool("MEDIA_STORAGE_ALLOW_OVERWRITE", False):
            raise FileExistsError("destination already exists and overwrite is disabled")
        fd, staging = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
        os.close(fd)
        try:
            if os.name == "posix":
                os.chmod(staging, 0o600)
            with open(tmp_src_path, "rb") as source, open(staging, "wb") as target:
                while True:
                    chunk = source.read(64 * 1024)
                    if not chunk:
                        break
                    target.write(chunk)
                target.flush()
                os.fsync(target.fileno())
            os.replace(staging, destination)
        finally:
            with contextlib.suppress(OSError):
                os.remove(staging)
        return validate_storage_path(dest_storage_path)

    def encrypt_to_storage_path(self, source: Source, dest_storage_path: str) -> str:
        self._require_storage(self.storage, "save", "open", "exists")
        destination = validate_storage_path(dest_storage_path)
        input_stream, owned = _open_source(source, self.storage)
        temporary_path: str | None = None
        try:
            fd, temporary_path = tempfile.mkstemp(suffix=".mtme")
            os.close(fd)
            if os.name == "posix":
                os.chmod(temporary_path, 0o600)
            with open(temporary_path, "wb") as encrypted:
                _encrypt_stream(input_stream, encrypted, self.fernet)
                encrypted.flush()
                os.fsync(encrypted.fileno())
            if getattr(self.storage, "_location", None) or getattr(
                self.storage, "location", None
            ):
                return self._write_to_filesystem_storage_direct(temporary_path, destination)
            try:
                from django.core.files import File
            except Exception:
                File = None
            with open(temporary_path, "rb") as encrypted:
                stored_name = self.storage.save(
                    destination,
                    File(encrypted, name=Path(destination).name) if File else encrypted,
                )
            if not isinstance(stored_name, str):
                raise RuntimeError("storage.save returned an invalid path")
            return validate_storage_path(stored_name)
        finally:
            if owned:
                with contextlib.suppress(Exception):
                    input_stream.close()
            if temporary_path:
                with contextlib.suppress(OSError):
                    os.remove(temporary_path)

    def decrypt_to_bytes(self, source: Union[str, os.PathLike[str], IO[bytes]]) -> bytes:
        input_stream, owned = _open_source(source, self.storage)
        limits = MediaServiceLimits.from_settings()
        output = tempfile.SpooledTemporaryFile(max_size=limits.spool_memory_bytes)
        try:
            _read_and_decrypt_stream_to_fileobj(input_stream, output, self.fernet)
            output.seek(0)
            data = output.read(limits.max_output_bytes + 1)
            if len(data) > limits.max_output_bytes:
                raise MediaEncryptionError("decrypted media exceeds configured output limit")
            return data
        finally:
            output.close()
            if owned:
                with contextlib.suppress(Exception):
                    input_stream.close()

    def stream_decrypted_storage_path(
        self, storage_path: str, download_name: str | None = None
    ):
        try:
            from django.http import FileResponse, HttpResponse
        except Exception as exc:
            raise RuntimeError("Django HTTP utilities are required") from exc
        self._require_storage(self.storage, "open", "exists")
        path = validate_storage_path(storage_path)
        if not self.storage.exists(path):
            return HttpResponse("File not found", status=404)
        fd, temporary_path = tempfile.mkstemp()
        os.close(fd)
        try:
            if os.name == "posix":
                os.chmod(temporary_path, 0o600)
            with self.storage.open(path, "rb") as encrypted, open(
                temporary_path, "wb"
            ) as plaintext:
                _read_and_decrypt_stream_to_fileobj(encrypted, plaintext, self.fernet)
            return FileResponse(
                _DeletingFile(temporary_path),
                as_attachment=True,
                filename=download_name or Path(path).name,
            )
        except CorruptEncryptedMedia:
            with contextlib.suppress(OSError):
                os.remove(temporary_path)
            return HttpResponse("File corrupted or encryption key unavailable", status=403)
        except Exception:
            with contextlib.suppress(OSError):
                os.remove(temporary_path)
            logger.exception("Failed to stream decrypted media")
            return HttpResponse("Failed to stream decrypted file", status=500)


def resolve_model(model_ref: Union[str, type, None]):
    if isinstance(model_ref, type):
        return model_ref
    if not isinstance(model_ref, str) or model_ref.count(".") != 1:
        raise LookupError("model_ref must be a model class or 'app_label.ModelName'")
    app_label, model_name = model_ref.split(".", 1)
    if not app_label or not model_name:
        raise LookupError("model_ref is invalid")
    try:
        from django.apps import apps

        model = apps.get_model(app_label, model_name, require_ready=True)
    except Exception as exc:
        raise LookupError(f"model {model_ref!r} could not be resolved") from exc
    if model is None:
        raise LookupError(f"model {model_ref!r} could not be resolved")
    return model


def _validate_source_temp_path(value: str) -> Path:
    candidate = Path(value).expanduser().resolve()
    roots = setting_csv(
        "MEDIA_TASK_ALLOWED_TEMP_ROOTS",
        (tempfile.gettempdir(),),
    )
    if not candidate.is_file():
        raise FileNotFoundError("source_temp_path does not exist")
    for root_value in roots:
        root = Path(root_value).expanduser().resolve()
        try:
            candidate.relative_to(root)
            return candidate
        except ValueError:
            continue
    raise UnsafeMediaPath("source_temp_path is outside allowed temporary roots")


def _save_encrypt_media_file_task_impl(
    self,
    *,
    source_temp_path: str,
    dest_storage_path: str,
    model_ref: Union[str, type],
    parent_object_id: Union[int, str],
    file_field_name: str,
    encrypt: bool = False,
):
    """Store a temporary media file and attach it to an existing model row.

    The task never creates a missing parent row and validates that the target is
    a Django FileField/ImageField unless compatibility is explicitly enabled.
    """

    source_path = _validate_source_temp_path(source_temp_path)
    destination = validate_storage_path(dest_storage_path)
    model = resolve_model(model_ref)
    try:
        field = model._meta.get_field(file_field_name)
    except Exception as exc:
        raise ValueError("file_field_name does not exist on the target model") from exc
    try:
        from django.db import transaction
        from django.db.models import FileField
    except Exception as exc:
        raise RuntimeError("Django ORM is required for the media attachment task") from exc
    allow_text_field = setting_bool("MEDIA_TASK_ALLOW_TEXT_PATH_FIELDS", False)
    if not isinstance(field, FileField) and not allow_text_field:
        raise ValueError("file_field_name must reference a FileField or ImageField")

    handler = EncryptionFileHandler()
    stored_path: str | None = None
    cleanup_on_failure = setting_bool("MEDIA_TASK_DELETE_SOURCE_ON_FAILURE", False)
    try:
        with transaction.atomic():
            parent = model._default_manager.select_for_update().filter(
                pk=parent_object_id
            ).first()
            if parent is None:
                raise model.DoesNotExist(f"target object {parent_object_id!r} does not exist")
            existing = getattr(parent, file_field_name, None)
            existing_name = getattr(existing, "name", existing)
            if existing_name == destination and handler.storage.exists(destination):
                return {"status": "already_attached", "storage_path": destination}

            if encrypt:
                stored_path = handler.encrypt_to_storage_path(source_path, destination)
            else:
                handler._require_storage(handler.storage, "save", "open", "exists")
                with source_path.open("rb") as source:
                    try:
                        from django.core.files import File
                    except Exception:
                        File = None
                    stored_path = handler.storage.save(
                        destination,
                        File(source, name=Path(destination).name) if File else source,
                    )
                stored_path = validate_storage_path(stored_path)
            setattr(parent, file_field_name, stored_path)
            parent.save(update_fields=[file_field_name])
        source_path.unlink(missing_ok=True)
        return {"status": "stored", "storage_path": stored_path, "encrypted": bool(encrypt)}
    except Exception:
        if stored_path and handler.storage is not None and callable(
            getattr(handler.storage, "delete", None)
        ):
            with contextlib.suppress(Exception):
                handler.storage.delete(stored_path)
        if cleanup_on_failure:
            with contextlib.suppress(OSError):
                source_path.unlink()
        raise


save_encrypt_media_file_task = _save_encrypt_media_file_task_impl
if _HAS_CELERY:
    save_encrypt_media_file_task_celery = shared_task(
        bind=True,
        autoretry_for=(OSError, TimeoutError),
        retry_backoff=True,
        retry_jitter=True,
        max_retries=5,
        ignore_result=False,
    )(_save_encrypt_media_file_task_impl)
else:
    save_encrypt_media_file_task_celery = None


__all__ = [
    "CorruptEncryptedMedia",
    "EncryptionFileHandler",
    "MediaEncryptionError",
    "UnsafeMediaPath",
    "generate_development_key",
    "get_fernet_from_settings",
    "resolve_model",
    "save_encrypt_media_file_task",
    "save_encrypt_media_file_task_celery",
]
