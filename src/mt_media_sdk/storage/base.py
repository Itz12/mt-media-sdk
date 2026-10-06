from __future__ import annotations

import abc
import dataclasses
import re
import typing as t

if t.TYPE_CHECKING:
    from .storage_settings import StorageBucketSpec, StorageSettings

_KEY_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_KEY_LENGTH = 1024

@dataclasses.dataclass(frozen=True, slots=True)
class PresignedUpload:
    method: str
    url: str
    headers: dict[str, str] = dataclasses.field(default_factory=dict)
    fields: dict[str, str] = dataclasses.field(default_factory=dict)
    expires_in: int = 3600

    def __repr__(self) -> str:
        return f"PresignedUpload(method={self.method!r}, url='<redacted>', expires_in={self.expires_in})"

@dataclasses.dataclass(frozen=True, slots=True)
class UploadedPart:
    part_number: int
    etag: str
    size: int

    def __repr__(self) -> str:
        return f"UploadedPart(part_number={self.part_number}, etag='<redacted>', size={self.size})"

class StorageBackend(abc.ABC):
    supports_native_multipart: bool = False
    # Custom backends must opt in only when ``url`` returns a short-lived,
    # access-controlled URL suitable for private objects.
    supports_private_download_urls: bool = False

    @abc.abstractmethod
    def save(self, path: str, fileobj: t.BinaryIO) -> int: ...
    @abc.abstractmethod
    def open(self, path: str) -> t.BinaryIO: ...
    @abc.abstractmethod
    def delete(self, path: str) -> None: ...
    @abc.abstractmethod
    def exists(self, path: str) -> bool: ...
    @abc.abstractmethod
    def size(self, path: str) -> int: ...
    @abc.abstractmethod
    def url(self, path: str, expire_seconds: int = 3600) -> str: ...

    def presign_put(self, path: str, content_type: str, expire_seconds: int = 3600) -> PresignedUpload:
        raise NotImplementedError(f"{type(self).__name__} does not support presigned uploads.")
    def initiate_multipart(self, path: str, content_type: str) -> str:
        raise NotImplementedError(f"{type(self).__name__} does not support native multipart.")
    def presign_part(self, path: str, upload_id: str, part_number: int, expire_seconds: int = 3600) -> PresignedUpload:
        raise NotImplementedError(f"{type(self).__name__} does not support native multipart.")
    def write_part(self, path: str, upload_id: str, part_number: int, data: bytes) -> UploadedPart:
        raise NotImplementedError(f"{type(self).__name__} does not support server-mediated part writes.")
    def complete_multipart(self, path: str, upload_id: str, parts: list[UploadedPart]) -> None:
        raise NotImplementedError(f"{type(self).__name__} does not support native multipart.")
    def abort_multipart(self, path: str, upload_id: str) -> None:
        raise NotImplementedError(f"{type(self).__name__} does not support native multipart.")

    @classmethod
    def from_bucket_spec(cls, bucket: "StorageBucketSpec", settings: "StorageSettings | None" = None) -> "StorageBackend":
        raise NotImplementedError(f"{cls.__name__} does not support bucket-spec construction.")

    @staticmethod
    def validate_key(path: str) -> str:
        from ..exceptions import StorageBackendError
        key = str(path or "").strip().replace("\\", "/").lstrip("/")
        if not key:
            raise StorageBackendError("Object key/path is required.")
        if len(key) > _MAX_KEY_LENGTH:
            raise StorageBackendError(f"Object key/path must be at most {_MAX_KEY_LENGTH} characters.", path=path)
        if _KEY_CONTROL_CHAR_RE.search(key):
            raise StorageBackendError("Object key/path contains control characters.", path=path)
        parts = key.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise StorageBackendError("Object key/path contains invalid path segments.", path=path)
        return key

    @staticmethod
    def validate_content_type(content_type: str | None) -> str | None:
        from ..exceptions import StorageBackendError
        if content_type is None:
            return None
        value = str(content_type).strip()
        if not value:
            raise StorageBackendError("content_type cannot be empty.")
        if _KEY_CONTROL_CHAR_RE.search(value):
            raise StorageBackendError("content_type contains invalid characters.")
        return value

    @staticmethod
    def validate_expiry(expire_seconds: int) -> int:
        from ..exceptions import StorageBackendError
        try:
            value = int(expire_seconds)
        except (TypeError, ValueError) as exc:
            raise StorageBackendError("expire_seconds must be an integer") from exc
        if value < 60 or value > 86400:
            raise StorageBackendError("expire_seconds must be between 60 and 86400")
        return value
