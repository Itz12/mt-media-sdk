from __future__ import annotations

from typing import List
import re

from ..exceptions import StorageBackendError
from .base import PresignedUpload, StorageBackend, UploadedPart



def _django_setting(name: str, default=None):
    try:
        from django.conf import settings as django_settings
        return getattr(django_settings, name, default)
    except Exception:
        return default


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _safe_backend_error(operation: str, path: str, exc: BaseException) -> StorageBackendError:
    return StorageBackendError(f"S3 {operation} failed ({type(exc).__name__})", path=path)


class S3StorageBackend(StorageBackend):
    """
    boto3-backed backend with real native multipart support, so large
    uploads can go client -> S3 directly via presigned URLs without
    round-tripping bytes through the Django app server. ``boto3`` is
    imported lazily so this module - and the rest of the app - loads fine
    even when it isn't installed; only calling into S3 requires it.

    Two ways to configure it
    ~~~~~~~~~~~~~~~~~~~~~~~~~
    1. **Bucket-spec aware** (recommended): resolved via
       ``from_bucket_spec()`` from a ``media.storage.storage_settings.
       StorageBucketSpec`` - which is how ``media.storage.registry.
       get_storage_backend_for_bucket("media")`` builds it. Gets the full
       config surface: endpoint_url (any S3-compatible provider), explicit
       or chain-based credentials, connect/read timeouts, retries, TLS,
       signature version, and path-vs-virtual addressing (the thing that
       most commonly needs to differ for self-hosted stores like MinIO).
    2. **Simple/legacy**: bare ``S3StorageBackend()``, reading
       ``settings.UPLOAD_S3_BUCKET`` / ``UPLOAD_S3_REGION`` /
       ``UPLOAD_S3_ENDPOINT_URL`` / ``UPLOAD_S3_USE_SSL`` directly. Fully
       preserved for existing simple setups; just doesn't get retry/
       timeout/addressing-style control.

    Extending for a provider that needs different *behavior* (not just
    different endpoint/credentials, which method 1 already covers)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Subclass and override one of these hooks rather than reimplementing
    the whole class:

    * ``_extra_put_kwargs(content_type=None)`` - ``ExtraArgs``/``Params``
      merged into every upload/presign/multipart-initiate call. Default
      enforces ``ServerSideEncryption=AES256``; override to add custom
      metadata, a KMS key id, different SSE, etc.
    * ``_build_client()`` - override for a fundamentally different client
      construction path (a different SDK, injected auth, ...).

    Register a custom subclass via ``settings.UPLOAD_STORAGE_BACKENDS =
    {"s3": "myapp.storage.MyBackend"}`` (see ``media.storage.registry``) or
    ``media.storage.registry.register_storage_backend(...)`` and it's
    picked up everywhere ``get_storage_backend`` /
    ``get_storage_backend_for_bucket`` is used, with no other code changes.
    """

    supports_native_multipart = True
    supports_private_download_urls = True

    def __init__(
        self,
        bucket: str | None = None,
        region: str | None = None,
        client=None,
        *,
        endpoint_url: str | None = None,
        use_ssl: bool | None = None,
        bucket_spec=None,
    ):
        # bucket_spec, when provided (normally only via from_bucket_spec),
        # is the source of truth; explicit bucket/region/etc. kwargs still
        # win if someone passes both, for predictability.
        self._bucket_spec = bucket_spec
        spec_bucket = getattr(bucket_spec, "bucket_name", None) if bucket_spec else None

        self.bucket = bucket or spec_bucket or _django_setting("UPLOAD_S3_BUCKET", None)
        if not self.bucket:
            raise StorageBackendError("settings.UPLOAD_S3_BUCKET is not configured.")

        self.region = region or getattr(bucket_spec, "region_name", None) or _django_setting("UPLOAD_S3_REGION", None)
        self.endpoint_url = endpoint_url or getattr(bucket_spec, "endpoint_url", None) or _django_setting("UPLOAD_S3_ENDPOINT_URL", None)
        self.use_ssl = use_ssl if use_ssl is not None else getattr(bucket_spec, "use_ssl", None)
        if self.use_ssl is None:
            self.use_ssl = _django_setting("UPLOAD_S3_USE_SSL", True)

        self._client = client

    @classmethod
    def from_bucket_spec(cls, bucket, settings=None) -> "S3StorageBackend":
        """
        Build an instance whose underlying boto3 client is fully derived
        from ``bucket`` (a ``StorageBucketSpec``) via
        ``storage_settings.get_s3_client_for_bucket`` - endpoint,
        credentials, timeouts, retries, SSL, signature version, and
        addressing style all applied and centrally cached/TTL'd. This is
        what ``media.storage.registry.get_storage_backend_for_bucket``
        calls; construct it directly if you're wiring things up by hand.
        """
        if not bucket.is_remote():
            raise StorageBackendError(
                f"Cannot build an S3StorageBackend for bucket alias '{bucket.alias}': no bucket_name configured."
            )
        from .storage_settings import get_s3_client_for_bucket

        client = get_s3_client_for_bucket(bucket)
        return cls(bucket=bucket.bucket_name, region=bucket.region_name, client=client, bucket_spec=bucket)

    def _build_client(self):
        """Overridable client construction for the simple/legacy
        (non-bucket-spec) path. Subclasses needing a fundamentally
        different client (different SDK, injected auth flow, ...) should
        override this rather than the ``client`` property itself."""
        try:
            import boto3
        except ImportError as exc:
            raise StorageBackendError("boto3 is required for S3StorageBackend but is not installed.") from exc
        kwargs: dict[str, object] = {"region_name": self.region, "use_ssl": self.use_ssl}
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url
        return boto3.client("s3", **kwargs)

    @property
    def client(self):
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def _extra_put_kwargs(self, content_type: str | None = None) -> dict[str, object]:
        """ExtraArgs/Params merged into upload/presign/multipart-initiate
        calls. Default enforces server-side encryption even if the bucket
        doesn't have default encryption configured (defense in depth);
        override in a subclass to customize (different SSE, a KMS key id,
        custom metadata, ...)."""
        extra = getattr(self._bucket_spec, "s3_object_parameters", None)
        params: dict[str, object] = dict(extra()) if callable(extra) else {"ServerSideEncryption": "AES256"}
        if content_type:
            params.setdefault("ContentType", content_type)
        return params

    def save(self, path, fileobj) -> int:
        key = self.validate_key(path)
        try:
            self.client.upload_fileobj(fileobj, self.bucket, key, ExtraArgs=self._extra_put_kwargs() or None)
            return self.size(key)
        except Exception as exc:
            raise _safe_backend_error("upload", path, exc) from exc

    def open(self, path):
        key = self.validate_key(path)
        try:
            obj = self.client.get_object(Bucket=self.bucket, Key=key)
            return obj["Body"]
        except Exception as exc:
            raise _safe_backend_error("get_object", path, exc) from exc

    def delete(self, path) -> None:
        key = self.validate_key(path)
        try:
            self.client.delete_object(Bucket=self.bucket, Key=key)
        except Exception as exc:
            raise _safe_backend_error("delete_object", path, exc) from exc

    def _is_not_found_error(self, exc: Exception) -> bool:
        response = getattr(exc, "response", None)
        if not isinstance(response, dict):
            return False
        error = response.get("Error", {}) or {}
        code = str(error.get("Code", ""))
        status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return code in {"404", "NoSuchKey", "NotFound"} or status == 404

    def exists(self, path) -> bool:
        key = self.validate_key(path)
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception as exc:
            if self._is_not_found_error(exc):
                return False
            # A permissions error (403) or a transient network/throttling
            # failure is NOT "the file doesn't exist" - conflating the two
            # used to make misconfigured credentials look like missing
            # files (silently "successful" no-ops, re-uploads, or worse,
            # code treating "doesn't exist yet" as license to overwrite).
            # Surface it loudly instead.
            raise _safe_backend_error("head_object", path, exc) from exc

    def size(self, path) -> int:
        key = self.validate_key(path)
        try:
            head = self.client.head_object(Bucket=self.bucket, Key=key)
            return int(head["ContentLength"])
        except Exception as exc:
            raise _safe_backend_error("head_object", path, exc) from exc

    def url(self, path, expire_seconds: int = 3600) -> str:
        key = self.validate_key(path)
        try:
            return self.client.generate_presigned_url(
                "get_object", Params={"Bucket": self.bucket, "Key": key}, ExpiresIn=self.validate_expiry(expire_seconds),
            )
        except Exception as exc:
            raise _safe_backend_error("presign_get", path, exc) from exc

    def presign_put(self, path, content_type, expire_seconds: int = 3600) -> PresignedUpload:
        key = self.validate_key(path)
        content_type = self.validate_content_type(content_type)
        try:
            params = {"Bucket": self.bucket, "Key": key, "ContentType": content_type}
            params.update({k: v for k, v in self._extra_put_kwargs(content_type).items() if k not in params})
            expires = self.validate_expiry(expire_seconds)
            url = self.client.generate_presigned_url("put_object", Params=params, ExpiresIn=expires)
            return PresignedUpload(method="PUT", url=url, headers={"Content-Type": content_type}, expires_in=expires)
        except Exception as exc:
            raise _safe_backend_error("presign_put", path, exc) from exc

    def initiate_multipart(self, path, content_type) -> str:
        key = self.validate_key(path)
        content_type = self.validate_content_type(content_type) or "application/octet-stream"
        try:
            kwargs = {"Bucket": self.bucket, "Key": key, "ContentType": content_type}
            kwargs.update({k: v for k, v in self._extra_put_kwargs(content_type).items() if k not in kwargs})
            resp = self.client.create_multipart_upload(**kwargs)
            return resp["UploadId"]
        except Exception as exc:
            raise _safe_backend_error("create_multipart_upload", path, exc) from exc

    def presign_part(self, path, upload_id, part_number, expire_seconds: int = 3600) -> PresignedUpload:
        key = self.validate_key(path)
        upload_id = str(upload_id or "").strip()
        if not upload_id or len(upload_id) > 1024 or _CONTROL_RE.search(upload_id):
            raise StorageBackendError("Invalid multipart upload id", path=path)
        if part_number < 1 or part_number > 10000:
            raise StorageBackendError(f"S3 part numbers must be between 1 and 10000, got {part_number}.")
        try:
            url = self.client.generate_presigned_url(
                "upload_part",
                Params={"Bucket": self.bucket, "Key": key, "UploadId": upload_id, "PartNumber": part_number},
                ExpiresIn=self.validate_expiry(expire_seconds),
            )
            return PresignedUpload(method="PUT", url=url, expires_in=self.validate_expiry(expire_seconds))
        except Exception as exc:
            raise _safe_backend_error("presign_part", path, exc) from exc

    def write_part(self, path, upload_id, part_number, data: bytes) -> UploadedPart:
        key = self.validate_key(path)
        if not isinstance(data, (bytes, bytearray, memoryview)) or not data:
            raise StorageBackendError("Multipart part data must be non-empty bytes", path=path)
        max_upload = getattr(self._bucket_spec, "max_upload_bytes", None)
        if max_upload is not None and len(data) > int(max_upload):
            raise StorageBackendError("Multipart part exceeds the configured upload limit", path=path)
        upload_id = str(upload_id or "").strip()
        if not upload_id or len(upload_id) > 1024 or _CONTROL_RE.search(upload_id):
            raise StorageBackendError("Invalid multipart upload id", path=path)
        if part_number < 1 or part_number > 10000:
            raise StorageBackendError(f"S3 part numbers must be between 1 and 10000, got {part_number}.")
        try:
            resp = self.client.upload_part(Bucket=self.bucket, Key=key, UploadId=upload_id, PartNumber=part_number, Body=data)
            return UploadedPart(part_number=part_number, etag=resp["ETag"], size=len(data))
        except Exception as exc:
            raise _safe_backend_error("upload_part", path, exc) from exc

    def complete_multipart(self, path, upload_id, parts: List[UploadedPart]) -> None:
        key = self.validate_key(path)
        upload_id = str(upload_id or "").strip()
        if not upload_id or len(upload_id) > 1024 or _CONTROL_RE.search(upload_id):
            raise StorageBackendError("Invalid multipart upload id", path=path)
        if not parts:
            raise StorageBackendError(f"S3 complete_multipart_upload requires at least one part for {path}.")
        try:
            # S3 requires parts in ascending PartNumber order; sorting
            # defensively here means a caller that forgot to order them
            # (or a custom UploadPart source that doesn't guarantee it)
            # doesn't get a confusing S3-side InvalidPartOrder error.
            ordered = sorted(parts, key=lambda p: p.part_number)
            numbers = [part.part_number for part in ordered]
            if len(numbers) != len(set(numbers)) or any(number < 1 or number > 10000 for number in numbers):
                raise StorageBackendError("Multipart parts contain duplicate or invalid part numbers", path=path)
            if any(not str(part.etag).strip() or _CONTROL_RE.search(str(part.etag)) for part in ordered):
                raise StorageBackendError("Multipart parts contain invalid ETags", path=path)
            self.client.complete_multipart_upload(
                Bucket=self.bucket, Key=key, UploadId=upload_id,
                MultipartUpload={"Parts": [{"ETag": p.etag, "PartNumber": p.part_number} for p in ordered]},
            )
        except StorageBackendError:
            raise
        except Exception as exc:
            raise _safe_backend_error("complete_multipart_upload", path, exc) from exc

    def abort_multipart(self, path, upload_id) -> None:
        key = self.validate_key(path)
        upload_id = str(upload_id or "").strip()
        if not upload_id or len(upload_id) > 1024 or _CONTROL_RE.search(upload_id):
            raise StorageBackendError("Invalid multipart upload id", path=path)
        try:
            self.client.abort_multipart_upload(Bucket=self.bucket, Key=key, UploadId=upload_id)
        except Exception as exc:
            raise _safe_backend_error("abort_multipart_upload", path, exc) from exc


    def __repr__(self) -> str:
        return f"S3StorageBackend(bucket={self.bucket!r}, region={self.region!r}, endpoint_configured={self.endpoint_url is not None})"
