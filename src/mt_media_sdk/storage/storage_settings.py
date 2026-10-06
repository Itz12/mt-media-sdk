from __future__ import annotations

"""
storage_settings.py

Production-ready, importable storage configuration for Django settings.

Features
- Private media URLs with signed URL generation
- Multiple storage aliases: media, staticfiles, backups
- Automatic bucket validation at startup
- Backup bucket support
- Object lifecycle policies
- Storage metrics and health monitoring
- Optional multi-region bucket failover
- Virus scanning hooks for uploaded files
- Extensible dotted-path hooks for project-specific components
- Thread-safe S3 client caching
- Configuration fingerprinting
- Safer object key and metadata validation
- Optional bucket capability validation hooks
- Deterministic backend configuration generation
"""

from dataclasses import dataclass, field, replace
from functools import lru_cache
import hashlib
import importlib
import json
import logging
import os
import re
import threading
import unicodedata
from pathlib import Path
from time import monotonic
from typing import Callable, Literal, Mapping, Protocol, TypeAlias, runtime_checkable
from urllib.parse import quote, urlparse

logger = logging.getLogger("mt_media_sdk.storage")

StorageMode: TypeAlias = Literal["auto", "filesystem", "s3"]
StorageAlias: TypeAlias = Literal["default", "media", "staticfiles", "backups"]
StorageProvider: TypeAlias = Literal["aws", "backblaze", "custom"]


class StorageError(RuntimeError):
    """Base storage configuration/runtime error."""


class StorageValidationError(StorageError):
    """Raised when storage settings are invalid."""


class BucketValidationError(StorageValidationError):
    """Raised when a bucket or alias configuration is invalid."""


class StorageHealthError(StorageError):
    """Raised when startup health checks fail."""


@runtime_checkable
class VirusScanHook(Protocol):
    def __call__(
        self,
        file_path: Path,
        *,
        object_key: str | None = None,
        bucket_name: str | None = None,
    ) -> None: ...


@runtime_checkable
class MetricsSink(Protocol):
    def __call__(self, event: str, payload: Mapping[str, object]) -> None: ...


@runtime_checkable
class BucketValidator(Protocol):
    def __call__(
        self,
        bucket: "StorageBucketSpec",
        settings: "StorageSettings",
    ) -> None: ...


@runtime_checkable
class StorageHealthProbe(Protocol):
    def __call__(
        self,
        bucket: "StorageBucketSpec",
        settings: "StorageSettings",
    ) -> tuple[bool, str]: ...


_BUCKET_RE = re.compile(
    r"^(?![0-9]+(?:\.[0-9]+){3}$)(?!.*\.\.)(?!.*\.-)(?!.*-\.)[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])?$"
)
_DOTTED_PATH_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$|^[A-Za-z_][A-Za-z0-9_.]*\.[A-Za-z_][A-Za-z0-9_]*$"
)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_OBJECT_KEY_LENGTH = 1024
_CLIENT_CACHE_LOCK = threading.RLock()
_CLIENT_CACHE: dict[tuple[object, ...], tuple[object, float]] = {}

# S3 clients built from *explicit* static credentials (access key/secret/
# session token passed directly, as opposed to boto3's own credential
# provider chain - env/IAM role/SSO/etc, which refreshes itself) are cached
# indefinitely by bucket_name-independent config. That's a problem for STS/
# temporary credentials, which commonly expire in an hour or less: without
# a TTL, this module would keep authenticating with an expired session
# token until the process restarts. _CLIENT_CACHE_TTL_SECONDS forces cached
# clients to be rebuilt periodically so rotated/refreshed credentials in
# the environment actually get picked up. _CLIENT_CACHE_MAX_SIZE bounds
# memory use for deployments juggling many distinct bucket configurations.
_CLIENT_CACHE_TTL_SECONDS = 2700  # 45 minutes - comfortably under typical 1h STS TTLs
_CLIENT_CACHE_MAX_SIZE = 64

# Cloud metadata service addresses. An endpoint_url/custom_domain pointed
# here - whether by a typo, a compromised config source, or a malicious
# STORAGE_*_ENDPOINT_URL - would turn every "S3" call this module makes
# into a request against the instance metadata service, which is a classic
# SSRF-to-credential-theft vector on EC2/ECS/GKE/etc. There's no legitimate
# reason a storage endpoint would ever point here, so it's blocked outright.
_BLOCKED_ENDPOINT_HOSTS = {
    "169.254.169.254",  # AWS/GCP/Azure IMDS
    "fd00:ec2::254",  # AWS IMDSv2 (IPv6)
    "metadata.google.internal",
}

# S3 canned ACLs, per AWS's documented list. Rejecting anything outside
# this set catches typos early (at config-validation time, not at the
# first failed upload), and lets us flag a dangerous combination
# elsewhere: a bucket alias marked private_urls=True (media, backups)
# should never carry a public-read* ACL.
_VALID_CANNED_ACLS = {
    "private",
    "public-read",
    "public-read-write",
    "authenticated-read",
    "aws-exec-read",
    "bucket-owner-read",
    "bucket-owner-full-control",
    "log-delivery-write",
}
_PUBLIC_CANNED_ACLS = {"public-read", "public-read-write"}


def _redact_secret(value: str | None) -> str | None:
    """Return a constant display-safe marker without leaking prefixes or length."""
    return None if value is None else "***REDACTED***"


def _credential_fingerprint(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_error_detail(exc: BaseException) -> str:
    """Return a stable diagnostic that cannot echo provider credentials or URLs."""
    return type(exc).__name__


def _env_get(env: Mapping[str, str], name: str, default: str | None = None) -> str | None:
    value = env.get(name)
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _env_bool(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = _env_get(env, name)
    if raw is None:
        return default
    lowered = raw.casefold()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise StorageValidationError(f"{name} must be a boolean value")


def _env_int(
    env: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    raw = _env_get(env, name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise StorageValidationError(f"{name} must be an integer") from exc
    if minimum is not None and value < minimum:
        raise StorageValidationError(f"{name} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise StorageValidationError(f"{name} must be at most {maximum}")
    return value


def _parse_csv(value: str | None) -> tuple[str, ...]:
    text = str(value or "").strip()
    if not text:
        return ()
    items: list[str] = []
    seen: set[str] = set()
    for raw in text.split(","):
        item = raw.strip()
        if item and item not in seen:
            seen.add(item)
            items.append(item)
    return tuple(items)


def _load_json_or_csv(value: str | None) -> tuple[str, ...]:
    text = str(value or "").strip()
    if not text:
        return ()
    if text.startswith("["):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise StorageValidationError("Expected JSON array or comma-separated string") from exc
        if not isinstance(payload, list):
            raise StorageValidationError("Expected a JSON array")
        values: list[str] = []
        seen: set[str] = set()
        for item in payload:
            item_text = str(item).strip()
            if item_text and item_text not in seen:
                seen.add(item_text)
                values.append(item_text)
        return tuple(values)
    return _parse_csv(text)


def _normalize_unicode_text(value: str) -> str:
    return unicodedata.normalize("NFKC", str(value))


def _validate_no_control_chars(value: str, *, field_name: str) -> None:
    if _CONTROL_CHAR_RE.search(value):
        raise StorageValidationError(f"{field_name} contains control characters")


def _normalize_bucket_name(value: str, *, field_name: str) -> str:
    bucket = _normalize_unicode_text(str(value or "")).strip().lower()
    if not bucket:
        raise BucketValidationError(f"{field_name} is required")
    if len(bucket) < 3 or len(bucket) > 63:
        raise BucketValidationError(f"{field_name} must be between 3 and 63 characters")
    if not _BUCKET_RE.fullmatch(bucket):
        raise BucketValidationError(f"{field_name} is not a valid bucket name")
    return bucket


def _normalize_region(value: str | None, *, default: str) -> str:
    region = _normalize_unicode_text(str(value or "")).strip()
    return region or default


def _normalize_https_url(value: str, *, field_name: str, allow_http: bool) -> str:
    url = _normalize_unicode_text(str(value or "")).strip().rstrip("/")
    if not url:
        raise StorageValidationError(f"{field_name} is required")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise StorageValidationError(f"{field_name} must use http:// or https://")
    if parsed.scheme == "http" and not allow_http:
        raise StorageValidationError(f"{field_name} must use https:// outside development")
    if not parsed.netloc:
        raise StorageValidationError(f"{field_name} must be an absolute URL")
    if parsed.username is not None or parsed.password is not None:
        raise StorageValidationError(f"{field_name} must not contain credentials")
    if parsed.query or parsed.fragment:
        raise StorageValidationError(f"{field_name} must not contain a query string or fragment")
    _validate_endpoint_host_safety(parsed.hostname, field_name=field_name)
    return url


def _validate_endpoint_host_safety(hostname: str | None, *, field_name: str) -> None:
    """Reject cloud metadata-service hosts outright. See
    _BLOCKED_ENDPOINT_HOSTS for the rationale (SSRF-to-credential-theft)."""
    if not hostname:
        return
    host = hostname.strip().lower().rstrip(".")
    if host in _BLOCKED_ENDPOINT_HOSTS:
        raise StorageValidationError(
            f"{field_name} may not point at a cloud metadata service address ({host})."
        )


def _safe_relative_path(value: str | None, default: str) -> str:
    text = _normalize_unicode_text(str(value or "")).strip()
    path = text or default
    normalized = path.replace("\\", "/").strip("/")
    if not normalized:
        return default.strip("/")
    parts = [part for part in normalized.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise StorageValidationError("Path values cannot contain traversal segments")
    for part in parts:
        _validate_no_control_chars(part, field_name="path")
    return "/".join(parts)


def _safe_url_path(value: str | None, default: str) -> str:
    path = _safe_relative_path(value, default)
    return f"/{path}".replace("//", "/")


def _sanitize_object_key(value: str) -> str:
    key = _normalize_unicode_text(str(value or "")).strip().replace("\\", "/").lstrip("/")
    if not key:
        raise StorageValidationError("object_key is required")
    if len(key) > _MAX_OBJECT_KEY_LENGTH:
        raise StorageValidationError(f"object_key must be at most {_MAX_OBJECT_KEY_LENGTH} characters")
    _validate_no_control_chars(key, field_name="object_key")
    parts = key.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise StorageValidationError("object_key contains invalid path segments")
    return key


def _validate_content_type(value: str) -> str:
    content_type = _normalize_unicode_text(value).strip()
    if not content_type:
        raise StorageValidationError("content_type cannot be empty")
    if _CONTROL_CHAR_RE.search(content_type) or "\n" in content_type or "\r" in content_type:
        raise StorageValidationError("content_type contains invalid characters")
    return content_type


@lru_cache(maxsize=128)
def _import_dotted_callable_cached(path: str, expected: str) -> Callable[..., object]:
    candidate = _normalize_unicode_text(path).strip()
    if not candidate:
        raise StorageValidationError(f"{expected} cannot be empty")
    if not _DOTTED_PATH_RE.fullmatch(candidate):
        raise StorageValidationError(
            f"{expected} must be a dotted path like 'package.module:function' or 'package.module.function'"
        )

    module_name, _, attr_name = candidate.replace(":", ".").rpartition(".")
    if not module_name or not attr_name:
        raise StorageValidationError(f"{expected} must reference a callable")

    module = importlib.import_module(module_name)
    hook = getattr(module, attr_name, None)
    if not callable(hook):
        raise StorageValidationError(f"{expected} must point to a callable")
    return hook


def _settings_current_utc() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _guess_backblaze_endpoint(region_name: str | None) -> str | None:
    region = _normalize_unicode_text(str(region_name or "")).strip()
    if not region:
        return None
    return f"https://s3.{region}.backblazeb2.com"


def _normalize_provider(value: str | None, *, default: StorageProvider) -> StorageProvider:
    provider = _normalize_unicode_text(str(value or "")).strip().casefold()
    if not provider:
        return default
    if provider == "aws":
        return "aws"
    if provider == "backblaze":
        return "backblaze"
    if provider == "custom":
        return "custom"
    raise StorageValidationError("Storage provider must be aws, backblaze, or custom")


def _s3_client_cache_key(bucket: "StorageBucketSpec") -> tuple[object, ...]:
    return (
        bucket.provider,
        bucket.region_name,
        bucket.endpoint_url,
        _credential_fingerprint(bucket.access_key_id),
        _credential_fingerprint(bucket.secret_access_key),
        _credential_fingerprint(bucket.session_token),
        bucket.connect_timeout_seconds,
        bucket.read_timeout_seconds,
        bucket.max_retries,
        bucket.retry_mode,
        bucket.use_ssl,
        bucket.signature_version,
        bucket.addressing_style,
    )


def _build_s3_client(bucket: "StorageBucketSpec"):
    try:
        import boto3  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover
        raise StorageValidationError("boto3 is required for remote storage operations") from exc

    kwargs: dict[str, object] = {
        "region_name": bucket.region_name,
        "endpoint_url": bucket.endpoint_url,
        # Previously not wired through at all: a bucket configured with
        # use_ssl=False (e.g. a local MinIO instance without TLS) had zero
        # effect on the client actually built here.
        "use_ssl": bucket.use_ssl,
    }
    if bucket.access_key_id:
        kwargs["aws_access_key_id"] = bucket.access_key_id
    if bucket.secret_access_key:
        kwargs["aws_secret_access_key"] = bucket.secret_access_key
    if bucket.session_token:
        kwargs["aws_session_token"] = bucket.session_token

    try:
        from botocore.config import Config  # type: ignore[import-not-found]
        retries: dict[str, object] = {
            "max_attempts": max(0, bucket.max_retries),
            "mode": bucket.retry_mode,
        }
        kwargs["config"] = Config(
            connect_timeout=max(1, bucket.connect_timeout_seconds),
            read_timeout=max(1, bucket.read_timeout_seconds),
            retries=retries,
            signature_version=bucket.signature_version,
            s3={"addressing_style": bucket.addressing_style},
        )
    except Exception as exc:
        raise StorageValidationError(
            f"Unable to apply the configured S3 transport policy for {bucket.alias}"
        ) from exc

    return boto3.client("s3", **kwargs)


def _build_s3_client_cached(bucket: "StorageBucketSpec"):
    cache_key = _s3_client_cache_key(bucket)
    now = monotonic()
    with _CLIENT_CACHE_LOCK:
        entry = _CLIENT_CACHE.get(cache_key)
        if entry is not None:
            client, created_at = entry
            if now - created_at < _CLIENT_CACHE_TTL_SECONDS:
                return client
            # Stale - fall through and rebuild, so a client built from
            # since-rotated/expired static credentials doesn't get reused
            # forever. (Clients relying on boto3's own credential chain -
            # no explicit access_key_id/secret_access_key - refresh
            # themselves regardless; rebuilding them periodically is
            # harmless, just slightly wasteful.)
            _CLIENT_CACHE.pop(cache_key, None)

        client = _build_s3_client(bucket)
        if len(_CLIENT_CACHE) >= _CLIENT_CACHE_MAX_SIZE:
            # Bound memory for deployments juggling many distinct bucket
            # configurations (e.g. per-tenant credentials): evict the
            # oldest entry rather than growing without limit.
            oldest_key = min(_CLIENT_CACHE, key=lambda k: _CLIENT_CACHE[k][1])
            _CLIENT_CACHE.pop(oldest_key, None)
        _CLIENT_CACHE[cache_key] = (client, now)
        return client


def clear_s3_client_cache() -> None:
    """Force every cached S3 client to be rebuilt on next use. Useful after
    a manual credential rotation, or in tests that swap env vars mid-run."""
    with _CLIENT_CACHE_LOCK:
        _CLIENT_CACHE.clear()


def _bucket_suffixes(alias: StorageAlias) -> tuple[str, ...]:
    if alias == "media":
        return ("media",)
    if alias == "staticfiles":
        return ("staticfiles",)
    if alias == "backups":
        return ("backups",)
    return ("default",)


@dataclass(frozen=True, slots=True)
class StorageLifecycleRule:
    prefix: str
    expiration_days: int | None = None
    transition_days: int | None = None
    storage_class: str | None = None
    enabled: bool = True

    def validate(self) -> None:
        prefix = _normalize_unicode_text(str(self.prefix or "")).strip()
        if not prefix:
            raise StorageValidationError("Lifecycle rule prefix cannot be empty")
        _validate_no_control_chars(prefix, field_name="lifecycle prefix")
        if self.expiration_days is not None and self.expiration_days < 1:
            raise StorageValidationError("Lifecycle expiration_days must be at least 1")
        if self.transition_days is not None and self.transition_days < 1:
            raise StorageValidationError("Lifecycle transition_days must be at least 1")
        if self.storage_class is not None and not str(self.storage_class).strip():
            raise StorageValidationError("Lifecycle storage_class cannot be empty")

    def as_dict(self) -> dict[str, object]:
        return {
            "prefix": self.prefix,
            "expiration_days": self.expiration_days,
            "transition_days": self.transition_days,
            "storage_class": self.storage_class,
            "enabled": self.enabled,
        }


@dataclass(frozen=True, slots=True)
class StorageFailoverConfig:
    enabled: bool
    secondary_region: str | None = None
    secondary_bucket: str | None = None
    secondary_endpoint_url: str | None = None
    fail_closed: bool = True
    retry_attempts: int = 1
    prefer_secondary_on_health_failure: bool = True

    def validate(self, *, allow_http: bool) -> None:
        if not self.enabled:
            return
        if not self.secondary_bucket:
            raise StorageValidationError("STORAGE_FAILOVER_SECONDARY_BUCKET is required when failover is enabled")
        if self.secondary_region is None or not self.secondary_region.strip():
            raise StorageValidationError("STORAGE_FAILOVER_SECONDARY_REGION is required when failover is enabled")
        _normalize_bucket_name(self.secondary_bucket, field_name="STORAGE_FAILOVER_SECONDARY_BUCKET")
        if self.secondary_endpoint_url:
            _normalize_https_url(
                self.secondary_endpoint_url,
                field_name="STORAGE_FAILOVER_SECONDARY_ENDPOINT_URL",
                allow_http=allow_http,
            )
        if self.retry_attempts < 0:
            raise StorageValidationError("STORAGE_FAILOVER_RETRY_ATTEMPTS cannot be negative")


@dataclass(frozen=True, slots=True)
class StorageMetricsConfig:
    enabled: bool = True
    prefix: str = "mt_media_sdk.storage"
    emit_latency_histogram: bool = True
    emit_health_gauge: bool = True
    log_level: int = logging.INFO
    sink_path: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "prefix": self.prefix,
            "emit_latency_histogram": self.emit_latency_histogram,
            "emit_health_gauge": self.emit_health_gauge,
            "log_level": self.log_level,
            "sink_path": self.sink_path,
        }


@dataclass(frozen=True, slots=True)
class StorageBucketSpec:
    alias: StorageAlias
    bucket_name: str | None
    provider: StorageProvider = "aws"
    region_name: str | None = None
    endpoint_url: str | None = None
    custom_domain: str | None = None
    access_key_id: str | None = None
    secret_access_key: str | None = None
    session_token: str | None = None
    file_overwrite: bool = False
    querystring_auth: bool = True
    default_acl: str | None = None
    object_parameters: Mapping[str, object] = field(default_factory=dict)
    location: str | None = None
    private_urls: bool = False
    validate_at_startup: bool = True
    connect_timeout_seconds: int = 3
    read_timeout_seconds: int = 5
    max_retries: int = 3
    retry_mode: str = "standard"
    use_ssl: bool = True
    signature_version: str = "s3v4"
    # "virtual" (bucket.host.tld/key) works for AWS and most managed
    # providers with wildcard-subdomain DNS. Self-hosted S3-compatible
    # stores (MinIO, on-prem Ceph/RGW, some internal setups) very commonly
    # *require* "path" (host.tld/bucket/key) because there's no DNS
    # wildcard routing bucket subdomains anywhere - this is one of the
    # most common reasons "just point it at MinIO" doesn't work out of the
    # box, so it's a first-class, per-bucket setting rather than something
    # you'd have to subclass the backend to change.
    addressing_style: str = "virtual"
    cache_control: str | None = None
    bucket_policy: str | None = None
    enforce_content_length: bool = False
    max_upload_bytes: int | None = None

    def is_remote(self) -> bool:
        return self.bucket_name is not None

    def validate(self, *, allow_http: bool) -> None:
        if self.bucket_name:
            _normalize_bucket_name(self.bucket_name, field_name=f"{self.alias}_bucket_name")
        if self.provider not in {"aws", "backblaze", "custom"}:
            raise StorageValidationError(f"{self.alias}_provider must be aws, backblaze, or custom")
        if self.provider == "backblaze" and self.signature_version != "s3v4":
            raise StorageValidationError("Backblaze requires s3v4 signatures")
        if bool(self.access_key_id) != bool(self.secret_access_key):
            raise StorageValidationError(
                f"{self.alias} explicit credentials require both access_key_id and secret_access_key"
            )
        if self.session_token and not (self.access_key_id and self.secret_access_key):
            raise StorageValidationError(
                f"{self.alias} session_token requires explicit access_key_id and secret_access_key"
            )
        if not allow_http and not self.use_ssl:
            raise StorageValidationError(f"{self.alias}_use_ssl must be true outside local development")
        if self.endpoint_url:
            _normalize_https_url(
                self.endpoint_url,
                field_name=f"{self.alias}_endpoint_url",
                allow_http=allow_http,
            )
        if self.custom_domain:
            normalized_domain = self.custom_domain.strip()
            if not normalized_domain.startswith(("http://", "https://")):
                normalized_domain = f"https://{normalized_domain.lstrip('/')}"
            _normalize_https_url(
                normalized_domain,
                field_name=f"{self.alias}_custom_domain",
                allow_http=allow_http,
            )
        if self.location:
            location = self.location.replace("\\", "/")
            if any(part in {".", ".."} for part in location.split("/")):
                raise StorageValidationError(f"{self.alias}_location cannot contain path traversal")
        if self.connect_timeout_seconds < 1:
            raise StorageValidationError(f"{self.alias}_connect_timeout_seconds must be >= 1")
        if self.read_timeout_seconds < 1:
            raise StorageValidationError(f"{self.alias}_read_timeout_seconds must be >= 1")
        if self.max_retries < 0:
            raise StorageValidationError(f"{self.alias}_max_retries cannot be negative")
        if self.retry_mode not in {"standard", "adaptive", "legacy"}:
            raise StorageValidationError(f"{self.alias}_retry_mode must be standard, adaptive, or legacy")
        if self.addressing_style not in {"virtual", "path", "auto"}:
            raise StorageValidationError(f"{self.alias}_addressing_style must be virtual, path, or auto")
        if self.default_acl is not None and not str(self.default_acl).strip():
            raise StorageValidationError(f"{self.alias}_default_acl cannot be empty")
        if self.default_acl is not None and self.default_acl not in _VALID_CANNED_ACLS:
            raise StorageValidationError(
                f"{self.alias}_default_acl '{self.default_acl}' is not a recognized S3 canned ACL "
                f"(expected one of: {', '.join(sorted(_VALID_CANNED_ACLS))})"
            )
        if self.private_urls and self.default_acl in _PUBLIC_CANNED_ACLS:
            # private_urls=True means callers get signed, time-limited URLs
            # specifically because the objects are NOT supposed to be
            # publicly readable. A public-read* ACL on top of that isn't a
            # style choice, it's a data-exposure bug: anyone with the
            # object key (which can leak via logs, referrers, browser
            # history) gets permanent, unauthenticated access regardless of
            # what URL-signing logic this module implements.
            raise StorageValidationError(
                f"{self.alias}_default_acl is '{self.default_acl}' but {self.alias} is a private-urls "
                "bucket - a public ACL would make objects readable without a signed URL, defeating the "
                "point. Use 'private' (or omit default_acl) for private buckets."
            )
        if self.cache_control is not None and not str(self.cache_control).strip():
            raise StorageValidationError(f"{self.alias}_cache_control cannot be empty")
        if self.max_upload_bytes is not None and self.max_upload_bytes < 1:
            raise StorageValidationError(f"{self.alias}_max_upload_bytes must be positive")
        if self.bucket_policy is not None and not str(self.bucket_policy).strip():
            raise StorageValidationError(f"{self.alias}_bucket_policy cannot be empty")

    def s3_object_parameters(self) -> dict[str, object]:
        params: dict[str, object] = dict(self.object_parameters)
        params.setdefault("ServerSideEncryption", "AES256")
        if self.cache_control:
            params.setdefault("CacheControl", self.cache_control)
        if self.enforce_content_length and self.max_upload_bytes is not None:
            params.setdefault("x-amz-meta-max-upload-bytes", str(self.max_upload_bytes))
        return params

    def build_backend_options(self) -> dict[str, object]:
        options: dict[str, object] = {
            "bucket_name": self.bucket_name,
            "file_overwrite": self.file_overwrite,
            "querystring_auth": self.querystring_auth,
            "default_acl": self.default_acl,
            "object_parameters": self.s3_object_parameters(),
            "use_ssl": self.use_ssl,
            "signature_version": self.signature_version,
            "addressing_style": self.addressing_style,
        }
        if self.region_name:
            options["region_name"] = self.region_name
        if self.endpoint_url:
            options["endpoint_url"] = self.endpoint_url
        if self.access_key_id:
            options["access_key"] = self.access_key_id
        if self.secret_access_key:
            options["secret_key"] = self.secret_access_key
        if self.session_token:
            options["security_token"] = self.session_token
        if self.custom_domain:
            options["custom_domain"] = self.custom_domain
        return options

    def as_dict(self) -> dict[str, object]:
        return {
            "alias": self.alias,
            "bucket_name": self.bucket_name,
            "provider": self.provider,
            "region_name": self.region_name,
            "endpoint_url": self.endpoint_url,
            "custom_domain": self.custom_domain,
            "file_overwrite": self.file_overwrite,
            "querystring_auth": self.querystring_auth,
            "default_acl": self.default_acl,
            "location": self.location,
            "private_urls": self.private_urls,
            "validate_at_startup": self.validate_at_startup,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "read_timeout_seconds": self.read_timeout_seconds,
            "max_retries": self.max_retries,
            "retry_mode": self.retry_mode,
            "use_ssl": self.use_ssl,
            "signature_version": self.signature_version,
            "addressing_style": self.addressing_style,
            "cache_control": self.cache_control,
            "bucket_policy": self.bucket_policy,
            "enforce_content_length": self.enforce_content_length,
            "max_upload_bytes": self.max_upload_bytes,
        }

    def __repr__(self) -> str:
        # Deliberately excludes/redacts access_key_id, secret_access_key,
        # and session_token: the default dataclass repr would print them in
        # full, which is exactly the kind of thing that ends up in logs, an
        # error tracker's captured locals, or a debug traceback. See
        # _redact_secret() for what "redacted" looks like.
        return (
            f"{type(self).__name__}(alias={self.alias!r}, bucket_name={self.bucket_name!r}, "
            f"provider={self.provider!r}, region_name={self.region_name!r}, "
            f"endpoint_url={self.endpoint_url!r}, custom_domain={self.custom_domain!r}, "
            f"access_key_id={_redact_secret(self.access_key_id)!r}, "
            f"secret_access_key={_redact_secret(self.secret_access_key)!r}, "
            f"session_token={_redact_secret(self.session_token)!r}, "
            f"private_urls={self.private_urls!r}, use_ssl={self.use_ssl!r}, "
            f"signature_version={self.signature_version!r}, addressing_style={self.addressing_style!r})"
        )


@dataclass(frozen=True, slots=True)
class StorageHealthReport:
    ok: bool
    checked_aliases: tuple[str, ...]
    failures: tuple[str, ...]
    checked_at: str

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "checked_aliases": self.checked_aliases,
            "failures": self.failures,
            "checked_at": self.checked_at,
        }


@dataclass(frozen=True, slots=True)
class StorageSettings:
    environment: str
    is_production: bool
    is_staging: bool
    is_development: bool
    allow_http: bool
    media_url: str
    static_url: str
    backup_root: Path
    storage_mode: StorageMode
    buckets: tuple[StorageBucketSpec, ...]
    lifecycle_rules: tuple[StorageLifecycleRule, ...]
    failover: StorageFailoverConfig
    metrics: StorageMetricsConfig
    private_media_signed_urls: bool
    signed_url_expires_seconds: int
    virus_scan_hook_path: str | None
    validate_remote_buckets: bool
    health_check_enabled: bool
    storages: dict[str, dict[str, object]]
    storage_root: Path
    storage_health_timeout_seconds: int
    strict_startup_validation: bool
    bucket_validator_path: str | None = None
    metrics_sink_path: str | None = None
    private_url_signer_path: str | None = None
    health_probe_path: str | None = None
    private_media_url_prefix: str = "/media/private"
    configuration_digest: str | None = None

    def get_bucket(self, alias: StorageAlias) -> StorageBucketSpec | None:
        for bucket in self.buckets:
            if bucket.alias == alias:
                return bucket
        return None

    def get_remote_bucket(self, alias: StorageAlias) -> StorageBucketSpec | None:
        bucket = self.get_bucket(alias)
        if bucket and bucket.is_remote():
            return bucket
        return None

    def resolve_bucket(self, alias: StorageAlias, *, use_failover: bool = False) -> StorageBucketSpec:
        bucket = self.get_bucket(alias)
        if bucket is None:
            raise StorageValidationError(f"Unknown storage alias: {alias}")
        if use_failover:
            secondary = self._failover_bucket_for(alias)
            if secondary is None:
                if self.failover.fail_closed:
                    raise StorageValidationError(f"No failover bucket is configured for {alias}")
                return bucket
            return secondary
        return bucket

    def resolve_failover_bucket(self, alias: StorageAlias) -> StorageBucketSpec:
        return self.resolve_bucket(alias, use_failover=True)

    def _failover_bucket_for(self, alias: StorageAlias) -> StorageBucketSpec | None:
        if not self.failover.enabled:
            return None
        if alias not in {"default", "media"}:
            return None
        if not self.failover.secondary_bucket or not self.failover.secondary_region:
            return None

        primary = self.get_bucket(alias)
        if primary is None:
            return None

        endpoint = self.failover.secondary_endpoint_url
        if endpoint is None and primary.provider == "backblaze":
            endpoint = _guess_backblaze_endpoint(self.failover.secondary_region)

        return StorageBucketSpec(
            alias=alias,
            bucket_name=self.failover.secondary_bucket,
            provider=primary.provider,
            region_name=self.failover.secondary_region,
            endpoint_url=endpoint,
            custom_domain=primary.custom_domain,
            access_key_id=primary.access_key_id,
            secret_access_key=primary.secret_access_key,
            session_token=primary.session_token,
            file_overwrite=primary.file_overwrite,
            querystring_auth=primary.querystring_auth,
            default_acl=primary.default_acl,
            object_parameters=primary.object_parameters,
            location=primary.location,
            private_urls=primary.private_urls,
            validate_at_startup=primary.validate_at_startup,
            connect_timeout_seconds=primary.connect_timeout_seconds,
            read_timeout_seconds=primary.read_timeout_seconds,
            max_retries=primary.max_retries,
            retry_mode=primary.retry_mode,
            use_ssl=primary.use_ssl,
            signature_version=primary.signature_version,
            addressing_style=primary.addressing_style,
            cache_control=primary.cache_control,
            bucket_policy=primary.bucket_policy,
            enforce_content_length=primary.enforce_content_length,
            max_upload_bytes=primary.max_upload_bytes,
        )

    def _load_private_url_signer(self) -> Callable[..., object] | None:
        if not self.private_url_signer_path:
            return None
        return _import_dotted_callable_cached(self.private_url_signer_path, expected="STORAGE_PRIVATE_URL_SIGNER")

    def _load_metrics_sink(self) -> Callable[..., object] | None:
        if not self.metrics_sink_path:
            return None
        return _import_dotted_callable_cached(self.metrics_sink_path, expected="STORAGE_METRICS_SINK")

    def _load_bucket_validator(self) -> Callable[..., object] | None:
        if not self.bucket_validator_path:
            return None
        return _import_dotted_callable_cached(self.bucket_validator_path, expected="STORAGE_BUCKET_VALIDATOR")

    def _load_health_probe(self) -> Callable[..., object] | None:
        if not self.health_probe_path:
            return None
        return _import_dotted_callable_cached(self.health_probe_path, expected="STORAGE_HEALTH_PROBE")

    def _build_url_from_bucket(self, bucket: StorageBucketSpec, key: str, *, signed: bool, expires: int) -> str:
        encoded_key = quote(key, safe="/")
        if bucket.custom_domain:
            base = bucket.custom_domain.rstrip("/")
            if signed:
                return f"{base}/{encoded_key}?expires={expires}"
            return f"{base}/{encoded_key}"
        return f"{self.media_url.rstrip('/')}/{encoded_key}"

    def build_private_media_url(self, object_key: str, *, expires_seconds: int | None = None) -> str:
        key = _sanitize_object_key(object_key)
        bucket = self.resolve_bucket("media")
        if bucket.bucket_name is None:
            return self._build_url_from_bucket(bucket, key, signed=False, expires=0)

        if not self.private_media_signed_urls:
            return self._build_url_from_bucket(bucket, key, signed=False, expires=0)

        expires = max(60, int(expires_seconds or self.signed_url_expires_seconds))
        custom_signer = self._load_private_url_signer()
        if custom_signer is not None:
            signed = custom_signer(bucket, key, expires)
            signed_text = str(signed or "").strip()
            if not signed_text:
                raise StorageError("Private URL signer returned an empty URL")
            return signed_text

        if bucket.custom_domain and not bucket.querystring_auth:
            if self.is_production or self.is_staging or self.strict_startup_validation:
                raise StorageError(
                    "Private custom-domain URLs require STORAGE_PRIVATE_URL_SIGNER or query-string authentication"
                )
            return self._build_url_from_bucket(bucket, key, signed=False, expires=0)

        try:
            client = _build_s3_client_cached(bucket)
            return client.generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket.bucket_name, "Key": key},
                ExpiresIn=expires,
            )
        except Exception as exc:
            if self.strict_startup_validation or self.is_production or self.is_staging:
                raise StorageError("Unable to generate a private media URL") from exc
            logger.warning("Falling back to non-signed media URL: %s", exc, exc_info=True)
            return self._build_url_from_bucket(bucket, key, signed=False, expires=0)

    def build_private_upload_url(self, object_key: str, *, expires_seconds: int | None = None) -> str:
        key = _sanitize_object_key(object_key)
        bucket = self.resolve_bucket("media")
        if bucket.bucket_name is None:
            return self._build_url_from_bucket(bucket, key, signed=False, expires=0)

        expires = max(60, int(expires_seconds or self.signed_url_expires_seconds))
        custom_signer = self._load_private_url_signer()
        if custom_signer is not None:
            signed = custom_signer(bucket, key, expires, method="put_object")
            signed_text = str(signed or "").strip()
            if not signed_text:
                raise StorageError("Private upload signer returned an empty URL")
            return signed_text

        try:
            client = _build_s3_client_cached(bucket)
            return client.generate_presigned_url(
                "put_object",
                Params={"Bucket": bucket.bucket_name, "Key": key},
                ExpiresIn=expires,
            )
        except Exception as exc:
            if self.strict_startup_validation or self.is_production or self.is_staging:
                raise StorageError("Unable to generate a private upload URL") from exc
            logger.warning("Falling back to non-signed upload URL: %s", exc, exc_info=True)
            return self._build_url_from_bucket(bucket, key, signed=False, expires=0)

    def run_virus_scan_hook(
        self,
        file_path: Path,
        *,
        object_key: str | None = None,
        bucket_name: str | None = None,
    ) -> None:
        if not self.virus_scan_hook_path:
            return
        hook = _import_dotted_callable_cached(self.virus_scan_hook_path, expected="STORAGE_VIRUS_SCAN_HOOK")
        hook(file_path, object_key=object_key, bucket_name=bucket_name)

    def record_metric(
        self,
        event: str,
        *,
        alias: StorageAlias,
        success: bool,
        duration_seconds: float = 0.0,
        detail: str | None = None,
    ) -> None:
        if not self.metrics.enabled:
            return
        event_name = _normalize_unicode_text(event).strip()
        if not event_name:
            raise StorageValidationError("event cannot be empty")
        payload = {
            "event": event_name,
            "alias": alias,
            "success": success,
            "duration_seconds": round(max(0.0, float(duration_seconds)), 6),
            "detail": (str(detail)[:256] if detail is not None else None),
            "environment": self.environment,
        }

        sink = self._load_metrics_sink()
        if sink is not None:
            try:
                sink(event_name, payload)
                return
            except Exception as exc:
                logger.warning("Storage metrics sink failed: %s", exc, exc_info=True)

        logger.log(self.metrics.log_level, "%s %s", self.metrics.prefix, json.dumps(payload, sort_keys=True, default=str))

    def health_check(self) -> StorageHealthReport:
        failures: list[str] = []
        checked: list[str] = []

        extra_probe = self._load_health_probe()

        for bucket in self.buckets:
            if not bucket.validate_at_startup or not bucket.is_remote():
                continue
            checked.append(bucket.alias)
            if extra_probe is not None:
                try:
                    ok, detail = extra_probe(bucket, self)
                    if not ok:
                        failures.append(f"{bucket.alias}: {detail}")
                        continue
                except Exception as exc:
                    failures.append(f"{bucket.alias}: {_safe_error_detail(exc)}")
                    continue
            if self.validate_remote_buckets:
                ok, detail = _validate_remote_bucket(bucket, allow_http=self.allow_http)
                if not ok:
                    failures.append(f"{bucket.alias}: {detail}")

        return StorageHealthReport(
            ok=not failures,
            checked_aliases=tuple(checked),
            failures=tuple(failures),
            checked_at=_settings_current_utc(),
        )

    def assert_startup_ready(self) -> None:
        validate_storage_settings(self)

    def storage_backend_config(self, alias: StorageAlias) -> dict[str, object]:
        return self.storages[alias]

    def as_dict(self) -> dict[str, object]:
        return {
            "environment": self.environment,
            "is_production": self.is_production,
            "is_staging": self.is_staging,
            "is_development": self.is_development,
            "allow_http": self.allow_http,
            "media_url": self.media_url,
            "static_url": self.static_url,
            "backup_root": str(self.backup_root),
            "storage_mode": self.storage_mode,
            "buckets": [bucket.as_dict() for bucket in self.buckets],
            "lifecycle_rules": [rule.as_dict() for rule in self.lifecycle_rules],
            "failover": {
                "enabled": self.failover.enabled,
                "secondary_region": self.failover.secondary_region,
                "secondary_bucket": self.failover.secondary_bucket,
                "secondary_endpoint_url": self.failover.secondary_endpoint_url,
                "fail_closed": self.failover.fail_closed,
                "retry_attempts": self.failover.retry_attempts,
                "prefer_secondary_on_health_failure": self.failover.prefer_secondary_on_health_failure,
            },
            "metrics": self.metrics.as_dict(),
            "private_media_signed_urls": self.private_media_signed_urls,
            "signed_url_expires_seconds": self.signed_url_expires_seconds,
            "validate_remote_buckets": self.validate_remote_buckets,
            "health_check_enabled": self.health_check_enabled,
            "storage_root": str(self.storage_root),
            "storage_health_timeout_seconds": self.storage_health_timeout_seconds,
            "strict_startup_validation": self.strict_startup_validation,
            "private_media_url_prefix": self.private_media_url_prefix,
            "configuration_digest": self.configuration_digest,
        }

    def _backup_bucket(self) -> StorageBucketSpec:
        bucket = self.get_bucket("backups")
        if bucket is None:
            raise StorageValidationError("Backups storage bucket is not configured")
        return bucket

    def build_backup_url(self, object_key: str, *, expires_seconds: int | None = None) -> str:
        key = _sanitize_object_key(object_key)
        bucket = self._backup_bucket()
        if bucket.bucket_name is None:
            return f"/backups/{quote(key, safe='/')}"
        if not bucket.querystring_auth:
            if bucket.custom_domain:
                return f"{bucket.custom_domain.rstrip('/')}/{quote(key, safe='/')}"
            return f"/backups/{quote(key, safe='/')}"
        expires = max(60, int(expires_seconds or self.signed_url_expires_seconds))
        try:
            client = _build_s3_client_cached(bucket)
            return client.generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket.bucket_name, "Key": key},
                ExpiresIn=expires,
            )
        except Exception as exc:
            if self.strict_startup_validation or self.is_production or self.is_staging:
                raise StorageError("Unable to generate a backup URL") from exc
            logger.warning("Falling back to non-signed backup URL: %s", exc, exc_info=True)
            if bucket.custom_domain:
                return f"{bucket.custom_domain.rstrip('/')}/{quote(key, safe='/')}"
            return f"/backups/{quote(key, safe='/')}"

    def build_presigned_post(
        self,
        object_key: str,
        *,
        content_type: str | None = None,
        expires_seconds: int | None = None,
        max_bytes: int | None = None,
    ) -> dict[str, object]:
        key = _sanitize_object_key(object_key)
        bucket = self.resolve_bucket("media")
        if bucket.bucket_name is None:
            raise StorageValidationError("Presigned uploads require a remote bucket")
        expires = max(60, int(expires_seconds or self.signed_url_expires_seconds))
        client = _build_s3_client_cached(bucket)
        conditions: list[object] = []
        fields: dict[str, str] = {}
        if content_type:
            validated_content_type = _validate_content_type(content_type)
            conditions.append({"Content-Type": validated_content_type})
            fields["Content-Type"] = validated_content_type
        if bucket.default_acl:
            conditions.append({"acl": bucket.default_acl})
            fields["acl"] = bucket.default_acl

        # A presigned POST with no content-length-range condition lets the
        # uploader send an object of *any* size - unbounded cost and a DoS
        # vector, since the request never touches this app server to be
        # size-checked. Always set one: explicit max_bytes wins, then the
        # bucket's configured max_upload_bytes, then a conservative
        # fallback so this is never silently unbounded even if neither is set.
        effective_cap = max_bytes or bucket.max_upload_bytes or (5 * 1024 * 1024 * 1024)
        if effective_cap < 1:
            raise StorageValidationError("max_bytes must be positive")
        conditions.append(["content-length-range", 0, int(effective_cap)])

        post = client.generate_presigned_post(
            Bucket=bucket.bucket_name,
            Key=key,
            Fields=fields or None,
            Conditions=conditions or None,
            ExpiresIn=expires,
        )
        return {"bucket": bucket.bucket_name, "key": key, "max_bytes": effective_cap, **post}

    def build_django_storages(self) -> dict[str, dict[str, object]]:
        return dict(self.storages)

    def configuration_fingerprint(self) -> str:
        payload = json.dumps(self.as_dict(), sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class StorageSettingsValidator:
    def validate(self, settings: StorageSettings) -> None:
        validate_storage_settings(settings)

    def validate_bucket(self, bucket: StorageBucketSpec, settings: StorageSettings) -> None:
        bucket.validate(allow_http=settings.allow_http)

    def validate_health(self, settings: StorageSettings) -> StorageHealthReport:
        return settings.health_check()


@dataclass(frozen=True, slots=True)
class StorageConfigSerializer:
    env: Mapping[str, str]

    def __repr__(self) -> str:
        # The default dataclass repr would print self.env in full - and
        # env is very often literally os.environ, meaning every secret in
        # the process's environment (database passwords, API keys, the
        # storage credentials this very class exists to parse) would be
        # one accidental print()/log call away from a leak. Show only a
        # count.
        try:
            count = len(self.env)
        except Exception:
            count = "?"
        return f"{type(self).__name__}(env=<{count} vars, redacted>)"

    def get(self, name: str, default: str | None = None) -> str | None:
        return _env_get(self.env, name, default)

    def get_bool(self, name: str, default: bool = False) -> bool:
        return _env_bool(self.env, name, default)

    def get_int(
        self,
        name: str,
        default: int,
        *,
        minimum: int | None = None,
        maximum: int | None = None,
    ) -> int:
        return _env_int(self.env, name, default, minimum=minimum, maximum=maximum)

    def get_csv(self, name: str) -> tuple[str, ...]:
        return _load_json_or_csv(self.get(name))

    def provider(self) -> StorageProvider:
        return _normalize_provider(self.get("STORAGE_PROVIDER"), default="aws")

    def storage_mode(self) -> StorageMode:
        mode = self.get("STORAGE_MODE", "auto") or "auto"
        if mode == "auto":
            return "auto"
        if mode == "filesystem":
            return "filesystem"
        if mode == "s3":
            return "s3"
        raise StorageValidationError("STORAGE_MODE must be auto, filesystem, or s3")

    def environment(self) -> str:
        raw = str(self.get("ENVIRONMENT", "development") or "development").strip().casefold()
        aliases = {
            "dev": "development", "development": "development", "local": "development",
            "test": "testing", "testing": "testing", "ci": "testing",
            "stage": "staging", "staging": "staging", "preprod": "staging", "pre-production": "staging",
            "prod": "production", "production": "production",
        }
        try:
            return aliases[raw]
        except KeyError as exc:
            raise StorageValidationError(
                "ENVIRONMENT must be development, testing, staging, or production"
            ) from exc

    def urls(self) -> tuple[str, str]:
        raw_media_url = self.get("MEDIA_URL", "/media/") or "/media/"
        raw_static_url = self.get("STATIC_URL", "/static/") or "/static/"

        media_url = (
            _normalize_https_url(raw_media_url, field_name="MEDIA_URL", allow_http=True)
            if raw_media_url.startswith(("http://", "https://"))
            else _safe_url_path(raw_media_url, "/media/")
        )
        static_url = (
            _normalize_https_url(raw_static_url, field_name="STATIC_URL", allow_http=True)
            if raw_static_url.startswith(("http://", "https://"))
            else _safe_url_path(raw_static_url, "/static/")
        )
        return str(media_url), str(static_url)

    def bucket(
        self,
        *,
        alias: StorageAlias,
        default_bucket_name_keys: tuple[str, ...],
        default_region: str,
        default_location: str,
        default_acl: str | None,
        default_cache_control: str,
        default_sse: str,
        overwrite: bool,
        querystring_auth: bool,
        private_urls: bool,
        allow_http: bool,
    ) -> StorageBucketSpec:
        return _build_bucket_from_env(
            self.env,
            alias=alias,
            default_bucket_name_keys=default_bucket_name_keys,
            default_region=default_region,
            default_location=default_location,
            default_acl=default_acl,
            default_cache_control=default_cache_control,
            default_sse=default_sse,
            overwrite=overwrite,
            querystring_auth=querystring_auth,
            private_urls=private_urls,
            allow_http=allow_http,
        )

    def lifecycle_rules(self) -> tuple[StorageLifecycleRule, ...]:
        return _parse_lifecycle_rules(self.env)

    def failover(self, allow_http: bool) -> StorageFailoverConfig:
        failover = StorageFailoverConfig(
            enabled=self.get_bool("STORAGE_FAILOVER_ENABLED", default=False),
            secondary_region=self.get("STORAGE_FAILOVER_SECONDARY_REGION"),
            secondary_bucket=self.get("STORAGE_FAILOVER_SECONDARY_BUCKET"),
            secondary_endpoint_url=self.get("STORAGE_FAILOVER_SECONDARY_ENDPOINT_URL"),
            fail_closed=self.get_bool("STORAGE_FAILOVER_FAIL_CLOSED", default=True),
            retry_attempts=self.get_int("STORAGE_FAILOVER_RETRY_ATTEMPTS", 1, minimum=0, maximum=10),
            prefer_secondary_on_health_failure=self.get_bool("STORAGE_FAILOVER_PREFER_SECONDARY", default=True),
        )
        failover.validate(allow_http=allow_http)
        return failover

    def metrics(self) -> StorageMetricsConfig:
        return StorageMetricsConfig(
            enabled=self.get_bool("STORAGE_METRICS_ENABLED", default=True),
            prefix=self.get("STORAGE_METRICS_PREFIX", "mt_media_sdk.storage") or "mt_media_sdk.storage",
            emit_latency_histogram=self.get_bool("STORAGE_METRICS_LATENCY_HISTOGRAM", default=True),
            emit_health_gauge=self.get_bool("STORAGE_METRICS_HEALTH_GAUGE", default=True),
            log_level=logging.INFO,
            sink_path=self.get("STORAGE_METRICS_SINK"),
        )

    def roots(self) -> tuple[Path, Path, Path, Path]:
        storage_root = Path(self.get("STORAGE_ROOT", str(Path.cwd() / "storage")) or "storage").expanduser()
        media_root = Path(self.get("MEDIA_ROOT", str(storage_root / "media")) or str(storage_root / "media")).expanduser()
        static_root = Path(self.get("STATIC_ROOT", str(storage_root / "staticfiles")) or str(storage_root / "staticfiles")).expanduser()
        backup_root = Path(self.get("BACKUP_ROOT", str(storage_root / "backups")) or str(storage_root / "backups")).expanduser()
        return storage_root, media_root, static_root, backup_root


def _build_storage_backend(bucket: StorageBucketSpec, *, filesystem_location: Path | None = None) -> dict[str, object]:
    if bucket.is_remote():
        return {
            "BACKEND": "storages.backends.s3.S3Storage",
            "OPTIONS": bucket.build_backend_options(),
        }

    if filesystem_location is None:
        filesystem_location = Path.cwd() / "storage" / str(bucket.alias)
    filesystem_location.mkdir(parents=True, exist_ok=True)
    return {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {
            "location": str(filesystem_location),
            "base_url": f"/{bucket.alias}/",
        },
    }


def _build_static_backend(
    *,
    storage_mode: StorageMode,
    static_bucket: StorageBucketSpec,
    static_root: Path,
    static_url: str,
) -> dict[str, object]:
    if storage_mode == "filesystem" or not static_bucket.bucket_name:
        static_root.mkdir(parents=True, exist_ok=True)
        return {
            "BACKEND": "django.contrib.staticfiles.storage.ManifestStaticFilesStorage",
            "OPTIONS": {
                "location": str(static_root),
                "base_url": static_url,
            },
        }
    return _build_storage_backend(static_bucket, filesystem_location=static_root)


def _provider_defaults_for_bucket(env: Mapping[str, str], alias: StorageAlias) -> StorageProvider:
    alias_prefix = str(alias).upper()
    return _normalize_provider(
        _env_get(env, f"{alias_prefix}_PROVIDER") or _env_get(env, "STORAGE_PROVIDER"),
        default="aws",
    )


def _build_bucket_from_env(
    env: Mapping[str, str],
    *,
    alias: StorageAlias,
    default_bucket_name_keys: tuple[str, ...],
    default_region: str,
    default_location: str,
    default_acl: str | None,
    default_cache_control: str,
    default_sse: str,
    overwrite: bool,
    querystring_auth: bool,
    private_urls: bool,
    allow_http: bool,
) -> StorageBucketSpec:
    alias_prefix = str(alias).upper()
    bucket_name: str | None = None
    for key in default_bucket_name_keys:
        candidate = _env_get(env, key)
        if candidate:
            bucket_name = _normalize_bucket_name(candidate, field_name=key)
            break

    provider = _provider_defaults_for_bucket(env, alias)

    region_key = f"{alias_prefix}_REGION_NAME"
    endpoint_keys = (
        f"{alias_prefix}_ENDPOINT_URL",
        f"{alias_prefix}_S3_ENDPOINT_URL",
        "OBJECT_STORAGE_ENDPOINT_URL",
    )

    region_name = _env_get(env, region_key) or default_region
    endpoint_url: str | None = None
    for key in endpoint_keys:
        candidate = _env_get(env, key)
        if candidate:
            endpoint_url = candidate
            break

    if provider == "backblaze" and endpoint_url is None:
        endpoint_url = _guess_backblaze_endpoint(region_name)

    access_key_id = _env_get(env, f"{alias_prefix}_ACCESS_KEY_ID") or _env_get(env, "OBJECT_STORAGE_ACCESS_KEY_ID")
    secret_access_key = _env_get(env, f"{alias_prefix}_SECRET_ACCESS_KEY") or _env_get(env, "OBJECT_STORAGE_SECRET_ACCESS_KEY")
    session_token = _env_get(env, f"{alias_prefix}_SESSION_TOKEN") or _env_get(env, "OBJECT_STORAGE_SESSION_TOKEN")
    custom_domain = _env_get(env, f"{alias_prefix}_CUSTOM_DOMAIN")
    default_acl_value = _env_get(env, f"{alias_prefix}_DEFAULT_ACL", default_acl)

    connect_timeout = _env_int(env, f"{alias_prefix}_CONNECT_TIMEOUT_SECONDS", 3, minimum=1, maximum=60)
    read_timeout = _env_int(env, f"{alias_prefix}_READ_TIMEOUT_SECONDS", 5, minimum=1, maximum=60)
    max_retries = _env_int(env, f"{alias_prefix}_MAX_RETRIES", 3, minimum=0, maximum=10)
    retry_mode = _env_get(env, f"{alias_prefix}_RETRY_MODE", "standard") or "standard"
    use_ssl = _env_bool(env, f"{alias_prefix}_USE_SSL", default=True)
    signature_version = _env_get(env, f"{alias_prefix}_SIGNATURE_VERSION", "s3v4") or "s3v4"
    addressing_style = _env_get(env, f"{alias_prefix}_ADDRESSING_STYLE", "virtual") or "virtual"
    if provider == "backblaze":
        signature_version = "s3v4"

    bucket = StorageBucketSpec(
        alias=alias,
        bucket_name=bucket_name,
        provider=provider,
        region_name=_normalize_region(region_name, default=default_region),
        endpoint_url=(
            _normalize_https_url(
                endpoint_url,
                field_name=f"{alias_prefix}_ENDPOINT_URL",
                allow_http=allow_http,
            )
            if endpoint_url
            else None
        ),
        custom_domain=custom_domain,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token,
        file_overwrite=overwrite,
        querystring_auth=querystring_auth,
        default_acl=default_acl_value,
        object_parameters={
            "CacheControl": _env_get(env, f"{alias_prefix}_CACHE_CONTROL", default_cache_control) or default_cache_control,
            "ServerSideEncryption": _env_get(env, f"{alias_prefix}_SSE", default_sse) or default_sse,
        },
        location=_safe_relative_path(_env_get(env, f"{alias_prefix}_LOCAL_DIR"), default_location),
        private_urls=private_urls,
        validate_at_startup=True,
        connect_timeout_seconds=connect_timeout,
        read_timeout_seconds=read_timeout,
        max_retries=max_retries,
        retry_mode=retry_mode,
        use_ssl=use_ssl,
        signature_version=signature_version,
        addressing_style=addressing_style,
        cache_control=_env_get(env, f"{alias_prefix}_CACHE_CONTROL", default_cache_control) or default_cache_control,
        bucket_policy=_env_get(env, f"{alias_prefix}_BUCKET_POLICY"),
        enforce_content_length=_env_bool(env, f"{alias_prefix}_ENFORCE_CONTENT_LENGTH", default=False),
        max_upload_bytes=_env_int(env, f"{alias_prefix}_MAX_UPLOAD_BYTES", 0, minimum=0, maximum=2_147_483_647) or None,
    )
    bucket.validate(allow_http=allow_http)
    return bucket


def _parse_lifecycle_rules(env: Mapping[str, str]) -> tuple[StorageLifecycleRule, ...]:
    raw = _env_get(env, "STORAGE_LIFECYCLE_RULES_JSON")
    if not raw:
        return ()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StorageValidationError("STORAGE_LIFECYCLE_RULES_JSON must be valid JSON") from exc
    if not isinstance(payload, list):
        raise StorageValidationError("STORAGE_LIFECYCLE_RULES_JSON must be a JSON list")

    rules: list[StorageLifecycleRule] = []
    for item in payload:
        if not isinstance(item, Mapping):
            raise StorageValidationError("Each lifecycle rule must be an object")
        expiration = item.get("expiration_days")
        transition = item.get("transition_days")
        rule = StorageLifecycleRule(
            prefix=str(item.get("prefix") or "").strip(),
            expiration_days=int(expiration) if expiration is not None else None,
            transition_days=int(transition) if transition is not None else None,
            storage_class=str(item["storage_class"]).strip() if item.get("storage_class") is not None else None,
            enabled=bool(item.get("enabled", True)),
        )
        rule.validate()
        rules.append(rule)
    return tuple(rules)


def _build_storage_configuration_digest(
    *,
    environment: str,
    storage_mode: StorageMode,
    buckets: tuple[StorageBucketSpec, ...],
    lifecycle_rules: tuple[StorageLifecycleRule, ...],
    failover: StorageFailoverConfig,
    metrics: StorageMetricsConfig,
    private_media_signed_urls: bool,
    signed_url_expires_seconds: int,
    media_url: str,
    static_url: str,
    private_media_url_prefix: str,
) -> str:
    payload = {
        "environment": environment,
        "storage_mode": storage_mode,
        "buckets": [bucket.as_dict() for bucket in buckets],
        "lifecycle_rules": [rule.as_dict() for rule in lifecycle_rules],
        "failover": {
            "enabled": failover.enabled,
            "secondary_region": failover.secondary_region,
            "secondary_bucket": failover.secondary_bucket,
            "secondary_endpoint_url": failover.secondary_endpoint_url,
            "fail_closed": failover.fail_closed,
            "retry_attempts": failover.retry_attempts,
            "prefer_secondary_on_health_failure": failover.prefer_secondary_on_health_failure,
        },
        "metrics": metrics.as_dict(),
        "private_media_signed_urls": private_media_signed_urls,
        "signed_url_expires_seconds": signed_url_expires_seconds,
        "media_url": media_url,
        "static_url": static_url,
        "private_media_url_prefix": private_media_url_prefix,
    }
    data = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def get_s3_client_for_bucket(bucket: "StorageBucketSpec"):
    """
    Public entrypoint for turning a StorageBucketSpec into a ready-to-use,
    cached boto3 S3 client - endpoint_url, credentials, timeouts, retries,
    SSL, signature version, and addressing style all applied.

    This is the sanctioned integration point for anything that needs a raw
    S3 client for a configured bucket/alias: ``S3StorageBackend`` uses it
    internally, and it's exactly what a custom S3-compatible backend
    (Cloudflare R2, DigitalOcean Spaces, on-prem MinIO/Ceph, ...) should
    call too, rather than hand-rolling its own boto3.client(...) call and
    re-deriving credentials/endpoint/timeout config from scratch.
    """
    return _build_s3_client_cached(bucket)


def build_storage_settings(env: Mapping[str, str] | None = None) -> StorageSettings:
    mapping = env or os.environ
    serializer = StorageConfigSerializer(mapping)

    environment = serializer.environment()
    is_production = environment == "production"
    is_staging = environment == "staging"
    is_development = environment in {"development", "testing"}

    allow_http = serializer.get_bool("STORAGE_ALLOW_HTTP", default=is_development)
    storage_mode = serializer.storage_mode()

    storage_root, media_root, static_root, backup_root = serializer.roots()
    media_url, static_url = serializer.urls()

    private_media_signed_urls = serializer.get_bool("PRIVATE_MEDIA_SIGNED_URLS", default=not is_development)
    signed_url_expires_seconds = serializer.get_int("PRIVATE_MEDIA_SIGNED_URL_EXPIRES_SECONDS", 900, minimum=60, maximum=86400)
    validate_remote_buckets = serializer.get_bool("STORAGE_VALIDATE_REMOTE_BUCKETS", default=is_production or is_staging)
    health_check_enabled = serializer.get_bool("STORAGE_HEALTH_CHECK_ENABLED", default=False)
    strict_startup_validation = serializer.get_bool("STORAGE_STRICT_STARTUP_VALIDATION", default=is_production or is_staging)
    storage_health_timeout_seconds = serializer.get_int("STORAGE_HEALTH_TIMEOUT_SECONDS", 8, minimum=1, maximum=60)

    default_region = serializer.get("OBJECT_STORAGE_REGION_NAME", "us-east-1") or "us-east-1"
    storage_provider = serializer.provider()

    media_bucket = serializer.bucket(
        alias="media",
        default_bucket_name_keys=("MEDIA_BUCKET_NAME", "DEFAULT_BUCKET_NAME"),
        default_region=default_region,
        default_location="media",
        default_acl=serializer.get("MEDIA_DEFAULT_ACL"),
        default_cache_control="private, max-age=3600",
        default_sse="AES256",
        overwrite=False,
        querystring_auth=True,
        private_urls=True,
        allow_http=allow_http,
    )
    static_bucket = serializer.bucket(
        alias="staticfiles",
        default_bucket_name_keys=("STATIC_BUCKET_NAME",),
        default_region=default_region,
        default_location="staticfiles",
        default_acl=serializer.get("STATIC_DEFAULT_ACL"),
        default_cache_control="public, max-age=31536000, immutable",
        default_sse="AES256",
        overwrite=True,
        querystring_auth=False,
        private_urls=False,
        allow_http=allow_http,
    )
    backup_bucket = serializer.bucket(
        alias="backups",
        default_bucket_name_keys=("BACKUP_BUCKET_NAME",),
        default_region=default_region,
        default_location="backups",
        default_acl=serializer.get("BACKUP_DEFAULT_ACL"),
        default_cache_control="private, max-age=0, no-store",
        default_sse="AES256",
        overwrite=False,
        querystring_auth=True,
        private_urls=True,
        allow_http=allow_http,
    )

    if storage_provider == "backblaze":
        if media_bucket.bucket_name and media_bucket.endpoint_url is None:
            media_bucket = replace(
                media_bucket,
                endpoint_url=_guess_backblaze_endpoint(media_bucket.region_name),
                signature_version="s3v4",
            )
        if static_bucket.bucket_name and static_bucket.endpoint_url is None:
            static_bucket = replace(
                static_bucket,
                endpoint_url=_guess_backblaze_endpoint(static_bucket.region_name),
                signature_version="s3v4",
            )
        if backup_bucket.bucket_name and backup_bucket.endpoint_url is None:
            backup_bucket = replace(
                backup_bucket,
                endpoint_url=_guess_backblaze_endpoint(backup_bucket.region_name),
                signature_version="s3v4",
            )

    buckets = (media_bucket, static_bucket, backup_bucket)
    lifecycle_rules = serializer.lifecycle_rules()
    failover = serializer.failover(allow_http=allow_http)
    metrics = serializer.metrics()

    virus_scan_hook_path = serializer.get("STORAGE_VIRUS_SCAN_HOOK")
    bucket_validator_path = serializer.get("STORAGE_BUCKET_VALIDATOR")
    private_url_signer_path = serializer.get("STORAGE_PRIVATE_URL_SIGNER")
    health_probe_path = serializer.get("STORAGE_HEALTH_PROBE")

    private_media_url_prefix = _safe_url_path(serializer.get("PRIVATE_MEDIA_URL_PREFIX", "/media/private"), "/media/private")
    configuration_digest = _build_storage_configuration_digest(
        environment=environment,
        storage_mode=storage_mode,
        buckets=buckets,
        lifecycle_rules=lifecycle_rules,
        failover=failover,
        metrics=metrics,
        private_media_signed_urls=private_media_signed_urls,
        signed_url_expires_seconds=signed_url_expires_seconds,
        media_url=media_url,
        static_url=static_url,
        private_media_url_prefix=private_media_url_prefix,
    )

    if storage_mode == "filesystem":
        storages = {
            "default": {
                "BACKEND": "django.core.files.storage.FileSystemStorage",
                "OPTIONS": {"location": str(media_root), "base_url": str(media_url)},
            },
            "media": {
                "BACKEND": "django.core.files.storage.FileSystemStorage",
                "OPTIONS": {"location": str(media_root), "base_url": str(media_url)},
            },
            "staticfiles": {
                "BACKEND": "django.contrib.staticfiles.storage.ManifestStaticFilesStorage",
                "OPTIONS": {"location": str(static_root), "base_url": str(static_url)},
            },
            "backups": {
                "BACKEND": "django.core.files.storage.FileSystemStorage",
                "OPTIONS": {"location": str(backup_root), "base_url": "/backups/"},
            },
        }
    elif storage_mode == "s3" or any(bucket.bucket_name for bucket in buckets):
        media_backend = _build_storage_backend(media_bucket, filesystem_location=media_root)
        static_backend = _build_static_backend(
            storage_mode=storage_mode,
            static_bucket=static_bucket,
            static_root=static_root,
            static_url=str(static_url),
        )
        backups_backend = _build_storage_backend(backup_bucket, filesystem_location=backup_root)
        storages = {
            "default": media_backend,
            "media": media_backend,
            "staticfiles": static_backend,
            "backups": backups_backend,
        }
    else:
        storages = {
            "default": {
                "BACKEND": "django.core.files.storage.FileSystemStorage",
                "OPTIONS": {"location": str(media_root), "base_url": str(media_url)},
            },
            "media": {
                "BACKEND": "django.core.files.storage.FileSystemStorage",
                "OPTIONS": {"location": str(media_root), "base_url": str(media_url)},
            },
            "staticfiles": {
                "BACKEND": "django.contrib.staticfiles.storage.ManifestStaticFilesStorage",
                "OPTIONS": {"location": str(static_root), "base_url": str(static_url)},
            },
            "backups": {
                "BACKEND": "django.core.files.storage.FileSystemStorage",
                "OPTIONS": {"location": str(backup_root), "base_url": "/backups/"},
            },
        }

    settings = StorageSettings(
        environment=environment,
        is_production=is_production,
        is_staging=is_staging,
        is_development=is_development,
        allow_http=allow_http,
        media_url=str(media_url),
        static_url=str(static_url),
        backup_root=backup_root,
        storage_mode=storage_mode,
        buckets=buckets,
        lifecycle_rules=lifecycle_rules,
        failover=failover,
        metrics=metrics,
        private_media_signed_urls=private_media_signed_urls,
        signed_url_expires_seconds=signed_url_expires_seconds,
        virus_scan_hook_path=virus_scan_hook_path,
        validate_remote_buckets=validate_remote_buckets,
        health_check_enabled=health_check_enabled,
        storages=storages,
        storage_root=storage_root,
        storage_health_timeout_seconds=storage_health_timeout_seconds,
        strict_startup_validation=strict_startup_validation,
        bucket_validator_path=bucket_validator_path,
        metrics_sink_path=metrics.sink_path,
        private_url_signer_path=private_url_signer_path,
        health_probe_path=health_probe_path,
        private_media_url_prefix=private_media_url_prefix,
        configuration_digest=configuration_digest,
    )

    validate_storage_settings(settings)
    return settings


def _validate_remote_bucket(bucket: StorageBucketSpec, *, allow_http: bool) -> tuple[bool, str]:
    try:
        _normalize_bucket_name(bucket.bucket_name or "", field_name=f"{bucket.alias}_bucket_name")
        if bucket.endpoint_url:
            _normalize_https_url(bucket.endpoint_url, field_name=f"{bucket.alias}_endpoint_url", allow_http=allow_http)
        if bucket.provider == "backblaze" and bucket.endpoint_url is None and bucket.region_name is None:
            return False, "Backblaze buckets need a region or endpoint URL"
    except StorageValidationError as exc:
        return False, _safe_error_detail(exc)

    try:
        client = _build_s3_client_cached(bucket)
    except Exception as exc:
        return False, _safe_error_detail(exc)

    try:
        client.head_bucket(Bucket=bucket.bucket_name)
        return True, "ok"
    except Exception as exc:
        return False, _safe_error_detail(exc)


def validate_storage_settings(settings: StorageSettings) -> None:
    if settings.is_production or settings.is_staging:
        if not settings.private_media_signed_urls:
            raise StorageValidationError("PRIVATE_MEDIA_SIGNED_URLS must be enabled in staging and production")
        if settings.storage_mode == "filesystem":
            raise StorageValidationError("filesystem storage mode is not allowed in staging and production")
        media_bucket = settings.get_bucket("media")
        backups_bucket = settings.get_bucket("backups")
        if media_bucket is None or not media_bucket.bucket_name:
            raise StorageValidationError("MEDIA_BUCKET_NAME is required in staging and production")
        if backups_bucket is None or not backups_bucket.bucket_name:
            raise StorageValidationError("BACKUP_BUCKET_NAME is required in staging and production")

    for bucket in settings.buckets:
        bucket.validate(allow_http=settings.allow_http)

    bucket_validator = settings._load_bucket_validator()
    if bucket_validator is not None:
        for bucket in settings.buckets:
            try:
                bucket_validator(bucket, settings)
            except Exception as exc:
                raise StorageValidationError(f"Bucket validator failed for {bucket.alias}: {type(exc).__name__}") from exc

    for rule in settings.lifecycle_rules:
        rule.validate()

    if settings.failover.enabled:
        if not (settings.is_production or settings.is_staging):
            raise StorageValidationError("Failover is only supported in staging or production")
        if not settings.failover.secondary_bucket:
            raise StorageValidationError("STORAGE_FAILOVER_SECONDARY_BUCKET is required when failover is enabled")
        if not settings.failover.secondary_region:
            raise StorageValidationError("STORAGE_FAILOVER_SECONDARY_REGION is required when failover is enabled")

    if settings.health_check_enabled and settings.validate_remote_buckets:
        start = monotonic()
        report = settings.health_check()
        duration = monotonic() - start
        settings.record_metric(
            "health_check",
            alias="media",
            success=report.ok,
            duration_seconds=duration,
            detail="; ".join(report.failures) if report.failures else "ok",
        )
        if not report.ok:
            if settings.strict_startup_validation:
                raise StorageHealthError("Storage health validation failed: " + "; ".join(report.failures))
            logger.warning("Storage health validation failed but startup is non-strict: %s", "; ".join(report.failures))



def build_storage_health_report(settings: StorageSettings) -> StorageHealthReport:
    report = settings.health_check()
    return StorageHealthReport(
        ok=report.ok,
        checked_aliases=report.checked_aliases,
        failures=report.failures,
        checked_at=_settings_current_utc(),
    )


def build_private_media_url(
    object_key: str,
    *,
    env: Mapping[str, str] | None = None,
    expires_seconds: int | None = None,
) -> str:
    settings = build_storage_settings(env)
    return settings.build_private_media_url(object_key, expires_seconds=expires_seconds)


def build_private_upload_url(
    object_key: str,
    *,
    env: Mapping[str, str] | None = None,
    expires_seconds: int | None = None,
) -> str:
    settings = build_storage_settings(env)
    return settings.build_private_upload_url(object_key, expires_seconds=expires_seconds)


def execute_virus_scan_hook(
    file_path: Path,
    *,
    env: Mapping[str, str] | None = None,
    object_key: str | None = None,
    bucket_name: str | None = None,
) -> None:
    settings = build_storage_settings(env)
    settings.run_virus_scan_hook(file_path, object_key=object_key, bucket_name=bucket_name)


def build_storage_django_settings(env: Mapping[str, str] | None = None) -> dict[str, object]:
    settings = build_storage_settings(env)
    if settings.health_check_enabled:
        health_report = settings.health_check().as_dict()
    else:
        health_report = StorageHealthReport(
            ok=True, checked_aliases=(), failures=(), checked_at=_settings_current_utc()
        ).as_dict()
        health_report["skipped"] = True
    return {
        "STORAGES": settings.build_django_storages(),
        "MEDIA_URL": settings.media_url,
        "STATIC_URL": settings.static_url,
        "MEDIA_ROOT": str(settings.storage_root / "media"),
        "STATIC_ROOT": str(settings.storage_root / "staticfiles"),
        "BACKUP_ROOT": str(settings.backup_root),
        "STORAGE_HEALTH_REPORT": health_report,
        "STORAGE_CONFIG": settings.as_dict(),
    }

@lru_cache(maxsize=1)
def get_storage_settings() -> StorageSettings:
    return build_storage_settings()


@lru_cache(maxsize=1)
def get_storage_django_settings() -> dict[str, object]:
    return build_storage_django_settings()

__all__ = [
    "BucketValidationError",
    "MetricsSink",
    "StorageAlias",
    "StorageBucketSpec",
    "StorageConfigSerializer",
    "StorageError",
    "StorageFailoverConfig",
    "StorageHealthError",
    "StorageHealthReport",
    "StorageLifecycleRule",
    "StorageMetricsConfig",
    "StorageMode",
    "StorageProvider",
    "StorageSettings",
    "StorageSettingsValidator",
    "StorageValidationError",
    "VirusScanHook",
    "BucketValidator",
    "StorageHealthProbe",
    "build_storage_settings",
    "validate_storage_settings",
    "build_storage_health_report",
    "build_private_media_url",
    "build_private_upload_url",
    "execute_virus_scan_hook",
    "build_storage_django_settings",
    "get_s3_client_for_bucket",
    "clear_s3_client_cache",
]
