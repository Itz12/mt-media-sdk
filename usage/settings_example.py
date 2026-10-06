"""
Example settings block for the media app. Copy the relevant bits into your
project's settings module - this file is never imported by the app itself.

IMPORTANT - one thing to confirm before copying any of this: every dotted
path below (INSTALLED_APPS, STORAGE_*_HOOK, MEDIA_LIMIT_MODEL_PATH, etc.)
assumes this app is importable as the top-level package `media`. If your
project installs it under a different name (e.g. because the repo/directory
is named something else, like `mt_media_sdk`), every "mt_media_sdk.xxx" path in
this file - and in the app's own internal defaults - needs the same prefix
swap. Cheapest way to confirm:
`python -c "import mt_media_sdk; print(mt_media_sdk.__file__)"`
in your project's environment.
"""
from __future__ import annotations


# =============================================================================
# Django app registration
# =============================================================================
INSTALLED_APPS = [
    # ...
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    "storages",           # required if STORAGE_MODE=s3 (django-storages)
    "rest_framework",
    "channels",

    "mt_media_sdk",
]

FILE_UPLOAD_HANDLERS = [
    "mt_media_sdk.uploads.handler.ProgressUploadHandler",
    "django.core.files.uploadhandler.MemoryFileUploadHandler",
    "django.core.files.uploadhandler.TemporaryFileUploadHandler",
]


# =============================================================================
# Storage backend (media/storage/) - buckets, credentials, health checks
# =============================================================================
# Everything under STORAGES/MEDIA_URL/MEDIA_ROOT/etc. below is derived from
# environment variables by mt_media_sdk.storage.storage_settings, and cached/
# health-checked at startup by mt_media_sdk.storage.storage_bootstrap. Don't set
# STORAGES by hand alongside this - build_storage_django_settings() is the
# single source of truth for it.
from mt_media_sdk.storage.storage_bootstrap import get_django_storage_settings  # noqa: E402

_storage_config = get_django_storage_settings()

STORAGES = _storage_config["STORAGES"]
MEDIA_URL = _storage_config["MEDIA_URL"]
STATIC_URL = _storage_config["STATIC_URL"]
MEDIA_ROOT = _storage_config["MEDIA_ROOT"]
STATIC_ROOT = _storage_config["STATIC_ROOT"]
BACKUP_ROOT = _storage_config["BACKUP_ROOT"]

STORAGE_HEALTH_REPORT = _storage_config["STORAGE_HEALTH_REPORT"]  # informational; inspect at startup/in a health endpoint
STORAGE_CONFIG = _storage_config["STORAGE_CONFIG"]                  # informational; secrets are already redacted

# Which StorageBackend class handles remote vs local-only bucket aliases,
# when resolving via mt_media_sdk.storage.registry.get_storage_backend_for_bucket().
# Override either to point at a custom S3-compatible backend subclass
# (see media/storage/base.py's module docstring for the two ways to plug
# one in) without touching any other setting.
UPLOAD_STORAGE_BACKEND_FOR_REMOTE = "s3"
UPLOAD_STORAGE_BACKEND_FOR_LOCAL = "local"
UPLOAD_STORAGE_BACKENDS = {                 # register additional/custom backends here
    # "gcs": "myproject.storage.GCSBackend",
    # "r2": "myproject.storage.CloudflareR2Backend",  # e.g. S3StorageBackend subclass
}

# Legacy/simple path: only read when a backend is bare-constructed (no
# bucket alias involved) rather than resolved via get_storage_backend_for_bucket.
# Prefer the environment variables in the "Storage system env vars" section
# below for anything going through the bucket-alias system.
UPLOAD_STORAGE_BACKEND = "local"          # or "s3"
UPLOAD_S3_BUCKET = "my-media-bucket"
UPLOAD_S3_REGION = "us-east-1"
UPLOAD_S3_ENDPOINT_URL = None              # e.g. "http://minio.internal:9000" for a self-hosted S3-compatible store
UPLOAD_S3_USE_SSL = True

# Extension points the storage system resolves via dotted path at startup.
# All five are optional (each STORAGE_* hook below only fires if you set it).
#
#   STORAGE_VIRUS_SCAN_HOOK   -> media/security/validators.py:scan_uploaded_file    (implemented)
#   STORAGE_BUCKET_VALIDATOR  -> media/security/validators.py:validate_bucket        (implemented)
#   STORAGE_HEALTH_PROBE      -> media/storage/storage_bootstrap.py:probe_storage_bucket  (implemented -
#                                  actually exercises Put/Get/DeleteObject, not just HeadBucket, so
#                                  read-only credentials fail loudly at startup instead of at the first
#                                  real upload)
#   STORAGE_METRICS_SINK      -> your own metrics integration (see contract below - not provided here,
#                                  since it depends on what you're actually sending metrics to)
#   STORAGE_PRIVATE_URL_SIGNER -> your own CDN/edge-signing integration (see contract below - same reason)
STORAGE_VIRUS_SCAN_HOOK = "mt_media_sdk.security.validators:scan_uploaded_file"
STORAGE_BUCKET_VALIDATOR = "mt_media_sdk.security.validators:validate_bucket"
STORAGE_HEALTH_PROBE = "mt_media_sdk.storage.storage_bootstrap:probe_storage_bucket"

# STORAGE_METRICS_SINK contract - implement and point this at it once you
# have somewhere to send metrics (Datadog, Prometheus pushgateway, your own
# services/media_processing.py, ...):
#
#   def storage_metrics_sink(event: str, payload: Mapping[str, object]) -> None:
#       ...
#
# `payload` always contains: event, alias, success, duration_seconds,
# detail, environment. Raising is fine - StorageSettings.record_metric()
# catches sink failures and falls back to a log line, it won't take down
# the request/task that triggered the metric.
# STORAGE_METRICS_SINK = "mt_media_sdk.services.media_processing:storage_metrics_sink"

# STORAGE_PRIVATE_URL_SIGNER contract - implement if you're fronting
# private media with a CDN/edge that needs its own signing scheme (e.g.
# CloudFront signed URLs) instead of raw S3 presigned URLs:
#
#   def sign_private_url(bucket: StorageBucketSpec, key: str, expires_seconds: int,
#                         method: str = "get_object") -> str:
#       ...
#
# Must return a non-empty URL string; StorageSettings.build_private_media_url/
# build_private_upload_url raise StorageError if it returns empty. Not set
# by default - without it, private URLs are generated as standard S3
# presigned URLs, which is correct and secure on its own; only add a signer
# if you specifically need CDN-level signing instead.
# STORAGE_PRIVATE_URL_SIGNER = "mt_media_sdk.services.encryption_media:sign_private_url"


# =============================================================================
# Storage system env vars (read by mt_media_sdk.storage.storage_settings at process
# start - set these in your environment/.env, not here; shown for reference)
# =============================================================================
# ENVIRONMENT=production
# STORAGE_MODE=s3
# STORAGE_PROVIDER=aws                      # or "backblaze" / "custom"
#
# MEDIA_BUCKET_NAME=your-media-bucket
# STATIC_BUCKET_NAME=your-static-bucket
# BACKUP_BUCKET_NAME=your-backup-bucket
#
# # Per-alias overrides follow the pattern {ALIAS}_{SETTING}, e.g. for a
# # self-hosted S3-compatible store behind the "media" alias:
# MEDIA_ENDPOINT_URL=https://s3.us-west-002.backblazeb2.com
# MEDIA_ADDRESSING_STYLE=path               # "virtual" (default) or "path" - MinIO/on-prem usually need "path"
# MEDIA_USE_SSL=true
#
# PRIVATE_MEDIA_SIGNED_URLS=true
# STORAGE_VALIDATE_REMOTE_BUCKETS=true
# STORAGE_HEALTH_CHECK_ENABLED=true
# STORAGE_STRICT_STARTUP_VALIDATION=true    # fail Django startup (don't just log) if health checks fail


# =============================================================================
# Chunked / resumable uploads (media/uploads/chunked.py)
# =============================================================================
UPLOAD_DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024      # 8 MiB
UPLOAD_SESSION_TTL_HOURS = 24
UPLOAD_CHUNK_STAGING_DIR = "/srv/app/tmp/upload_parts"

# -- Simple (non-chunked) handler --------------------------------------------
UPLOAD_HANDLER_TAKE_OWNERSHIP = True
TEMP_UPLOAD_DIR = "/srv/app/tmp/uploads"
UPLOAD_HANDLER_CLEANUP_DELAY_S = 300
UPLOAD_HANDLER_THROTTLE_SECONDS = 1.0
UPLOAD_HANDLER_THROTTLE_PERCENT = 2
UPLOAD_HANDLER_MAX_ACTIVE_UPLOADS = 10
UPLOAD_MIME_SNIFF_BYTES = 2048

"""Recommended production settings for resumable chunked uploads."""

UPLOAD_STORAGE_BACKEND = "s3"
UPLOAD_CHUNK_STAGING_DIR = "/var/lib/must-tip/upload-parts"
UPLOAD_MIN_CHUNK_SIZE_BYTES = 5 * 1024 * 1024
UPLOAD_MAX_CHUNK_SIZE_BYTES = 128 * 1024 * 1024
UPLOAD_MAX_MULTIPART_PARTS = 10_000
UPLOAD_REQUIRE_EXACT_PART_SIZES = True
UPLOAD_REQUIRE_SERVER_VERIFIED_NATIVE_PARTS = True
UPLOAD_VERIFY_NATIVE_CHECKSUM = True
UPLOAD_VALIDATE_COMPLETED_CONTENT = True
UPLOAD_FINAL_VALIDATOR_FAIL_CLOSED = True
UPLOAD_CHUNK_DISK_RESERVE_BYTES = 2 * 1024 * 1024 * 1024
UPLOAD_PART_URL_EXPIRY_SECONDS = 900
UPLOAD_MAX_SESSION_TTL_HOURS = 168
UPLOAD_MAX_METADATA_BYTES = 64 * 1024
UPLOAD_MAX_FILENAME_LENGTH = 255
UPLOAD_MAX_DECLARED_SIZE_BYTES = 5 * 1024 * 1024 * 1024
UPLOAD_ALLOW_HIDDEN_FILENAMES = False
UPLOAD_ALLOW_OCTET_STREAM = False

# Optional dotted paths. Leave blank to use the built-in metadata pipeline and
# mt_media_sdk.security.validators.CustomValidator for completed content.
UPLOAD_INITIATION_VALIDATOR = ""
UPLOAD_COMPLETED_VALIDATOR = ""

# =============================================================================
# Validation & sanitization (media/security/validators.py, sanitizer.py)
# =============================================================================
UPLOAD_ALLOWED_EXTENSIONS = None          # e.g. {"png", "jpg", "pdf"}; None = no allow-list
UPLOAD_BLOCKED_EXTENSIONS = {"exe", "bat", "cmd", "sh", "msi", "dll", "scr", "com", "pif", "jar", "ps1"}

ARCHIVE_MAX_FILES = 1000
ARCHIVE_MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024
ARCHIVE_MAX_SINGLE_FILE_BYTES = 500 * 1024 * 1024
ARCHIVE_MAX_COMPRESSION_RATIO = 100        # zip-bomb heuristic; ratio above this is rejected
SVG_MAX_BYTES = 5 * 1024 * 1024
TEXT_MAX_LENGTH = 200_000                    # characters, before any sanitization runs
IMAGE_MAX_PIXELS = 89_478_485                # decompression-bomb guard (Pillow's historical default cap)
MAX_FILES_PER_REQUEST = 50
MAX_TOTAL_UPLOAD_BYTES = 250 * 1024 * 1024

MEDIA_LIMIT_MODEL_PATH = "mt_media_sdk.models.MediaLimit"
MEDIA_LIMIT_NEGATIVE_CACHE_SECONDS = 30    # backoff after a failed MediaLimit lookup before retrying

# -- Virus scanning (validators.py's own upload-time path; separate from
#    the storage-layer STORAGE_VIRUS_SCAN_HOOK above, which re-scans the
#    persisted file after it's written to storage) --------------------------
CLAMAV_ENABLED = True
CLAMAV_USE_TCP = True
CLAMAV_TCP_ADDR = "127.0.0.1"
CLAMAV_TCP_PORT = 3310
CLAMAV_UNIX_SOCKET = "/var/run/clamav/clamd.ctl"
CLAMAV_CIRCUIT_BREAKER_SECONDS = 15        # skip reattempting a connection for this long after a failure

UPLOAD_VIRUS_SCANNER = None  # e.g. "mt_media_sdk.validators.ClamdVirusScanner" (defaults to NullVirusScanner)


# =============================================================================
# Progress delivery (media/progress/)
# =============================================================================
UPLOAD_PROGRESS_BACKEND = "mt_media_sdk.progress.backends.DjangoCacheProgressBackend"
# For real push notifications instead of poll-only:
# UPLOAD_PROGRESS_BACKEND = "mt_media_sdk.progress.backends.RedisProgressBackend"
# UPLOAD_PROGRESS_REDIS_URL = "redis://localhost:6379/1"
UPLOAD_PROGRESS_POLL_INTERVAL = 3.0
UPLOAD_PROGRESS_HEARTBEAT_INTERVAL = 20.0


# =============================================================================
# DRF throttling
# =============================================================================
REST_FRAMEWORK = {
    "DEFAULT_THROTTLE_RATES": {
        "media_upload": "30/min",
        "media_upload_session": "10/min",
        "media_upload_part": "600/min",
    },
}


# =============================================================================
# Celery beat (periodic maintenance)
# =============================================================================
CELERY_BEAT_SCHEDULE = {
    "media-cleanup-expired-sessions": {
        "task": "mt_media_sdk.tasks.cleanup_expired_sessions",
        "schedule": 300,  # seconds
    },
    "media-purge-soft-deleted": {
        "task": "mt_media_sdk.tasks.purge_soft_deleted_media",
        "schedule": 86400,
        "kwargs": {"days": 30},
    },
    "media-retry-pending-scans": {
        "task": "mt_media_sdk.tasks.retry_pending_scans",
        "schedule": 900,
    },
}


# =============================================================================
# Channels routing (add to your ASGI routing, e.g. media/routing.py)
# =============================================================================
# from mt_media_sdk.consumers import UploadProgressConsumer
# websocket_urlpatterns = [
#     path("ws/uploads/", UploadProgressConsumer.as_asgi()),
# ]


# =============================================================================
# URL routing
# =============================================================================
# In your project urls.py:
# path("api/media/", include("mt_media_sdk.urls")),
