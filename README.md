# mt-media-sdk

Reusable Django SDK for secure media uploads, chunked transfer, storage,
processing, progress tracking, and service integration.

## Install

From the public Git repository:

```bash
python -m pip install "mt-media-sdk @ git+https://github.com/must-tip/mt_media_sdk.git"
```

Or from a package index:

```bash
pip install mt-media-sdk
```

Install only the integrations a service uses:

```bash
pip install "mt-media-sdk[s3,redis,security]"
```

## Django setup

```python
INSTALLED_APPS = [
    # ...
    "mt_media_sdk.apps.MTMediaSDKConfig",
]
```

Mount the API and websocket routes under service-owned prefixes:

```python
path("api/media/", include("mt_media_sdk.urls"))
```

```python
from mt_media_sdk.routing import websocket_urlpatterns
```

Run the packaged migrations before serving traffic:

```bash
python manage.py migrate mt_media_sdk
```

Storage validation and ClamAV startup probes are explicit because they can
perform network I/O:

```python
MT_MEDIA_VALIDATE_STORAGE_ON_STARTUP = True
MT_MEDIA_CLAMAV_STARTUP_PROBE = True
```

Keep both disabled for services that do not configure those integrations.
Production upload policy should use explicit size/type allow-lists, private
storage, server-side encryption, malware scanning, and authenticated API
permissions.

Private media URLs fail closed: custom storage backends must set
`supports_private_download_urls = True` only when their `url()` implementation
returns a short-lived, access-controlled URL. The bundled S3 backend does this;
the local filesystem backend does not expose private objects directly.

The authenticated encryption format is versioned and legacy decryption is
disabled by default. During a controlled migration only, set
`MEDIA_ENCRYPTION_ALLOW_LEGACY_FORMAT = True`, re-encrypt existing objects, and
then disable it again.
