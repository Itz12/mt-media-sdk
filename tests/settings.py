from __future__ import annotations

SECRET_KEY = "mt-media-sdk-test-key-not-for-production"
DEBUG = False
USE_TZ = True
TIME_ZONE = "UTC"
ALLOWED_HOSTS = ["testserver", "localhost"]
ROOT_URLCONF = "tests.urls"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
    "mt_media_sdk.apps.MTMediaSDKConfig",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "mt-media-sdk-tests",
    }
}

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    }
}

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
MEDIA_ROOT = "/tmp/mt-media-sdk-tests"
MEDIA_URL = "/media/"
UPLOAD_STORAGE_BACKEND = "local"
UPLOAD_MIN_CHUNK_SIZE_BYTES = 1
UPLOAD_MAX_CHUNK_SIZE_BYTES = 64 * 1024 * 1024
MT_MEDIA_VALIDATE_STORAGE_ON_STARTUP = False
MT_MEDIA_CLAMAV_STARTUP_PROBE = False
MT_MEDIA_AUTO_PROCESS_UPLOADS = False
