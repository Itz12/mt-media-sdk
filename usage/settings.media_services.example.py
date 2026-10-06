# Bounded media-processing policy
MEDIA_STREAM_CHUNK_BYTES = 64 * 1024
MEDIA_MAX_INPUT_BYTES = 256 * 1024 * 1024
MEDIA_MAX_OUTPUT_BYTES = 512 * 1024 * 1024
MEDIA_MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024
MEDIA_MAX_COMPRESSION_RATIO = 100.0
MEDIA_MAX_IMAGE_PIXELS = 50_000_000
MEDIA_MAX_PDF_PAGES = 1000
MEDIA_MAX_FILES_PER_REQUEST = 100
MEDIA_MAX_FILENAME_LENGTH = 255
MEDIA_MAX_SORT_ITEMS = 100_000
MEDIA_SPOOL_MEMORY_BYTES = 8 * 1024 * 1024

# External process controls
MEDIA_FFMPEG_TIMEOUT_SECONDS = 300
MEDIA_FFMPEG_MAX_STDERR_BYTES = 64 * 1024

# Authenticated media-stream format
MEDIA_ENCRYPTION_STREAM_CHUNK_BYTES = 64 * 1024
MEDIA_ENCRYPTION_MAX_FRAME_BYTES = 8 * 1024 * 1024
MEDIA_ENCRYPTION_MAX_FRAMES = 1_000_000
MEDIA_ENCRYPTION_ALLOW_LEGACY_FORMAT = True  # Disable after legacy files are migrated.
MEDIA_STORAGE_ALLOW_OVERWRITE = False

# Resolve these values through the existing Vault/secret manager. The first key
# encrypts new media; all keys may decrypt older media during rotation.
# MEDIA_ENCRYPTION_KEYS = (
#     secret_setting("MEDIA_ENCRYPTION_KEY_CURRENT", required=True),
#     secret_setting("MEDIA_ENCRYPTION_KEY_PREVIOUS", required=False),
# )

# Background attachment task safety
MEDIA_TASK_ALLOWED_TEMP_ROOTS = (
    "/tmp",
    # str(BASE_DIR / "tmp_uploads"),
)
MEDIA_TASK_ALLOW_TEXT_PATH_FIELDS = False
MEDIA_TASK_DELETE_SOURCE_ON_FAILURE = False

# Progress compatibility. Use ProgressPolicy(allow_progress_regression=False)
# for workflows that require strictly monotonic progress.
