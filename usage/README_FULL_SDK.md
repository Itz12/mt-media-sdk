# mt_media_sdk

This README maps the **complete current tree** (as of the `tree` output you
shared) and is explicit about which parts of it were built/hardened in this
session versus which parts are pre-existing subsystems whose contents I
haven't seen. That distinction matters: everything in the first category has
been written, syntax-checked, and exercised against test cases in this
conversation; everything in the second is documented here only at the
"what it appears to do, from its name and what references it" level, and
shouldn't be treated as verified.

**Before anything else**: confirm the package's real import name. Every
dotted path in this codebase (`INSTALLED_APPS`, `STORAGE_*_HOOK` settings,
`MEDIA_LIMIT_MODEL_PATH`, `UPLOAD_STORAGE_BACKENDS`, ...) assumes it's
importable as top-level `media` - which is consistent with every settings
fragment and hook path you've pasted so far, but the repo directory itself
is `mt_media_sdk`, not `media`. If your packaging config doesn't map
`mt_media_sdk` → `media` (e.g. a `src/` layout with a package rename, or a
namespace package setup), every dotted path everywhere in this app is
wrong. One-line check in your project's environment:
`python -c "import media; print(media.__file__)"`.

## Tree, annotated

```
mt_media_sdk/
├── apps.py, consumers.py, exceptions.py, models.py, routing.py,     core Django app
│   serializers.py, signals.py, tasks.py, urls.py, views.py            wiring (built this
│                                                                       session; see below)
├── validators.py                                                    [!] root-level, distinct from
│                                                                       security/validators.py - see
│                                                                       "Worth resolving" below
├── settings_example.py                                              Every setting this app reads,
│                                                                       fixed this session (see below)
│
├── security/
│   ├── sanitizer.py, validators.py                                  [x] hardened this session
│   ├── sanitizer_old.py, validators_old.py                          [!] pre-hardening backups - see
│   │                                                                    "Cleanup" below
│
├── storage/
│   ├── base.py, local.py, registry.py, s3.py,                       [x] hardened this session
│   │   storage_bootstrap.py, storage_settings.py
├── storage_old/                                                     [!] pre-hardening backup - see
│   └── (same 6 files)                                                  "Cleanup" below
│
├── progress/
│   ├── backends.py, tracker.py                                      [x] built this session
│
├── uploads/
│   ├── chunked.py, handler.py                                       [x] built this session
│
├── depriciated_upload_to_be_removed/                                [!] named for deletion - see
│   ├── constants.py, progress_tracker.py,                              "Cleanup" below
│   │   upload_consumers.py, upload_handler.py
│
├── migrations/
│   └── 0001_initial.py                                              Not regenerated since the
│                                                                        models.py rebuild - see
│                                                                        "Needs your attention" below
│
├── detector/                                                        [?] NOT reviewed this session -
│   ├── facedetector.py                                                 content-moderation subsystem;
│   ├── audio/audio_checker.py, speech_to_text_helper.py                see "Adjacent subsystems"
│   ├── image/image_nudity_detector.py
│   ├── stream/piplen.py, realtime_moderation.py
│   ├── text/text_moderator.py
│   └── video/video_moderator.py
│
├── ranking_filter/                                                  [?] NOT reviewed this session -
│   ├── dynamic_featured.py, dynamic_streams.py,                        feed-ranking/recommendation
│   │   recommender_service.py                                          subsystem; see below
│
├── services/                                                        [?] NOT reviewed this session -
│   ├── encryption_media.py, media_processing.py,                       referenced by
│   │   media_sorter.py                                                 settings_example.py's
│                                                                        STORAGE_METRICS_SINK /
│                                                                        STORAGE_PRIVATE_URL_SIGNER;
│                                                                        see below
│
├── utils/
│   └── file_utils.py                                                [?] NOT reviewed this session
│
├── tests/                                                           Mixed - see "Tests" below
├── usage/
│   ├── README.md, USEAGE_README.md,                                 [!] three overlapping READMEs -
│   │   media_upload_system_README.md                                   see "Cleanup" below
│   └── requirements.txt
```

Legend: `[x]` built/hardened and tested this session · `[!]` worth your
attention (bug, cleanup, or naming collision) · `[?]` exists, not reviewed.

## What's verified vs. what isn't

**Built, tested, and documented in depth this session** (the "media upload
system" core): `models.py` (`MediaLimit`, `MediaFile`, `UploadSession`,
`UploadPart`, `Load`), `exceptions.py`, `security/sanitizer.py` +
`security/validators.py`, `storage/` (all 6 files), `progress/`,
`uploads/`, `tasks.py`, `signals.py`, `admin.py`, `apps.py`, `serializers.py`,
`views.py`, `urls.py`, `consumers.py`, `settings_example.py`. Every claim
about these in this README reflects code that was actually written here and,
where testable without a live Django/Postgres/Redis/ClamAV stack, exercised
against real test cases (mocked S3 clients, mocked ClamAV clients, real
temp-directory filesystem operations) - not just reasoned about. See the
`media_upload_system_README.md` and `README.md` under `usage/` for the
detailed writeups from those sessions (worth consolidating - see Cleanup).

**Not reviewed this session, documented here only from filenames and cross-
references**: `detector/`, `ranking_filter/`, `services/`, `utils/
file_utils.py`, the root-level `validators.py`/`views.py` (if distinct from
what's described above), and whatever `models.py`/`views.py`/`urls.py`/
`serializers.py`/`consumers.py`/`routing.py`/`signals.py`/`tasks.py`/
`exceptions.py`/`apps.py` currently actually contain, if they've diverged
from what was generated here. If you want the same treatment applied to any
of these - security review, robustness pass, tests - paste the file
contents the same way you have for everything else; a tree listing alone
isn't enough to safely rewrite code without risking silently breaking real
business logic.

## Adjacent subsystems (inferred purpose only)

| Directory | Inferred purpose | Confidence |
|---|---|---|
| `detector/` | Content moderation: face detection, audio analysis + speech-to-text, image nudity detection, a real-time streaming moderation pipeline (`stream/piplen.py`, `realtime_moderation.py`), text moderation, video moderation | Filename-level only |
| `ranking_filter/` | Feed/content ranking - "featured" content selection, "dynamic streams", a recommender service | Filename-level only |
| `services/` | `media_processing.py` (post-processing pipeline?), `media_sorter.py` (sorting/organizing media?), `encryption_media.py` (the private-URL-signing / at-rest encryption integration `settings_example.py` expects) | Filename-level only |

If `services/encryption_media.py` and `services/media_processing.py` are
meant to fulfill the `STORAGE_PRIVATE_URL_SIGNER` / `STORAGE_METRICS_SINK`
contracts referenced in `settings_example.py`, they need to match these
signatures exactly (this is the one place I can be precise about the
contract, since I wrote the `Protocol` definitions they need to satisfy in
`storage/storage_settings.py`):

```python
# services/encryption_media.py
def sign_private_url(bucket: StorageBucketSpec, key: str, expires_seconds: int,
                      method: str = "get_object") -> str:
    """Must return a non-empty URL string."""

# services/media_processing.py
def storage_metrics_sink(event: str, payload: Mapping[str, object]) -> None:
    """payload always has: event, alias, success, duration_seconds, detail, environment."""
```

## Settings & hooks reference

`settings_example.py` was updated this session to fix two bugs that would
have broken Django startup if these settings were actually turned on:

1. **Stale import**: it imported `get_django_storage_settings` from
   `media.utils.storage_bootstrap`, but that module lives at
   `media/storage/storage_bootstrap.py` - `utils/` only has `file_utils.py`
   now (the stray `utils/__pycache__/vault_storage_settings.cpython-314.pyc`
   with no matching `.py` confirms `storage_settings.py` used to live there
   before it moved into `storage/`). Fixed to import from the right place.
2. **Dangling hooks**: `settings_example.py` referenced
   `media.security.validators:scan_uploaded_file`,
   `media.security.validators:validate_bucket`, and
   `media.upload.upload_handler:probe_storage_bucket` - none of which
   existed anywhere (the third also pointed at `media.upload` singular,
   which doesn't exist; `uploads/` - plural - does, but that's the
   deprecated handler's old home, not where a storage health probe
   belongs). `import_string()` resolving any of these would raise
   `StorageValidationError` at startup the moment
   `STORAGE_VIRUS_SCAN_HOOK`/`STORAGE_BUCKET_VALIDATOR`/
   `STORAGE_HEALTH_PROBE` were actually set. Fixed by implementing all
   three for real:

| Setting | Points at | What it does |
|---|---|---|
| `STORAGE_VIRUS_SCAN_HOOK` | `security/validators.py:scan_uploaded_file` | Scans a file already written to storage, using the same ClamAV client this module already had (sync, not the async wrapper - storage hooks aren't guaranteed to run inside an event loop). Best-effort on scanner-unavailable, raises on infected. |
| `STORAGE_BUCKET_VALIDATOR` | `security/validators.py:validate_bucket` | Startup policy checks beyond `StorageBucketSpec.validate()`'s syntax checks: rejects a dev/test/staging-*-looking bucket name in production, confirms SSE is actually configured on private buckets, warns (doesn't fail) if a private bucket's URLs are only "expires="-stamped rather than cryptographically signed. |
| `STORAGE_HEALTH_PROBE` | `storage/storage_bootstrap.py:probe_storage_bucket` | Actually exercises PutObject/GetObject/DeleteObject, not just HeadBucket - catches read-only credentials that would otherwise report "healthy" and only fail on the first real upload. |
| `STORAGE_METRICS_SINK` | *(your `services/` module - not implemented here)* | See contract above. |
| `STORAGE_PRIVATE_URL_SIGNER` | *(your `services/` module - not implemented here)* | See contract above. |

All five are optional - the app works with none of them set (virus scanning
and bucket validation just no-op; URLs are standard S3 presigned URLs
instead of CDN-signed ones).

## Tests

`tests/test_upload_sessions.py`, `test_uploads.py`, `test_validator.py`,
`test_validators.py`, `test_progress_tracker.py`, `test_sanitizer.py` line
up with the core system documented above. `test_audio_checker.py`,
`test_dynamic_featured.py`, `test_dynamic_streams.py`,
`test_encryption_media.py`, `test_image_nudity_detector.py`,
`test_media_processing.py`, `test_media_sorter.py`,
`test_realtime_moderation.py`, `test_recommender_service.py`,
`test_speech_to_text.py`, `test_text_moderator.py`, `test_video_moderator.py`
correspond to the adjacent subsystems and weren't touched. `test_id_verifier.py`
doesn't have an obviously-corresponding source file anywhere in this tree -
worth checking it isn't testing something that got moved/renamed/deleted.
`media_store_test.py` doesn't follow the `test_*.py` naming the rest of the
suite uses; harmless if your pytest config explicitly discovers `*_test.py`
too, worth a second look if not (it'd silently never run).

## Worth resolving

- **`validators.py` (root) vs. `security/validators.py`**: two files with
  the same name doing (presumably) different jobs is a standing invitation
  for someone to import the wrong one, or for the two to drift apart in
  ways nobody notices. If the root one is request/serializer-level field
  validation and `security/validators.py` is upload-content security
  validation, a rename (`field_validators.py`?) would make the split
  obvious from the filename instead of relying on everyone remembering
  which is which.
- **Missing `admin.py`**: not in this tree, though it's part of the core
  system built this session (`MediaFile`/`Load`/`UploadSession` admin
  registration, including a "requeue processing" action). Worth confirming
  it wasn't deleted unintentionally.
- **`migrations/0001_initial.py`**: if this predates the current
  `models.py` (the rebuild added `UploadSession`, `UploadPart`, and several
  fields on `MediaFile`/`Load`), it's out of sync. Run
  `manage.py makemigrations media` and check whether it generates new
  migrations before you deploy.

## Cleanup

Straightforward, low-risk once you've confirmed nothing still imports from
them:

- **`depriciated_upload_to_be_removed/`** - named for deletion; delete it.
  Grep for `depriciated_upload_to_be_removed` first to confirm nothing
  still imports from it.
- **`storage_old/`, `security/sanitizer_old.py`, `security/validators_old.py`**
  - pre-hardening backups. Fine to keep briefly during a rollout, but they
  invite a real failure mode: something (a stale import, a copy-pasted
  settings path) quietly pointing back at the old, unhardened version,
  silently reintroducing every bug that was just fixed. Once the new
  versions are confirmed working in your environment, delete these rather
  than leaving them as permanent fixtures - `git log` is a better home for
  "what did this used to look like" than a parallel `_old` file that has to
  be manually kept from being imported.
- **`__pycache__/` directories** (`security/`, `storage/`, `services/`,
  `tests/`, `utils/`, root) - if these are git-tracked rather than just
  local build artifacts, add `__pycache__/` and `*.pyc` to `.gitignore` and
  remove them from the repo; if they're already gitignored and this is just
  what a local checkout looks like, ignore this note.
- **`usage/README.md`, `usage/USEAGE_README.md`, `usage/media_upload_system_README.md`**
  - three READMEs with overlapping scope (and one with a typo in the
  filename) is a maintenance hazard on its own: the next person to update
  "how uploads work" has no way to know there are two other copies that now
  disagree. Worth consolidating into one, with this file as the top-level
  entry point and `usage/` reduced to whatever's genuinely
  usage-example-specific (e.g. just `requirements.txt` and a quickstart).

## Getting the core system running

```bash
pip install -r usage/requirements.txt
# copy the relevant blocks from settings_example.py into your project settings
python manage.py makemigrations media
python manage.py migrate
python manage.py test media   # or: pytest
```

Then wire up Celery beat (`CELERY_BEAT_SCHEDULE`) and your ASGI routing for
the websocket consumer, both shown in `settings_example.py`.

## Extension points (core system)

- **New storage backend**: implement `media.storage.base.StorageBackend`
  and either register it in `settings.UPLOAD_STORAGE_BACKENDS` or call
  `media.storage.registry.register_storage_backend()` at runtime. Implement
  `from_bucket_spec()` too if you want it resolvable by bucket alias
  (`get_storage_backend_for_bucket("media")`) with the full
  endpoint/credentials/retry/addressing-style config `StorageBucketSpec`
  already centralizes, instead of re-deriving your own settings surface.
- **New validator**: write `(UploadContext) -> None` raising a
  `ValidationFailed` subclass, pass it into
  `ValidationPipeline(validators=[...])`.
- **Real virus scanning**: `settings.UPLOAD_VIRUS_SCANNER` (upload-time,
  `security/validators.py`) and `settings.STORAGE_VIRUS_SCAN_HOOK`
  (post-persist, `storage/storage_settings.py`) are two different points in
  the pipeline - both point at ClamAV-backed implementations by default in
  this session's code; both are independently optional.
- **Push instead of poll for progress**: `settings.UPLOAD_PROGRESS_BACKEND`
  → `RedisProgressBackend`.
- **Multi-tenancy**: `tenant_id` is a plain `CharField`, not a hard FK - set
  it from your tenancy middleware via `request.tenant_id`.

## Known limitations (by design, not oversights)

- `UploadSession.missing_part_numbers()` requires `declared_size` up front;
  truly unknown-length streaming uploads would need a client-signaled
  "final part" flag to work, which isn't implemented.
- The local storage backend has no native multipart, so chunked uploads to
  it are assembled on the app server at `complete()` time. For large files
  in production, use the `s3` backend (or a custom S3-compatible one) so
  parts go client → storage directly.
- Native-multipart backends (S3) don't return a whole-file hash for free;
  `checksum_actual` falls back to the client-declared checksum there rather
  than a server-verified one.

This code was written and syntax/logic-checked (`py_compile` plus targeted
test scripts against mocked boto3/ClamAV clients) outside a live Django
environment, since standing up Postgres/Redis/Celery/a real S3
bucket/ClamAV wasn't available here - review it as you would any first-pass
PR before deploying, particularly the DRF view wiring and the migration
step.
