# media/tests/test_validator.py
import os

# Ensure a minimal Django settings module is available before importing the module under test.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import zipfile
import asyncio
from io import BytesIO

import pytest
from django.core.files.uploadedfile import InMemoryUploadedFile, TemporaryUploadedFile
from django.core.exceptions import ValidationError

# import module under test after DJANGO_SETTINGS_MODULE set
from mt_media_sdk.security import validators as validator


@pytest.fixture(autouse=True)
def ensure_module_html(monkeypatch):
    """
    Ensure validator.html exists and can be used by awaitable_bleach_clean fallback.
    Use raising=False so the attribute is created if missing.
    """
    import html as _html

    monkeypatch.setattr(validator, "html", _html, raising=False)


def make_zip_bytes(file_map: dict) -> bytes:
    bio = BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        for name, data in file_map.items():
            zf.writestr(name, data)
    return bio.getvalue()


def test_media_limit_orm_lookup_uses_django_thread_sensitive_bridge(monkeypatch):
    from asgiref import sync

    class Limits:
        image = 987654

    class Manager:
        @staticmethod
        def first():
            return Limits()

    class Model:
        objects = Manager()

    bridge_options = []
    original_bridge = sync.sync_to_async

    def tracked_bridge(func, *, thread_sensitive=True, **kwargs):
        bridge_options.append(thread_sensitive)
        return original_bridge(func, thread_sensitive=thread_sensitive, **kwargs)

    monkeypatch.setattr(sync, "sync_to_async", tracked_bridge)
    monkeypatch.setattr(validator, "cache", None)
    monkeypatch.setattr(validator.CustomValidator, "_resolve_model_class", lambda _path: Model)
    monkeypatch.setattr(validator.CustomValidator, "_media_limit_unavailable_until", 0.0)

    assert asyncio.run(validator.CustomValidator.get_max_file_size("image")) == 987654
    assert bridge_options == [True]


def test_get_file_length_and_read_all_bytes_bytesio():
    async def _inner():
        b = BytesIO(b"hello world")
        b.name = "hello.txt"
        assert validator._get_file_length(b) == len(b.getvalue())
        assert validator._read_all_bytes(b) == b.getvalue()

    asyncio.run(_inner())


def test_safe_extract_check_zip_valid_and_unsafe():
    good_zip = make_zip_bytes({"ok.txt": b"ok"})
    validator._safe_extract_check_zip(good_zip)

    bad_zip1 = make_zip_bytes({"../evil.sh": b"rm -rf /"})
    with pytest.raises(ValidationError):
        validator._safe_extract_check_zip(bad_zip1)

    bad_zip2 = make_zip_bytes({"payload.exe": b"PE"})
    with pytest.raises(ValidationError):
        validator._safe_extract_check_zip(bad_zip2)

    many = {f"f{i}.txt": b"x" for i in range(validator.ARCHIVE_MAX_FILES + 1)}
    big_zip = make_zip_bytes(many)
    with pytest.raises(ValidationError):
        validator._safe_extract_check_zip(big_zip)


def test_validate_file_none_and_empty():
    async def _inner():
        with pytest.raises(ValidationError):
            await validator.CustomValidator.validate_file(None, "image")

        empty = BytesIO(b"")
        empty.name = "empty.jpg"
        with pytest.raises(ValidationError) as exc:
            await validator.CustomValidator.validate_file(empty, "image")
        assert "File is empty" in str(exc.value)

    asyncio.run(_inner())


def test_validate_file_svg_and_archive(monkeypatch, tmp_path):
    async def _inner():
        monkeypatch.setenv("CLAMAV_ENABLED", "false")
        monkeypatch.setattr(validator, "CLAMD_IMPORT_AVAILABLE", False)

        monkeypatch.setattr(validator, "get_mime_type", lambda f: "image/svg+xml")
        monkeypatch.setattr(validator, "sanitize_svg", lambda f: b"<svg>clean</svg>")

        svg_stream = BytesIO(b"<svg><script>alert(1)</script></svg>")
        svg_stream.name = "bad.svg"
        res = await validator.CustomValidator.validate_file(svg_stream, "image")
        assert hasattr(res, "read")
        assert getattr(res, "name", "").endswith("sanitized.svg")
        res.seek(0)
        assert b"clean" in res.read()

        monkeypatch.setattr(validator, "get_mime_type", lambda f: "application/zip")
        good_zip = make_zip_bytes({"ok.txt": b"ok"})
        zip_stream = BytesIO(good_zip)
        zip_stream.name = "upload.zip"
        res2 = await validator.CustomValidator.validate_file(zip_stream, "archive")
        assert hasattr(res2, "read")
        assert getattr(res2, "name", "").startswith("archive-")
        res2.seek(0)
        stream_bytes = res2.read()
        assert b"ok" in stream_bytes

    asyncio.run(_inner())


def test_inmemory_to_temporaryuploadedfile_conversion(monkeypatch, tmp_path):
    async def _inner():
        monkeypatch.setenv("CLAMAV_ENABLED", "false")
        monkeypatch.setattr(validator, "CLAMD_IMPORT_AVAILABLE", False)

        # force small memory limit on the module's settings object
        # module uses django.conf.settings; since we created a dummy settings module, these attributes exist there.
        import importlib

        importlib.reload(validator)  # make sure module sees environment if needed

        # reduce FILE_UPLOAD_MAX_MEMORY_SIZE via patching settings attribute on django.conf.settings
        # this uses getattr(settings, ...) inside validator; the test-only settings module defines defaults.
        from django.conf import settings as djsettings

        djsettings.FILE_UPLOAD_MAX_MEMORY_SIZE = 10
        djsettings.TEMP_UPLOAD_DIR = str(tmp_path)

        content = b"a" * 1024
        bio = BytesIO(content)
        imf = InMemoryUploadedFile(
            bio,
            field_name="file",
            name="big.png",
            content_type="image/png",
            size=len(content),
            charset=None,
        )
        monkeypatch.setattr(validator, "get_mime_type", lambda f: "image/png")
        monkeypatch.setattr(
            validator,
            "_sanitizer_is_supported_image",
            lambda _stream: True,
        )

        res = await validator.CustomValidator.validate_file(imf, "image")
        assert (
            isinstance(res, TemporaryUploadedFile)
            or getattr(res, "name", "").endswith(".png")
            or hasattr(res, "temporary_file_path")
        )
        close = getattr(res, "close", None)
        if callable(close):
            close()

    asyncio.run(_inner())


def test_validate_text_basic_and_clamav_skip(monkeypatch):
    async def _inner():
        monkeypatch.setattr(
            validator, "validate_text", lambda txt, field: f"clean:{txt}"
        )
        monkeypatch.setenv("CLAMAV_ENABLED", "false")
        monkeypatch.setattr(validator, "CLAMD_IMPORT_AVAILABLE", False)

        out = await validator.CustomValidator.validate_text("hello")
        assert out == "clean:hello"

        with pytest.raises(ValidationError):
            await validator.CustomValidator.validate_text(None)

    asyncio.run(_inner())


def test_awaitable_bleach_clean_uses_fallback_escape(monkeypatch):
    async def _inner():
        monkeypatch.setattr(validator, "BLEACH_AVAILABLE", False)
        monkeypatch.setattr(validator, "bleach", None, raising=False)

        res = await validator.awaitable_bleach_clean("<b>bad</b>")
        assert "&lt;b&gt;bad&lt;/b&gt;" in res

    asyncio.run(_inner())


class DummyUploaded:
    def __init__(self, name, content_type, data: bytes):
        self.name = name
        self.content_type = content_type
        self._data = data
        self.size = len(data)

    def read(self):
        return self._data

    def __repr__(self):
        return f"<DummyUploaded {self.name}>"


def test_validatorhandler_extract_and_validate_media_and_text(monkeypatch, tmp_path):
    async def _inner():
        monkeypatch.setenv("CLAMAV_ENABLED", "false")
        monkeypatch.setattr(validator, "CLAMD_IMPORT_AVAILABLE", False)
        # ensure temp dir in real django settings points at tmp_path for persistence
        from django.conf import settings as djsettings

        djsettings.TEMP_UPLOAD_DIR = str(tmp_path)

        img = DummyUploaded("pic.jpg", "image/jpeg", b"JPEGDATA")
        doc = DummyUploaded("report.pdf", "application/pdf", b"%PDF-1.4")
        zbytes = make_zip_bytes({"file.txt": b"x"})
        zf = DummyUploaded("archive.zip", "application/zip", zbytes)

        class FakeRequest:
            FILES = {"image": img, "doc": doc, "archive": zf}
            data = {"text1": "<b>Hello</b>", "other": "plain"}

        async def clean_text(value, field_name="text"):
            return f"cleaned:{value}"

        monkeypatch.setattr(
            validator.CustomValidator,
            "validate_text",
            staticmethod(clean_text),
        )

        async def dummy_validate(f, mtype):
            data = validator._read_all_bytes(f) or b""
            b = BytesIO(data)
            b.name = getattr(f, "name", "upload")
            return b

        monkeypatch.setattr(
            validator.CustomValidator,
            "validate_file",
            staticmethod(dummy_validate),
            raising=False,
        )

        handler = validator.ValidatorHandler()
        res = await handler.validate_media_and_text(FakeRequest())

        assert any("cleaned" in t["content"] for t in res["texts"])

        tmp_paths = []
        for group in ("images", "documents", "archives"):
            for entry in res[group]:
                assert entry["status"] == "success"
                assert "tmp_path" in entry
                tmp_paths.append(entry["tmp_path"])
                assert os.path.exists(entry["tmp_path"])

        for p in tmp_paths:
            try:
                os.unlink(p)
            except Exception:
                pass

    asyncio.run(_inner())
