# media/tests/test_sanitizer.py
import io
import zipfile
import pytest
import html

from mt_media_sdk.security import sanitizer as mod

# Use mod.ValidationError (works with or without Django)
ValidationError = mod.ValidationError

# -------------------------
# bleach failure / missing
# -------------------------
def test_validate_text_bleach_missing(monkeypatch):
    monkeypatch.setattr(mod, "bleach", None)
    dirty = '<b onclick="evil()">bold</b>'
    result = mod.validate_text(dirty)
    # fallback escapes tags
    assert result == html.escape(dirty).strip()


def test_validate_text_bleach_raises(monkeypatch):
    class DummyBleach:
        @staticmethod
        def clean(text, **kwargs):
            raise ValueError("fail")

    monkeypatch.setattr(mod, "bleach", DummyBleach)
    dirty = "<b>bold</b>"
    result = mod.validate_text(dirty)
    assert result == html.escape(dirty).strip()


# -------------------------
# python-magic missing / failing
# -------------------------
def test_get_mime_type_no_magic(tmp_path, monkeypatch):
    f = tmp_path / "file.txt"
    f.write_text("hello")
    monkeypatch.setattr(mod, "magic", None)
    with f.open("rb") as fh:
        mime = mod.get_mime_type(fh)
        assert mime in ["text/plain", "application/octet-stream"]


def test_get_mime_type_magic_raises(monkeypatch):
    class DummyMagic:
        def from_buffer(self, buf):
            raise ValueError("fail")

    monkeypatch.setattr(mod, "magic", DummyMagic())
    f = io.BytesIO(b"hello")
    mime = mod.get_mime_type(f)
    assert mime == "application/octet-stream"


def test_get_mime_type_magic_success(monkeypatch):
    class DummyMagic:
        def from_buffer(self, buf):
            return "application/fake"

    monkeypatch.setattr(mod, "magic", DummyMagic())
    f = io.BytesIO(b"data")
    mime = mod.get_mime_type(f)
    assert mime == "application/fake"


# -------------------------
# Text sanitization tests
# -------------------------
@pytest.mark.parametrize(
    "input_text,expected",
    [
        ("<script>alert(1)</script><b>ok</b>", "ok"),
        ("<b>bold</b> <i>italic</i>", "<b>bold</b> <i>italic</i>"),
        ("onload=evil()", "evil()"),
        ("DROP TABLE users;", ""),
        (None, ""),
    ],
)
def test_validate_text_basic(input_text, expected):
    result = mod.validate_text(input_text)
    assert result == expected


def test_validate_text_non_string_raises():
    with pytest.raises(ValidationError):
        mod.validate_text(123)


# -------------------------
# Safe filename
# -------------------------
@pytest.mark.parametrize(
    "name,expected",
    [
        ("normal.txt", True),
        ("/etc/passwd", False),
        ("C:\\Windows\\system32", False),
        ("../evil.py", False),
        ("good\\file.txt", True),
        ("\x00bad", False),
    ],
)
def test_safe_filename(name, expected):
    assert mod._safe_filename(name) == expected


# -------------------------
# SVG sanitization
# -------------------------
def test_sanitize_svg_removes_script_and_onclick():
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg">
        <script>alert(1)</script>
        <rect onclick="evil()" width="10" height="10"/>
    </svg>"""
    out = mod.sanitize_svg(io.BytesIO(svg))
    out_str = out.decode("utf-8")
    assert "<script" not in out_str.lower()
    assert "onclick" not in out_str.lower()
    assert "<rect" in out_str.lower()


def test_sanitize_svg_bytes_input():
    svg = b'<svg><rect width="10"/></svg>'
    out = mod.sanitize_svg(svg)
    assert b"<rect" in out


def test_sanitize_svg_empty_raises():
    with pytest.raises(ValidationError):
        mod.sanitize_svg(b"")


# -------------------------
# MIME detection
# -------------------------
def test_get_mime_type_basic(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("hello")
    with f.open("rb") as fh:
        mime = mod.get_mime_type(fh)
        assert mime in ["text/plain", "application/octet-stream"]


def test_get_mime_type_non_seekable_stream():
    class NonSeekable(io.BytesIO):
        def seekable(self):
            return False

    ns = NonSeekable(b"hello")
    mime = mod.get_mime_type(ns)
    assert mime is not None


def test_get_mime_type_strict_extension_mismatch(tmp_path):
    f = tmp_path / "file.pdf"
    f.write_text("hello")
    with f.open("rb") as fh:
        with pytest.raises(ValidationError):
            mod.get_mime_type(fh, strict_extension_check=True)


# -------------------------
# Archive scanning
# -------------------------
def make_zip_file(file_list):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        for name, data in file_list:
            zf.writestr(name, data)
    bio.seek(0)
    return bio


def test_scan_archive_valid_zip():
    f = make_zip_file([("good.txt", b"hello")])
    result = mod.scan_archive(f)
    # result is seekable (seek(0) should succeed), and returns file-like
    assert hasattr(result, "seek")


def test_scan_archive_unsafe_filename():
    f = make_zip_file([("../evil.txt", b"bad")])
    with pytest.raises(ValidationError):
        mod.scan_archive(f)


def test_scan_archive_blocked_internal_file():
    f = make_zip_file([("malware.exe", b"bad")])
    with pytest.raises(ValidationError):
        mod.scan_archive(f)


def test_scan_archive_too_many_files():
    files = [(f"f{i}.txt", b"data") for i in range(mod.ARCHIVE_MAX_FILES + 1)]
    f = make_zip_file(files)
    with pytest.raises(ValidationError):
        mod.scan_archive(f)


def test_scan_archive_large_uncompressed_size():
    f = make_zip_file([("big.dat", b"x" * (mod.ARCHIVE_MAX_UNCOMPRESSED_BYTES + 1))])
    with pytest.raises(ValidationError):
        mod.scan_archive(f)


@pytest.mark.skipif(mod.rarfile is None, reason="rarfile not installed")
def test_scan_archive_rar_mocked(monkeypatch):
    class FakeRarInfo:
        filename = "good.txt"
        file_size = 10
        is_encrypted = False

    class FakeRarFile:
        def infolist(self):
            return [FakeRarInfo()]

        def namelist(self):
            return ["good.txt"]

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

    monkeypatch.setattr(mod.rarfile, "is_rarfile", lambda f: True)
    monkeypatch.setattr(mod, "rarfile", mod.rarfile)
    monkeypatch.setattr(mod.rarfile, "RarFile", lambda f: FakeRarFile())
    bio = io.BytesIO(b"fake rar")
    result = mod.scan_archive(bio)
    assert result is not None
