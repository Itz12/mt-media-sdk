from __future__ import annotations

import gzip
import os
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image
from pypdf import PdfReader, PdfWriter

from mt_media_sdk.services import media_processing as mp


def _png(width: int = 4, height: int = 4) -> bytes:
    output = BytesIO()
    Image.new("RGB", (width, height), (10, 20, 30)).save(output, format="PNG")
    return output.getvalue()


def _pdf(pages: int = 1) -> bytes:
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=72, height=72)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def test_temp_file_borrows_existing_path_without_deleting(tmp_path) -> None:
    path = tmp_path / "input.bin"
    path.write_bytes(b"hello")
    with mp.temp_file_path(path) as resolved:
        assert resolved == str(path)
    assert path.exists()


def test_temp_file_copies_and_removes_bytes() -> None:
    with mp.temp_file_path(b"hello") as path:
        assert os.path.exists(path)
        assert Path(path).read_bytes() == b"hello"
    assert not os.path.exists(path)


def test_temp_file_rejects_missing_path() -> None:
    with pytest.raises(mp.InvalidInputError):
        with mp.temp_file_path("/definitely/missing/file.bin"):
            pass


def test_plain_and_gzip_text_are_supported() -> None:
    assert mp.DecompressionService.decompress_text(b"hello") == "hello"
    compressed = gzip.compress(b"hello")
    assert mp.DecompressionService.decompress_text(compressed) == "hello"


def test_invalid_utf8_text_is_rejected() -> None:
    with pytest.raises(mp.InvalidInputError):
        mp.DecompressionService.decompress_text(b"\xff\xfe")


def test_gzip_ratio_limit_blocks_decompression_bomb(monkeypatch) -> None:
    monkeypatch.setenv("MEDIA_MAX_COMPRESSION_RATIO", "2")
    compressed = gzip.compress(b"a" * 10000)
    with pytest.raises(mp.MediaLimitExceeded):
        mp.DecompressionService.decompress_text(compressed)


def test_image_normalization_strips_input_container_and_returns_png() -> None:
    result = mp.DecompressionService.decompress_image(_png())
    assert result.read(8) == b"\x89PNG\r\n\x1a\n"


def test_image_pixel_limit_is_enforced(monkeypatch) -> None:
    monkeypatch.setenv("MEDIA_MAX_IMAGE_PIXELS", "1000")
    with pytest.raises(mp.InvalidInputError):
        mp.DecompressionService.decompress_image(_png(40, 40))


def test_image_compression_validates_quality_and_format() -> None:
    with pytest.raises(mp.InvalidInputError):
        mp.CompressionService.compress_image(_png(), quality=0)
    with pytest.raises(mp.UnsupportedMediaError):
        mp.CompressionService.compress_image(_png(), fmt="TIFF")
    output = mp.CompressionService.compress_image(_png(), quality=80, fmt="JPEG")
    assert output.name == "image.jpeg"


def test_pdf_roundtrip_and_page_limit(monkeypatch) -> None:
    source = _pdf(2)
    compressed = mp.CompressionService.compress_pdf(source)
    assert len(PdfReader(compressed).pages) == 2
    monkeypatch.setenv("MEDIA_MAX_PDF_PAGES", "1")
    with pytest.raises(mp.MediaLimitExceeded):
        mp.DecompressionService.decompress_pdf(source)


def test_ffmpeg_missing_is_reported_without_shell_execution(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(mp, "which", lambda _name: None)
    with pytest.raises(mp.FFmpegNotFoundError):
        mp._run_ffmpeg(str(tmp_path / "in"), str(tmp_path / "out"), [])


def test_data_processing_handles_plain_text_and_image() -> None:
    text = BytesIO(b"hello")
    text.name = "note.txt"
    text.content_type = "text/plain"
    image = BytesIO(_png())
    image.name = "photo.png"
    image.content_type = "image/png"
    result = mp.DataProcessingService().process_incoming_files(
        {"documents": [text, image]}
    )
    assert [item["media_type"] for item in result["documents"]] == ["text", "image"]
    assert all(len(item["sha256"]) == 64 for item in result["documents"])


def test_content_type_mismatch_is_rejected() -> None:
    source = BytesIO(_png())
    source.name = "photo.png"
    source.content_type = "application/pdf"
    with pytest.raises(mp.InvalidInputError):
        mp.DataProcessingService().process_incoming_files({"file": source})


def test_continue_on_error_isolates_bad_files() -> None:
    good = BytesIO(b"hello")
    good.name = "note.txt"
    good.content_type = "text/plain"
    bad = BytesIO(b"not-an-image")
    bad.name = "bad.png"
    bad.content_type = "image/png"
    result = mp.DataProcessingService().process_incoming_files(
        {"files": [good, bad]},
        continue_on_error=True,
    )
    assert len(result["files"]) == 1
    assert result["__errors__"][0]["filename"] == "bad.png"


def test_unknown_binary_is_fail_closed_by_default() -> None:
    source = BytesIO(b"unknown")
    source.name = "file.unknown"
    source.content_type = "application/octet-stream"
    with pytest.raises(mp.UnsupportedMediaError):
        mp.DataProcessingService().process_incoming_files({"file": source})
