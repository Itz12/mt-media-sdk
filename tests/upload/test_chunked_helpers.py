from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from django.core.exceptions import ValidationError
from django.test import override_settings

from mt_media_sdk.exceptions import PartOutOfRangeError
from mt_media_sdk.uploads.chunked import (
    _expected_part_size,
    _replace_local_part,
    _session_parts_dir,
    _total_parts,
)
from mt_media_sdk.uploads.validation import (
    UploadContext,
    ValidationPipeline,
    normalize_filename,
    normalize_sha256,
    validate_json_metadata,
)


def test_total_parts_and_final_part_size() -> None:
    assert _total_parts(10, 4) == 3
    assert _expected_part_size(10, 4, 1) == 4
    assert _expected_part_size(10, 4, 2) == 4
    assert _expected_part_size(10, 4, 3) == 2
    with pytest.raises(PartOutOfRangeError):
        _expected_part_size(10, 4, 4)


def test_checksum_normalization_is_strict() -> None:
    digest = hashlib.sha256(b"payload").hexdigest()
    assert normalize_sha256(digest.upper()) == digest
    assert normalize_sha256("") is None
    with pytest.raises(ValidationError):
        normalize_sha256("not-a-sha256")


def test_filename_removes_client_paths_but_rejects_hidden_names() -> None:
    assert normalize_filename(r"C:\\fakepath\\photo.JPG") == "photo.JPG"
    with pytest.raises(ValidationError):
        normalize_filename("../.env")


def test_metadata_rejects_nan_and_excessive_payload() -> None:
    with pytest.raises(ValidationError):
        validate_json_metadata({"score": float("nan")})
    with override_settings(UPLOAD_MAX_METADATA_BYTES=8):
        with pytest.raises(ValidationError):
            validate_json_metadata({"value": "too large"})


def test_initiation_pipeline_normalizes_contract() -> None:
    digest = hashlib.sha256(b"payload").hexdigest()
    with override_settings(UPLOAD_MAX_DECLARED_SIZE_BYTES=100):
        context = ValidationPipeline().run(
            UploadContext(
                filename="folder/photo.JPG",
                mime_type="IMAGE/JPEG; charset=binary",
                size="7",
                tenant_id="tenant-1",
                checksum=digest.upper(),
            )
        )
    assert context.filename == "photo.JPG"
    assert context.mime_type == "image/jpeg"
    assert context.size == 7
    assert context.checksum == digest


@override_settings(UPLOAD_CHUNK_DISK_RESERVE_BYTES=0)
def test_local_part_replacement_can_commit_and_rollback(tmp_path: Path) -> None:
    target = tmp_path / "part"
    target.write_bytes(b"old")

    mutation = _replace_local_part(target, b"new")
    assert target.read_bytes() == b"new"
    mutation.rollback()
    assert target.read_bytes() == b"old"

    mutation = _replace_local_part(target, b"final")
    mutation.commit()
    assert target.read_bytes() == b"final"


@override_settings(UPLOAD_CHUNK_STAGING_DIR="/tmp/chunked-upload-test")
def test_session_directory_rejects_non_uuid_identifiers() -> None:
    with pytest.raises(ValidationError):
        _session_parts_dir("../../escape")
