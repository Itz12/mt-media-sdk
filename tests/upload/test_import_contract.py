from __future__ import annotations

import ast
import inspect
from pathlib import Path

import mt_media_sdk.uploads.chunked as chunked
from mt_media_sdk.uploads.chunked import UploadSessionService as CompatibilityService


def test_compatibility_import_points_to_canonical_service() -> None:
    assert CompatibilityService is chunked.UploadSessionService


def test_chunked_module_does_not_import_missing_validation_symbols() -> None:
    source_path = inspect.getsourcefile(chunked)
    assert source_path is not None
    source = Path(source_path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in {
            "mt_media_sdk.security.validators",

        }:
            names = {alias.name for alias in node.names}
            if {"UploadContext", "ValidationPipeline"} & names:
                forbidden.append((node.module, names))
    assert forbidden == []


def test_public_upload_service_contract_is_retained() -> None:
    expected = {
        "initiate",
        "presign_part",
        "upload_part",
        "resume_info",
        "complete",
        "abort",
        "expire_and_cleanup",
        "register_native_part",
        "confirm_part",
    }
    assert expected <= set(dir(chunked.UploadSessionService))
