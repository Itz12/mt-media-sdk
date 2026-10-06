from __future__ import annotations

import ast
from pathlib import Path


def test_service_tree_contains_no_concatenated_duplicate_tests() -> None:
    root = Path(__file__).resolve().parent
    for path in root.glob("test_*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names: set[str] = set()
        duplicates: set[str] = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name in names:
                    duplicates.add(node.name)
                names.add(node.name)
        assert duplicates == set(), f"duplicate definitions in {path.name}: {duplicates}"


def test_legacy_import_paths_resolve_to_same_public_functions() -> None:
    from mt_media_sdk import media_sorter as legacy
    from mt_media_sdk.services import media_sorter as canonical

    assert legacy.sort_media is canonical.sort_media
    assert legacy.infer_media_type_from_name is canonical.infer_media_type_from_name
