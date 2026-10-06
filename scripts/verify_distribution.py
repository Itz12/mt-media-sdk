#!/usr/bin/env python3
"""Fail CI when the built mt-media-sdk distribution is missing required package files."""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

REQUIRED_WHEEL_PATHS = {
    "mt_media_sdk/__init__.py",
    "mt_media_sdk/apps.py",
    "mt_media_sdk/models.py",
    "mt_media_sdk/migrations/0001_initial.py",
    "mt_media_sdk/security/validators.py",
    "mt_media_sdk/services/media_sorter.py",
    "mt_media_sdk/storage/storage_settings.py",
    "mt_media_sdk/uploads/chunked.py",
}


def verify_wheel(path: Path) -> None:
    if not path.is_file():
        raise SystemExit(f"wheel not found: {path}")

    with zipfile.ZipFile(path) as wheel:
        names = set(wheel.namelist())

    missing = sorted(REQUIRED_WHEEL_PATHS - names)
    if missing:
        rendered = "\n".join(f"  - {item}" for item in missing)
        raise SystemExit(f"wheel is missing required SDK files:\n{rendered}")

    package_files = [name for name in names if name.startswith("mt_media_sdk/")]
    if len(package_files) < 20:
        raise SystemExit(
            f"wheel contains only {len(package_files)} mt_media_sdk files; "
            "package discovery is probably broken"
        )

    print(f"verified wheel: {path} ({len(package_files)} package files)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args()
    verify_wheel(args.wheel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
