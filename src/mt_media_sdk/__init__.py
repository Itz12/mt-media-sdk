"""Reusable media processing, upload, and storage SDK for Django services."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

__version__ = "1.0.0"

__all__ = ["__version__", "media_sorter"]


def __getattr__(name: str) -> ModuleType:
    """Load compatibility modules without importing Django or optional features."""
    if name == "media_sorter":
        module = import_module(".services.media_sorter", __name__)
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
