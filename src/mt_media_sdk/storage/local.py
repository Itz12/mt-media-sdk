from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from ..exceptions import StorageBackendError
from .base import StorageBackend

_CHUNK_SIZE = 1024 * 1024

class LocalFileSystemBackend(StorageBackend):
    supports_native_multipart = False

    def __init__(self, root: str | None = None, base_url: str | None = None, *, file_permissions: int = 0o600, dir_permissions: int = 0o700, max_upload_bytes: int | None = None):
        if root is None:
            try:
                from django.conf import settings as django_settings
                root = getattr(django_settings, "MEDIA_ROOT", None)
                base_url = base_url or getattr(django_settings, "MEDIA_URL", "/media/")
            except Exception as exc:
                raise StorageBackendError(
                    "Local storage requires an explicit root or Django MEDIA_ROOT."
                ) from exc
        if not root:
            raise StorageBackendError(
                "Local storage requires an explicit root or Django MEDIA_ROOT."
            )
        self.root = os.path.abspath(os.path.expanduser(str(root)))
        self.base_url = str(base_url or "/media/")
        self.file_permissions = int(file_permissions) & 0o777
        self.dir_permissions = int(dir_permissions) & 0o777
        self.max_upload_bytes = int(max_upload_bytes) if max_upload_bytes else None
        self._ensure_root()

    @classmethod
    def from_bucket_spec(cls, bucket, settings=None):
        base_root = Path(getattr(settings, "storage_root", Path.cwd() / "storage"))
        location = bucket.location or str(bucket.alias)
        root = base_root / location
        base_url = getattr(settings, "media_url", "/media/") if bucket.alias in {"default", "media"} else f"/{bucket.alias}/"
        return cls(root=str(root), base_url=base_url, max_upload_bytes=bucket.max_upload_bytes)

    def _ensure_root(self) -> None:
        root = Path(self.root)
        root.mkdir(parents=True, exist_ok=True, mode=self.dir_permissions)
        if root.is_symlink() or not root.is_dir():
            raise StorageBackendError("Storage root must be a real directory")
        try:
            mode = stat.S_IMODE(root.stat().st_mode)
            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise StorageBackendError("Storage root must not be group/world writable")
            os.chmod(root, self.dir_permissions)
        except OSError as exc:
            raise StorageBackendError("Unable to validate storage root permissions") from exc

    def _abspath(self, path: str) -> str:
        key = self.validate_key(path)
        full = os.path.abspath(os.path.join(self.root, *key.split("/")))
        if os.path.commonpath((self.root, full)) != self.root:
            raise StorageBackendError("Path traversal detected in storage path.", path=path)
        return full

    def _ensure_dir(self, dest_dir: str) -> None:
        root = Path(self.root)
        current = root
        relative = Path(dest_dir).relative_to(root)
        for part in relative.parts:
            current = current / part
            if current.exists() and current.is_symlink():
                raise StorageBackendError("Storage directory path contains a symlink")
            current.mkdir(exist_ok=True, mode=self.dir_permissions)
            os.chmod(current, self.dir_permissions)

    def save(self, path, fileobj) -> int:
        dest = self._abspath(path)
        dest_dir = os.path.dirname(dest)
        self._ensure_dir(dest_dir)
        if os.path.lexists(dest) and os.path.islink(dest):
            raise StorageBackendError("Refusing to replace a symlinked destination", path=path)
        fd, tmp_path = tempfile.mkstemp(prefix=".upload-", dir=dest_dir)
        written = 0
        committed = False
        try:
            with os.fdopen(fd, "wb") as out:
                while True:
                    chunk = fileobj.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    if not isinstance(chunk, (bytes, bytearray, memoryview)):
                        raise StorageBackendError("Upload stream must return bytes")
                    written += len(chunk)
                    if self.max_upload_bytes is not None and written > self.max_upload_bytes:
                        raise StorageBackendError("Upload exceeded the configured maximum size", path=path)
                    out.write(chunk)
                out.flush(); os.fsync(out.fileno())
            os.chmod(tmp_path, self.file_permissions)
            os.replace(tmp_path, dest)
            committed = True
            dir_fd = os.open(dest_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try: os.fsync(dir_fd)
            finally: os.close(dir_fd)
            return written
        finally:
            if not committed:
                try: os.unlink(tmp_path)
                except OSError: pass

    def open(self, path):
        full = self._abspath(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(full, flags)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                os.close(fd)
                raise StorageBackendError("Stored object is not a regular file", path=path)
            return os.fdopen(fd, "rb")
        except OSError as exc:
            raise StorageBackendError("Failed to open stored object", path=path) from exc

    def delete(self, path) -> None:
        full = self._abspath(path)
        try:
            if os.path.islink(full):
                raise StorageBackendError("Refusing to delete a symlinked object", path=path)
            os.unlink(full)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise StorageBackendError("Failed to delete stored object", path=path) from exc

    def exists(self, path) -> bool:
        full = self._abspath(path)
        try:
            st = os.lstat(full)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(st.st_mode):
            raise StorageBackendError("Stored object path is a symlink", path=path)
        return stat.S_ISREG(st.st_mode)

    def size(self, path) -> int:
        with self.open(path) as handle:
            return int(os.fstat(handle.fileno()).st_size)

    def url(self, path, expire_seconds: int = 3600) -> str:
        key = self.validate_key(path)
        return self.base_url.rstrip("/") + "/" + key

    def __repr__(self) -> str:
        return f"LocalFileSystemBackend(root={self.root!r}, base_url={self.base_url!r})"
