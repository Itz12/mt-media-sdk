from __future__ import annotations

import io
import os
import struct
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from mt_media_sdk.services import encryption_media as em


class LocalStorage:
    def __init__(self, root: Path):
        self._location = str(root)
        root.mkdir(parents=True, exist_ok=True)

    def _path(self, name: str) -> Path:
        return Path(self._location) / name

    def exists(self, name: str) -> bool:
        return self._path(name).exists()

    def open(self, name: str, mode: str = "rb"):
        return self._path(name).open(mode)

    def save(self, name: str, content):
        path = self._path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as output:
            while True:
                chunk = content.read(65536)
                if not chunk:
                    break
                output.write(chunk)
        return name

    def delete(self, name: str) -> None:
        self._path(name).unlink(missing_ok=True)


@pytest.fixture
def handler(tmp_path) -> em.EncryptionFileHandler:
    return em.EncryptionFileHandler(
        fernet=Fernet(Fernet.generate_key()),
        storage=LocalStorage(tmp_path),
    )


def test_versioned_stream_roundtrip_across_multiple_frames(handler, monkeypatch) -> None:
    monkeypatch.setenv("MEDIA_ENCRYPTION_STREAM_CHUNK_BYTES", "4096")
    plaintext = os.urandom(20_000)
    stored = handler.encrypt_to_storage_path(plaintext, "tenant/user/media.mtme")
    assert stored == "tenant/user/media.mtme"
    assert handler.decrypt_to_bytes(stored) == plaintext


def test_authenticated_final_frame_detects_clean_boundary_truncation(handler) -> None:
    handler.encrypt_to_storage_path(b"important", "file.mtme")
    path = Path(handler.storage._location) / "file.mtme"
    data = path.read_bytes()
    # Remove the complete final frame, which the legacy implementation could not detect.
    header_size = em._HEADER.size
    position = header_size
    frames: list[tuple[int, int]] = []
    while position < len(data):
        _sequence, _flags, length = em._FRAME_HEADER.unpack(
            data[position : position + em._FRAME_HEADER.size]
        )
        frame_end = position + em._FRAME_HEADER.size + length
        frames.append((position, frame_end))
        position = frame_end
    path.write_bytes(data[: frames[-1][0]])
    with pytest.raises(em.CorruptEncryptedMedia):
        handler.decrypt_to_bytes("file.mtme")


def test_tampered_ciphertext_is_rejected(handler) -> None:
    handler.encrypt_to_storage_path(b"important", "file.mtme")
    path = Path(handler.storage._location) / "file.mtme"
    data = bytearray(path.read_bytes())
    data[-10] ^= 1
    path.write_bytes(data)
    with pytest.raises(em.CorruptEncryptedMedia):
        handler.decrypt_to_bytes("file.mtme")


def test_storage_path_traversal_is_rejected(handler) -> None:
    with pytest.raises(ValueError):
        handler.encrypt_to_storage_path(b"secret", "../escape.mtme")


def test_caller_owned_stream_remains_open(handler) -> None:
    source = io.BytesIO(b"hello")
    handler.encrypt_to_storage_path(source, "file.mtme")
    assert source.closed is False


def test_key_rotation_reads_old_ciphertext(monkeypatch, tmp_path) -> None:
    old_key = Fernet.generate_key()
    new_key = Fernet.generate_key()
    storage = LocalStorage(tmp_path)
    old_handler = em.EncryptionFileHandler(Fernet(old_key), storage)
    old_handler.encrypt_to_storage_path(b"rotated", "file.mtme")
    monkeypatch.setenv(
        "MEDIA_ENCRYPTION_KEYS",
        f"{new_key.decode()},{old_key.decode()}",
    )
    rotated_handler = em.EncryptionFileHandler(em.get_fernet_from_settings(), storage)
    assert rotated_handler.decrypt_to_bytes("file.mtme") == b"rotated"


def test_legacy_format_can_be_read_during_migration(handler, monkeypatch, tmp_path) -> None:
    token = handler.fernet.encrypt(b"legacy")
    legacy = struct.pack(">I", len(token)) + token
    path = tmp_path / "legacy.enc"
    path.write_bytes(legacy)
    monkeypatch.setenv("MEDIA_ENCRYPTION_ALLOW_LEGACY_FORMAT", "true")
    assert handler.decrypt_to_bytes(path) == b"legacy"
    monkeypatch.setenv("MEDIA_ENCRYPTION_ALLOW_LEGACY_FORMAT", "false")
    with pytest.raises(em.CorruptEncryptedMedia):
        handler.decrypt_to_bytes(path)
