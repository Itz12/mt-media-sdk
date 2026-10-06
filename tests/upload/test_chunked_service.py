from __future__ import annotations

import hashlib
import io
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.utils import timezone

from mt_media_sdk.exceptions import (
    ChecksumMismatchError,
    InvalidStateTransitionError,
    PartOutOfRangeError,
)
from mt_media_sdk.models import (
    UploadPart,
    UploadSession,
    UploadSessionStatus,
)
from mt_media_sdk.storage.base import PresignedUpload, UploadedPart
from mt_media_sdk.uploads import chunked


class MemoryStorage:
    supports_native_multipart = False

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.save_calls = 0
        self.deleted: list[str] = []

    def save(self, path: str, fileobj) -> int:
        self.save_calls += 1
        value = fileobj.read()
        self.objects[path] = value
        return len(value)

    def open(self, path: str):
        return io.BytesIO(self.objects[path])

    def exists(self, path: str) -> bool:
        return path in self.objects

    def size(self, path: str) -> int:
        return len(self.objects[path])

    def delete(self, path: str) -> None:
        self.deleted.append(path)
        self.objects.pop(path, None)


class NativeMemoryStorage(MemoryStorage):
    supports_native_multipart = True

    def __init__(self) -> None:
        super().__init__()
        self.upload_id = "upload-1"
        self.parts: dict[int, bytes] = {}
        self.completed = False
        self.aborted = False

    def initiate_multipart(self, path: str, content_type: str) -> str:
        return self.upload_id

    def presign_part(
        self,
        path: str,
        upload_id: str,
        part_number: int,
        expire_seconds: int = 3600,
    ) -> PresignedUpload:
        return PresignedUpload(
            method="PUT",
            url=f"https://upload.invalid/{part_number}",
            expires_in=expire_seconds,
        )

    def write_part(
        self,
        path: str,
        upload_id: str,
        part_number: int,
        data: bytes,
    ) -> UploadedPart:
        self.parts[part_number] = bytes(data)
        return UploadedPart(part_number, f'"etag-{part_number}"', len(data))

    def list_multipart_parts(self, path: str, upload_id: str):
        return [
            UploadedPart(number, f'"etag-{number}"', len(value))
            for number, value in sorted(self.parts.items())
        ]

    def complete_multipart(self, path: str, upload_id: str, parts) -> None:
        self.objects[path] = b"".join(self.parts[item.part_number] for item in parts)
        self.completed = True

    def abort_multipart(self, path: str, upload_id: str) -> None:
        self.aborted = True
        self.parts.clear()


def _create_user():
    model = get_user_model()
    values: dict[str, Any] = {}
    username_field = model.USERNAME_FIELD
    if username_field == "email":
        values[username_field] = "chunk-upload@example.test"
    else:
        values[username_field] = "chunk-upload-user"
    for required in getattr(model, "REQUIRED_FIELDS", ()):
        if required in values:
            continue
        field = model._meta.get_field(required)
        if field.get_internal_type() in {"EmailField"}:
            values[required] = f"{required}@example.test"
        elif "phone" in required:
            values[required] = "+15550001001"
        else:
            values[required] = f"test-{required}"
    user = model.objects.create(**values)
    set_password = getattr(user, "set_password", None)
    if callable(set_password):
        set_password("Strong-Test-Password-1!")
        user.save(update_fields=["password"])
    return user


def _session(user, *, native: bool = False, declared_size: int = 8, chunk_size: int = 4):
    return UploadSession.objects.create(
        user=user,
        tenant_id=None,
        filename="payload.bin",
        mime_type="application/octet-stream",
        declared_size=declared_size,
        chunk_size=chunk_size,
        checksum_expected=hashlib.sha256(b"abcdefgh").hexdigest()
        if declared_size == 8
        else None,
        storage_backend="memory",
        storage_path="media/uploads/test/payload.bin",
        native_upload_id="upload-1" if native else None,
        uploaded_bytes=0,
        status=UploadSessionStatus.UPLOADING,
        expires_at=timezone.now() + timedelta(hours=1),
    )


@pytest.fixture(autouse=True)
def disable_final_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chunked, "validate_completed_stream", lambda *a, **k: None)
    monkeypatch.setattr(
        chunked.progress_tracker,
        "update_progress_by_file_id",
        lambda *a, **k: None,
    )


@pytest.mark.django_db
@override_settings(
    UPLOAD_MIN_CHUNK_SIZE_BYTES=1,
    UPLOAD_MAX_CHUNK_SIZE_BYTES=1024,
    UPLOAD_REQUIRE_EXACT_PART_SIZES=True,
    UPLOAD_CHUNK_DISK_RESERVE_BYTES=0,
)
def test_retried_part_does_not_double_count_uploaded_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with override_settings(UPLOAD_CHUNK_STAGING_DIR=str(tmp_path)):
        storage = MemoryStorage()
        monkeypatch.setattr(chunked, "get_storage_backend", lambda name: storage)
        user = _create_user()
        session = _session(user)
        service = chunked.UploadSessionService("memory")

        service.upload_part(session, 1, b"abcd")
        service.upload_part(session, 1, b"abcd")

        session.refresh_from_db()
        assert session.uploaded_bytes == 4
        assert UploadPart.objects.filter(session=session, part_number=1).count() == 1


@pytest.mark.django_db
@override_settings(
    UPLOAD_MIN_CHUNK_SIZE_BYTES=1,
    UPLOAD_MAX_CHUNK_SIZE_BYTES=1024,
    UPLOAD_REQUIRE_EXACT_PART_SIZES=True,
    UPLOAD_CHUNK_DISK_RESERVE_BYTES=0,
)
def test_replacing_part_recalculates_authoritative_total(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with override_settings(UPLOAD_CHUNK_STAGING_DIR=str(tmp_path)):
        storage = MemoryStorage()
        monkeypatch.setattr(chunked, "get_storage_backend", lambda name: storage)
        user = _create_user()
        session = _session(user)
        service = chunked.UploadSessionService("memory")

        service.upload_part(session, 1, b"abcd")
        replacement = service.upload_part(session, 1, b"wxyz")

        session.refresh_from_db()
        assert session.uploaded_bytes == 4
        assert replacement.checksum == hashlib.sha256(b"wxyz").hexdigest()


@pytest.mark.django_db
@override_settings(
    UPLOAD_MIN_CHUNK_SIZE_BYTES=1,
    UPLOAD_MAX_CHUNK_SIZE_BYTES=1024,
    UPLOAD_REQUIRE_EXACT_PART_SIZES=True,
)
def test_non_final_short_part_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = MemoryStorage()
    monkeypatch.setattr(chunked, "get_storage_backend", lambda name: storage)
    user = _create_user()
    session = _session(user)
    service = chunked.UploadSessionService("memory")

    with pytest.raises(PartOutOfRangeError):
        service.upload_part(session, 1, b"abc")
    assert UploadPart.objects.filter(session=session).count() == 0


@pytest.mark.django_db
@override_settings(
    UPLOAD_MIN_CHUNK_SIZE_BYTES=1,
    UPLOAD_MAX_CHUNK_SIZE_BYTES=1024,
    UPLOAD_REQUIRE_EXACT_PART_SIZES=True,
    UPLOAD_CHUNK_DISK_RESERVE_BYTES=0,
)
def test_local_completion_streams_exact_bytes_and_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with override_settings(UPLOAD_CHUNK_STAGING_DIR=str(tmp_path)):
        storage = MemoryStorage()
        monkeypatch.setattr(chunked, "get_storage_backend", lambda name: storage)
        user = _create_user()
        session = _session(user)
        service = chunked.UploadSessionService("memory")

        service.upload_part(session, 1, b"abcd")
        service.upload_part(session, 2, b"efgh")
        media = service.complete(session)
        again = service.complete(session)

        assert again.pk == media.pk
        assert storage.objects[session.storage_path] == b"abcdefgh"
        assert storage.save_calls == 1
        session.refresh_from_db()
        assert session.status == UploadSessionStatus.COMPLETED
        assert session.uploaded_bytes == 8


@pytest.mark.django_db
@override_settings(
    UPLOAD_MIN_CHUNK_SIZE_BYTES=1,
    UPLOAD_MAX_CHUNK_SIZE_BYTES=1024,
    UPLOAD_REQUIRE_EXACT_PART_SIZES=True,
    UPLOAD_REQUIRE_SERVER_VERIFIED_NATIVE_PARTS=True,
)
def test_presigned_native_parts_are_verified_and_registered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = NativeMemoryStorage()
    monkeypatch.setattr(chunked, "get_storage_backend", lambda name: storage)
    user = _create_user()
    session = _session(user, native=True)
    service = chunked.UploadSessionService("memory")

    storage.parts[1] = b"abcd"
    part = service.register_native_part(
        session,
        1,
        etag='"etag-1"',
        size=4,
    )

    session.refresh_from_db()
    assert part.storage_ref == '"etag-1"'
    assert session.uploaded_bytes == 4


@pytest.mark.django_db
@override_settings(
    UPLOAD_MIN_CHUNK_SIZE_BYTES=1,
    UPLOAD_MAX_CHUNK_SIZE_BYTES=1024,
    UPLOAD_REQUIRE_EXACT_PART_SIZES=True,
    UPLOAD_REQUIRE_SERVER_VERIFIED_NATIVE_PARTS=True,
)
def test_native_registration_rejects_client_storage_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = NativeMemoryStorage()
    monkeypatch.setattr(chunked, "get_storage_backend", lambda name: storage)
    user = _create_user()
    session = _session(user, native=True)
    service = chunked.UploadSessionService("memory")
    storage.parts[1] = b"abcd"

    with pytest.raises(ChecksumMismatchError):
        service.register_native_part(session, 1, etag='"wrong"', size=4)


@pytest.mark.django_db
def test_completed_session_cannot_be_aborted(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = MemoryStorage()
    monkeypatch.setattr(chunked, "get_storage_backend", lambda name: storage)
    user = _create_user()
    session = _session(user)
    session.status = UploadSessionStatus.COMPLETED
    session.save(update_fields=["status"])

    with pytest.raises(InvalidStateTransitionError):
        chunked.UploadSessionService("memory").abort(session)


@pytest.mark.django_db
def test_upload_part_constraint_is_unique_per_session() -> None:
    """Required database invariant for deployments upgrading older schemas."""
    model = UploadPart
    constraints = list(model._meta.constraints)
    assert any(
        set(getattr(item, "fields", ())) == {"session", "part_number"}
        for item in constraints
    ), "UploadPart requires a UniqueConstraint(session, part_number)"
