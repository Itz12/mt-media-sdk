from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("django")

from django.db import connection, models
from django.test import override_settings
from django.test.utils import isolate_apps

from mt_media_sdk.services import encryption_media as em

pytestmark = pytest.mark.django_db(transaction=True)


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
            while chunk := content.read(65536):
                output.write(chunk)
        return name

    def delete(self, name: str) -> None:
        self._path(name).unlink(missing_ok=True)


@isolate_apps("mt_media_sdk")
def test_attachment_task_updates_only_existing_parent(monkeypatch, tmp_path) -> None:
    class AttachmentTarget(models.Model):
        media = models.FileField(upload_to="media", blank=True)

        class Meta:
            app_label = "mt_media_sdk"

    with connection.schema_editor() as editor:
        editor.create_model(AttachmentTarget)
    try:
        storage = LocalStorage(tmp_path / "storage")
        monkeypatch.setattr(em, "default_storage", storage)
        source = tmp_path / "incoming.bin"
        source.write_bytes(b"payload")
        parent = AttachmentTarget.objects.create()

        with override_settings(
            MEDIA_TASK_ALLOWED_TEMP_ROOTS=(str(tmp_path),),
            MEDIA_TASK_ALLOW_TEXT_PATH_FIELDS=False,
        ):
            result = em.save_encrypt_media_file_task(
                None,
                source_temp_path=str(source),
                dest_storage_path="tenant/media.bin",
                model_ref=AttachmentTarget,
                parent_object_id=parent.pk,
                file_field_name="media",
                encrypt=False,
            )

        parent.refresh_from_db()
        assert result["status"] == "stored"
        assert parent.media.name == "tenant/media.bin"
        assert storage.exists("tenant/media.bin")
        assert source.exists() is False
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(AttachmentTarget)


@isolate_apps("mt_media_sdk")
def test_attachment_task_never_creates_missing_parent(monkeypatch, tmp_path) -> None:
    class AttachmentTarget(models.Model):
        media = models.FileField(upload_to="media", blank=True)

        class Meta:
            app_label = "mt_media_sdk"

    with connection.schema_editor() as editor:
        editor.create_model(AttachmentTarget)
    try:
        storage = LocalStorage(tmp_path / "storage")
        monkeypatch.setattr(em, "default_storage", storage)
        source = tmp_path / "incoming.bin"
        source.write_bytes(b"payload")

        with override_settings(MEDIA_TASK_ALLOWED_TEMP_ROOTS=(str(tmp_path),)):
            with pytest.raises(AttachmentTarget.DoesNotExist):
                em.save_encrypt_media_file_task(
                    None,
                    source_temp_path=str(source),
                    dest_storage_path="tenant/media.bin",
                    model_ref=AttachmentTarget,
                    parent_object_id=999999,
                    file_field_name="media",
                    encrypt=False,
                )

        assert AttachmentTarget.objects.count() == 0
        assert storage.exists("tenant/media.bin") is False
        assert source.exists() is True
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(AttachmentTarget)
