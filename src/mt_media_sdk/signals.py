"""
media.signals
---------------
Wires MediaFile creation to the processing pipeline (virus scan, etc).
Disconnect this receiver, or set ``instance._skip_auto_process = True``
before saving, if you want to control enqueueing yourself - e.g. bulk
imports that should skip virus scanning.
"""
from __future__ import annotations

from django.conf import settings
from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import MediaFile


@receiver(
    post_save,
    sender=MediaFile,
    dispatch_uid="mt_media_sdk.signals.auto_process_media_file",
)
def auto_process_media_file(sender, instance: MediaFile, created: bool, **kwargs):
    if (
        not created
        or getattr(instance, "_skip_auto_process", False)
        or not getattr(settings, "MT_MEDIA_AUTO_PROCESS_UPLOADS", True)
    ):
        return

    media_file_id = str(instance.pk)

    def enqueue() -> None:
        from .tasks import process_media_file

        process_media_file.delay(media_file_id)

    transaction.on_commit(enqueue, using=kwargs.get("using"))
