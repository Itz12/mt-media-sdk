from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from mt_media_sdk.exceptions import ChecksumMismatchError, PartOutOfRangeError
from mt_media_sdk.models import MediaFile, UploadSessionStatus
from mt_media_sdk.uploads.chunked import UploadSessionService

User = get_user_model()


@override_settings(
    UPLOAD_STORAGE_BACKEND="local",
    MEDIA_ROOT="/tmp/media_test_root",
    UPLOAD_VALIDATE_COMPLETED_CONTENT=False,
)
class ChunkedUploadFlowTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="x")
        self.service = UploadSessionService(storage_backend_name="local")

    def test_full_upload_and_complete(self):
        result = self.service.initiate(
            user=self.user, tenant_id=None, filename="video.mp4", mime_type="video/mp4",
            declared_size=20, chunk_size=10,
        )
        session = result["session"]
        self.assertEqual(session.total_parts, 2)

        self.service.upload_part(session, 1, b"0123456789")
        self.service.upload_part(session, 2, b"abcdefghij")

        info = self.service.resume_info(session)
        self.assertEqual(info["missing_parts"], [])

        media_file = self.service.complete(session, owner=self.user)
        self.assertIsInstance(media_file, MediaFile)
        session.refresh_from_db()
        self.assertEqual(session.status, UploadSessionStatus.COMPLETED)
        self.assertEqual(media_file.size, 20)

    def test_resume_info_reports_missing_parts_after_partial_upload(self):
        result = self.service.initiate(
            user=self.user, tenant_id=None, filename="video.mp4", mime_type="video/mp4",
            declared_size=30, chunk_size=10,
        )
        session = result["session"]
        self.service.upload_part(session, 2, b"abcdefghij")

        info = self.service.resume_info(session)
        self.assertEqual(info["missing_parts"], [1, 3])
        self.assertEqual(info["received_parts"], [2])

    def test_complete_fails_with_missing_parts(self):
        result = self.service.initiate(
            user=self.user, tenant_id=None, filename="video.mp4", mime_type="video/mp4",
            declared_size=20, chunk_size=10,
        )
        session = result["session"]
        self.service.upload_part(session, 1, b"0123456789")
        with self.assertRaises(PartOutOfRangeError):
            self.service.complete(session, owner=self.user)

    def test_part_checksum_mismatch_rejected(self):
        result = self.service.initiate(
            user=self.user, tenant_id=None, filename="doc.pdf", mime_type="application/pdf",
            declared_size=10, chunk_size=10,
        )
        session = result["session"]
        with self.assertRaises(ChecksumMismatchError):
            self.service.upload_part(
                session,
                1,
                b"0123456789",
                part_checksum="0" * 64,
            )

    def test_deduplicated_initiate_skips_transfer(self):
        checksum = "a" * 64
        existing = MediaFile.objects.create(
            owner=self.user, original_filename="dup.txt", mime_type="text/plain",
            size=5, checksum=checksum,
        )
        result = self.service.initiate(
            user=self.user, tenant_id=None, filename="dup.txt", mime_type="text/plain",
            declared_size=5, checksum_expected=checksum,
        )
        self.assertTrue(result["deduplicated"])
        self.assertEqual(result["media_file_id"], str(existing.id))
