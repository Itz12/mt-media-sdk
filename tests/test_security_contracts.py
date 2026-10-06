from __future__ import annotations

import io
from unittest.mock import patch

from django.db import IntegrityError, transaction
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from mt_media_sdk.exceptions import ScanUnavailableError, StorageBackendError, UploadError
from mt_media_sdk.models import (
    MediaFile,
    MediaLimit,
    MediaStatus,
    UploadSession,
)
from mt_media_sdk.storage.s3 import S3StorageBackend
from mt_media_sdk.tasks import ClamAVVirusScanner
from mt_media_sdk.views import (
    MediaFileViewSet,
    UploadSessionDetailView,
    _control_cache_key_for_user,
    _status_cache_key_for_user,
)


class _URLBackend:
    def __init__(self, *, private: bool) -> None:
        self.supports_private_download_urls = private
        self.calls = 0

    def url(self, path: str, expire_seconds: int = 60) -> str:
        self.calls += 1
        return f"https://media.example/{path}?expires={expire_seconds}"


class _ClamAVClient:
    def __init__(self, response) -> None:
        self.response = response
        self.closed = False

    def instream(self, _fileobj):
        return self.response

    def close(self) -> None:
        self.closed = True


class SecurityContractTests(TestCase):
    def setUp(self) -> None:
        self.user = get_user_model().objects.create_user(
            username="security-contract-user",
            password="not-used-by-tests",
        )
        self.factory = APIRequestFactory()

    def test_deduplication_never_crosses_tenant_boundaries(self) -> None:
        tenant_file = MediaFile.all_objects.create(
            tenant_id="tenant-a",
            file="media/tenant-a/file.txt",
            checksum="a" * 64,
            size=4,
            status=MediaStatus.READY,
        )
        global_file = MediaFile.all_objects.create(
            tenant_id=None,
            file="media/global/file.txt",
            checksum="a" * 64,
            size=4,
            status=MediaStatus.READY,
        )

        assert MediaFile.objects.find_duplicate("a" * 64, 4, None) == global_file
        assert MediaFile.objects.find_duplicate("a" * 64, 4, "tenant-a") == tenant_file
        assert MediaFile.objects.find_duplicate("a" * 64, 4, "tenant-b") is None

    def test_only_one_global_media_limit_can_exist(self) -> None:
        MediaLimit.objects.create(tenant_id=None)
        with self.assertRaises(IntegrityError), transaction.atomic():
            MediaLimit.objects.create(tenant_id="")

    def test_private_file_fails_closed_without_protected_url_support(self) -> None:
        media = MediaFile(file="media/private.txt", is_public=False, storage_backend="local")
        backend = _URLBackend(private=False)
        with patch("mt_media_sdk.storage.registry.get_storage_backend", return_value=backend):
            assert media.get_url() is None
        assert backend.calls == 0

    def test_public_file_can_use_regular_backend_url(self) -> None:
        media = MediaFile(file="media/public.txt", is_public=True, storage_backend="local")
        backend = _URLBackend(private=False)
        with patch("mt_media_sdk.storage.registry.get_storage_backend", return_value=backend):
            assert media.get_url(expire_seconds=120) == (
                "https://media.example/media/public.txt?expires=120"
            )
        assert backend.calls == 1

    def test_s3_backend_declares_protected_download_support(self) -> None:
        assert S3StorageBackend.supports_private_download_urls is True

    def test_storage_errors_use_common_sanitized_upload_contract(self) -> None:
        error = StorageBackendError("Storage operation failed", path="/private/secret")
        assert isinstance(error, UploadError)
        assert error.retryable is True
        assert error.to_dict() == {
            "code": "storage_error",
            "message": "Storage operation failed",
        }

    def test_clamav_adapter_parses_clean_and_infected_results(self) -> None:
        clean_client = _ClamAVClient({"stream": ("OK", None)})
        infected_client = _ClamAVClient({"stream": ("FOUND", "Eicar-Test-Signature")})
        with patch(
            "mt_media_sdk.security.validators.get_clamav_client",
            return_value=clean_client,
        ):
            assert ClamAVVirusScanner().scan(io.BytesIO(b"clean")).clean is True
        with patch(
            "mt_media_sdk.security.validators.get_clamav_client",
            return_value=infected_client,
        ):
            result = ClamAVVirusScanner().scan(io.BytesIO(b"infected"))
        assert result.clean is False
        assert result.detail == "Eicar-Test-Signature"
        assert clean_client.closed and infected_client.closed

    def test_clamav_adapter_fails_closed_when_scanner_is_unavailable(self) -> None:
        with patch(
            "mt_media_sdk.security.validators.get_clamav_client",
            return_value=None,
        ), self.assertRaises(ScanUnavailableError):
            ClamAVVirusScanner().scan(io.BytesIO(b"data"))

    def test_media_api_scopes_global_and_tenant_requests_separately(self) -> None:
        global_file = MediaFile.all_objects.create(
            tenant_id=None,
            owner=self.user,
            file="media/global.txt",
            is_public=True,
        )
        tenant_file = MediaFile.all_objects.create(
            tenant_id="tenant-a",
            owner=self.user,
            file="media/tenant-a.txt",
            is_public=True,
        )
        view = MediaFileViewSet.as_view({"get": "list"})

        global_request = self.factory.get("/")
        global_request.tenant_id = None
        force_authenticate(global_request, user=self.user)
        global_response = view(global_request)
        global_ids = {item["id"] for item in global_response.data["results"]}

        tenant_request = self.factory.get("/")
        tenant_request.tenant_id = "tenant-a"
        force_authenticate(tenant_request, user=self.user)
        tenant_response = view(tenant_request)
        tenant_ids = {item["id"] for item in tenant_response.data["results"]}

        assert global_ids == {str(global_file.id)}
        assert tenant_ids == {str(tenant_file.id)}

    def test_upload_session_lookup_rejects_cross_tenant_access(self) -> None:
        session = UploadSession.objects.create(
            tenant_id="tenant-a",
            user=self.user,
            filename="file.txt",
            storage_path="tenant-a/file.txt",
        )
        request = self.factory.get("/")
        request.tenant_id = "tenant-b"
        force_authenticate(request, user=self.user)
        response = UploadSessionDetailView.as_view()(request, session_id=session.id)
        assert response.status_code == 404

    def test_progress_and_control_cache_keys_are_tenant_scoped(self) -> None:
        assert _status_cache_key_for_user(self.user, None) != (
            _status_cache_key_for_user(self.user, "tenant-a")
        )
        assert _control_cache_key_for_user(self.user, "tenant-a") != (
            _control_cache_key_for_user(self.user, "tenant-b")
        )
