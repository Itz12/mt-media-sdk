"""
media.exceptions
-----------------
Central exception hierarchy for the upload subsystem.

Keeping every upload-related error under one ``UploadError`` base makes it
trivial for API views to catch-and-translate into consistent HTTP responses
(see ``media.views.UploadErrorMixin``), and lets background workers tell
*retryable* problems (scanner temporarily down, storage hiccup) apart from
*terminal* ones (infected file, bad checksum) without string-matching
messages.
"""
from __future__ import annotations


class UploadError(Exception):
    """Base class for all upload-related errors."""

    #: Stable, machine-readable code. API responses and the websocket
    #: protocol key off this instead of parsing human-readable text.
    code = "upload_error"
    #: Whether a caller may reasonably retry the *same* operation as-is.
    retryable = False

    def __init__(self, message: str | None = None, **context):
        self.message = message or self.__class__.__doc__ or self.code
        self.context = context
        super().__init__(self.message)

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, **self.context}


class ValidationFailed(UploadError):
    """A file or request failed validation before any bytes were persisted."""
    code = "validation_failed"


class FileTooLargeError(ValidationFailed):
    """The declared or observed size exceeds the configured limit."""
    code = "file_too_large"


class InvalidFileTypeError(ValidationFailed):
    """The extension/MIME type is not permitted, or contents don't match it."""
    code = "invalid_file_type"


class UnsafeFilenameError(ValidationFailed):
    """The filename contains unsafe characters or path traversal segments."""
    code = "unsafe_filename"


class ChecksumMismatchError(UploadError):
    """The computed checksum did not match the client-declared checksum."""
    code = "checksum_mismatch"


class VirusDetectedError(UploadError):
    """The virus scanner flagged the uploaded content as infected."""
    code = "virus_detected"


class ScanUnavailableError(UploadError):
    """The virus scanner could not be reached; retryable by policy."""
    code = "scan_unavailable"
    retryable = True


class UploadSessionError(UploadError):
    """Base class for chunked/resumable upload session errors."""
    code = "upload_session_error"


class UploadSessionNotFoundError(UploadSessionError):
    code = "upload_session_not_found"


class UploadSessionExpiredError(UploadSessionError):
    code = "upload_session_expired"


class InvalidStateTransitionError(UploadSessionError):
    """Attempted an operation not valid for the session's current status."""
    code = "invalid_state_transition"


class PartOutOfRangeError(UploadSessionError):
    """Part number/size doesn't match the session's chunking contract, or
    parts are missing at completion time."""
    code = "part_out_of_range"


class RateLimitExceededError(UploadError):
    code = "rate_limit_exceeded"
    retryable = True


class StorageBackendError(UploadError):
    """The underlying storage backend raised a sanitized operational error."""

    code = "storage_error"
    retryable = True

    def __init__(self, message: str, *, path: str | None = None) -> None:
        self.path = path
        super().__init__(message)

    def __repr__(self) -> str:
        return f"StorageBackendError(path_configured={self.path is not None})"
