from __future__ import annotations

import contextlib
import gzip
import hashlib
import logging
import os
import re
import subprocess
import tempfile
import warnings
from collections.abc import Mapping
from io import BytesIO
from pathlib import Path
from shutil import which
from typing import Any, BinaryIO, IO, Iterator, Union

import pypdf
from PIL import Image, ImageOps, UnidentifiedImageError

from .limits import (
    MediaServiceLimits,
    validate_field_name,
    validate_filename,
)
from .media_sorter import infer_media_type_from_name

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

Source = Union[str, os.PathLike[str], bytes, bytearray, BytesIO, IO[bytes]]


class MediaProcessingError(Exception):
    """Base media processing error safe for service-layer handling."""


class UnsupportedMediaError(MediaProcessingError):
    pass


class FFmpegNotFoundError(MediaProcessingError):
    pass


class ExternalProcessError(MediaProcessingError):
    pass


class InvalidInputError(MediaProcessingError):
    pass


class MediaLimitExceeded(InvalidInputError):
    pass


_FORMAT_RE = re.compile(r"^[A-Za-z0-9]{1,12}$", flags=re.ASCII)
_BITRATE_RE = re.compile(r"^[1-9][0-9]{0,6}(?:[kKmM])?$", flags=re.ASCII)
_ALLOWED_VIDEO_FORMATS = frozenset({"mp4", "mov", "mkv", "webm", "avi"})
_ALLOWED_AUDIO_FORMATS = frozenset({"wav", "mp3", "m4a", "aac", "ogg", "flac"})
_ALLOWED_IMAGE_FORMATS = frozenset({"JPEG", "PNG", "WEBP"})


def _compute_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bounded_bytes(value: bytes, *, maximum: int, label: str) -> bytes:
    if len(value) > maximum:
        raise MediaLimitExceeded(f"{label} exceeds the configured byte limit")
    return value


def _read_limited(stream: BinaryIO, *, maximum: int, chunk_size: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        total += len(chunk)
        if total > maximum:
            raise MediaLimitExceeded("input exceeds the configured byte limit")
        chunks.append(bytes(chunk))
    return b"".join(chunks)


@contextlib.contextmanager
def _open_source(source: Source) -> Iterator[tuple[BinaryIO, bool]]:
    """Yield ``(stream, owned)`` without closing caller-owned streams."""

    if isinstance(source, (bytes, bytearray)):
        stream = BytesIO(bytes(source))
        try:
            yield stream, True
        finally:
            stream.close()
        return
    if isinstance(source, (str, os.PathLike)):
        path = Path(source)
        if not path.is_file():
            raise InvalidInputError("source path does not exist or is not a regular file")
        stream = path.open("rb")
        try:
            yield stream, True
        finally:
            stream.close()
        return
    if not callable(getattr(source, "read", None)):
        raise InvalidInputError("source must be bytes, a file path, or a binary stream")
    original_position: int | None = None
    try:
        original_position = int(source.tell())
    except Exception:
        original_position = None
    try:
        try:
            source.seek(0)
        except Exception:
            pass
        yield source, False
    finally:
        if original_position is not None:
            try:
                source.seek(original_position)
            except Exception:
                pass


class temp_file_path:
    """Secure, bounded temporary-file adapter.

    Existing local paths are borrowed and never removed. New files use mode
    ``0600`` and are removed unless ``keep=True``.
    """

    def __init__(self, source: Source, suffix: str = "", keep: bool = False):
        self.source = source
        self.suffix = suffix or ""
        self.keep = bool(keep)
        self.path: str | None = None
        self._owned = False

    def __enter__(self) -> str:
        if isinstance(self.source, (str, os.PathLike)):
            path = Path(self.source)
            if not path.is_file():
                raise InvalidInputError("source path does not exist")
            self.path = str(path)
            return self.path
        limits = MediaServiceLimits.from_settings()
        fd, path = tempfile.mkstemp(suffix=self.suffix)
        os.close(fd)
        try:
            if os.name == "posix":
                os.chmod(path, 0o600)
            with open(path, "wb") as destination, _open_source(self.source) as (
                source,
                _owned,
            ):
                copied = 0
                while True:
                    chunk = source.read(limits.stream_chunk_bytes)
                    if not chunk:
                        break
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8")
                    copied += len(chunk)
                    if copied > limits.max_input_bytes:
                        raise MediaLimitExceeded("input exceeds MEDIA_MAX_INPUT_BYTES")
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
        except Exception:
            with contextlib.suppress(OSError):
                os.remove(path)
            raise
        self.path = path
        self._owned = True
        return path

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._owned and self.path and not self.keep:
            with contextlib.suppress(OSError):
                os.remove(self.path)


def _ensure_ffmpeg_available() -> str:
    executable = which("ffmpeg")
    if executable is None:
        raise FFmpegNotFoundError(
            "ffmpeg is not installed or is not available on PATH"
        )
    return executable


def _validate_output_format(value: str, *, media_type: str) -> str:
    candidate = str(value or "").strip().casefold()
    allowed = _ALLOWED_VIDEO_FORMATS if media_type == "video" else _ALLOWED_AUDIO_FORMATS
    if not candidate or _FORMAT_RE.fullmatch(candidate) is None or candidate not in allowed:
        raise InvalidInputError(f"unsupported {media_type} output format")
    return candidate




def _validate_ffmpeg_args(arguments: list[str]) -> list[str]:
    forbidden = {
        "-i",
        "-filter_complex_script",
        "-filter_script",
        "-attach",
        "-dump_attachment",
        "-protocol_whitelist",
    }
    cleaned: list[str] = []
    for argument in arguments:
        if not isinstance(argument, str):
            raise InvalidInputError("codec_args must contain only strings")
        value = argument.strip()
        if (
            not value
            or len(value) > 1024
            or "\x00" in value
            or "\n" in value
            or "\r" in value
            or value in forbidden
            or "://" in value
            or value.casefold().startswith(("file:", "concat:", "subfile:"))
        ):
            raise InvalidInputError("codec_args contains an unsafe argument")
        cleaned.append(value)
    return cleaned

def _run_ffmpeg(
    input_path: str,
    output_path: str,
    args: list[str],
    timeout: int | None = None,
) -> None:
    limits = MediaServiceLimits.from_settings()
    effective_timeout = limits.ffmpeg_timeout_seconds if timeout is None else int(timeout)
    if not 1 <= effective_timeout <= limits.ffmpeg_timeout_seconds:
        raise InvalidInputError("ffmpeg timeout exceeds configured policy")
    executable = _ensure_ffmpeg_available()
    command = [
        executable,
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-protocol_whitelist",
        "file,pipe,crypto",
        "-i",
        input_path,
        *args,
        output_path,
    ]
    try:
        result = subprocess.run(  # noqa: S603 - executable and arguments are validated
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=effective_timeout,
            check=False,
            close_fds=True,
            env={
                "PATH": os.environ.get("PATH", ""),
                "LANG": "C",
                "LC_ALL": "C",
                "HOME": tempfile.gettempdir(),
            },
        )
    except subprocess.TimeoutExpired as exc:
        raise ExternalProcessError("ffmpeg timed out") from exc
    stderr = (result.stderr or b"")[: limits.ffmpeg_max_stderr_bytes]
    if result.returncode != 0:
        message = stderr.decode("utf-8", errors="replace").strip()
        raise ExternalProcessError(f"ffmpeg failed with code {result.returncode}: {message}")
    try:
        size = os.path.getsize(output_path)
    except OSError as exc:
        raise ExternalProcessError("ffmpeg did not produce an output file") from exc
    if size <= 0 or size > limits.max_output_bytes:
        raise MediaLimitExceeded("ffmpeg output violates configured size limits")


def _gzip_decompress_limited(data: bytes, limits: MediaServiceLimits) -> bytes:
    compressed_size = max(1, len(data))
    output = BytesIO()
    try:
        with gzip.GzipFile(fileobj=BytesIO(data), mode="rb") as gz:
            total = 0
            while True:
                chunk = gz.read(limits.stream_chunk_bytes)
                if not chunk:
                    break
                total += len(chunk)
                if total > limits.max_decompressed_bytes:
                    raise MediaLimitExceeded("gzip output exceeds configured limit")
                if total / compressed_size > limits.max_compression_ratio:
                    raise MediaLimitExceeded("gzip compression ratio exceeds configured limit")
                output.write(chunk)
    except (OSError, EOFError) as exc:
        raise InvalidInputError("invalid gzip-compressed input") from exc
    return output.getvalue()


def _read_source_bytes(source: Source, *, maximum: int | None = None) -> bytes:
    limits = MediaServiceLimits.from_settings()
    cap = limits.max_input_bytes if maximum is None else min(maximum, limits.max_input_bytes)
    with _open_source(source) as (stream, _owned):
        return _read_limited(stream, maximum=cap, chunk_size=limits.stream_chunk_bytes)


class DecompressionService:
    @staticmethod
    def decompress_text(source: Source) -> str:
        limits = MediaServiceLimits.from_settings()
        data = _read_source_bytes(source)
        if data.startswith(b"\x1f\x8b"):
            data = _gzip_decompress_limited(data, limits)
        else:
            _bounded_bytes(data, maximum=limits.max_decompressed_bytes, label="text")
        try:
            return data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise InvalidInputError("text input must be valid UTF-8") from exc

    @staticmethod
    def decompress_image(source: Source, return_pil: bool = False):
        limits = MediaServiceLimits.from_settings()
        data = _read_source_bytes(source)
        previous_max = Image.MAX_IMAGE_PIXELS
        Image.MAX_IMAGE_PIXELS = limits.max_image_pixels
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(BytesIO(data)) as probe:
                    probe.verify()
                with Image.open(BytesIO(data)) as image:
                    width, height = image.size
                    if width <= 0 or height <= 0 or width * height > limits.max_image_pixels:
                        raise MediaLimitExceeded("image dimensions exceed configured policy")
                    normalized = ImageOps.exif_transpose(image)
                    normalized.load()
                    normalized = normalized.copy()
            if return_pil:
                return normalized
            output = BytesIO()
            mode = "RGBA" if "A" in normalized.getbands() else "RGB"
            normalized.convert(mode).save(output, format="PNG", optimize=True)
            if output.tell() > limits.max_output_bytes:
                raise MediaLimitExceeded("normalized image exceeds configured output limit")
            output.seek(0)
            output.name = "image.png"
            return output
        except (UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
            raise InvalidInputError("invalid or unsafe image input") from exc
        finally:
            Image.MAX_IMAGE_PIXELS = previous_max

    @staticmethod
    def decompress_pdf(source: Source) -> BytesIO:
        limits = MediaServiceLimits.from_settings()
        data = _read_source_bytes(source)
        try:
            reader = pypdf.PdfReader(BytesIO(data), strict=True)
            if reader.is_encrypted:
                raise InvalidInputError("encrypted PDFs require an explicit decrypt workflow")
            if len(reader.pages) > limits.max_pdf_pages:
                raise MediaLimitExceeded("PDF page count exceeds configured policy")
            writer = pypdf.PdfWriter()
            for page in reader.pages:
                with contextlib.suppress(Exception):
                    page.decompress_content_streams()
                writer.add_page(page)
            output = BytesIO()
            writer.write(output)
        except MediaProcessingError:
            raise
        except Exception as exc:
            raise InvalidInputError("invalid PDF input") from exc
        if output.tell() > limits.max_output_bytes:
            raise MediaLimitExceeded("PDF output exceeds configured policy")
        output.seek(0)
        output.name = "decompressed.pdf"
        return output

    @staticmethod
    def decompress_audio_video(
        source: Source,
        output_format: str = "mp4",
        codec_args: list[str] | None = None,
        timeout: int | None = None,
        media_type: str = "video",
    ) -> BytesIO:
        media = str(media_type).casefold()
        if media not in {"audio", "video"}:
            raise InvalidInputError("media_type must be audio or video")
        fmt = _validate_output_format(output_format, media_type=media)
        arguments = list(codec_args) if codec_args is not None else (
            ["-c:v", "copy", "-c:a", "copy"] if media == "video" else ["-c:a", "pcm_s16le"]
        )
        arguments = _validate_ffmpeg_args(arguments)
        with temp_file_path(source, suffix=".input") as input_path:
            fd, output_path = tempfile.mkstemp(suffix=f".{fmt}")
            os.close(fd)
            try:
                _run_ffmpeg(input_path, output_path, arguments, timeout=timeout)
                data = Path(output_path).read_bytes()
            finally:
                with contextlib.suppress(OSError):
                    os.remove(output_path)
        result = BytesIO(data)
        result.name = f"out.{fmt}"
        result.seek(0)
        return result

    @staticmethod
    def decompress_file(source: Source, media_type: str):
        normalized = str(media_type or "").strip().casefold()
        if normalized in {"text", "txt", "gzip"}:
            return DecompressionService.decompress_text(source)
        if normalized == "pdf":
            return DecompressionService.decompress_pdf(source)
        if normalized in {"image", "img", "jpg", "jpeg", "png", "gif", "webp"}:
            return DecompressionService.decompress_image(source)
        if normalized == "video":
            return DecompressionService.decompress_audio_video(
                source, output_format="mp4", media_type="video"
            )
        if normalized == "audio":
            return DecompressionService.decompress_audio_video(
                source, output_format="wav", media_type="audio"
            )
        raise UnsupportedMediaError(f"unsupported media type: {media_type}")


class CompressionService:
    @staticmethod
    def compress_image(
        source: Source,
        quality: int = 70,
        fmt: str | None = "JPEG",
    ) -> BytesIO:
        limits = MediaServiceLimits.from_settings()
        try:
            quality_value = int(quality)
        except (TypeError, ValueError) as exc:
            raise InvalidInputError("quality must be an integer") from exc
        if not 1 <= quality_value <= 95:
            raise InvalidInputError("quality must be between 1 and 95")
        format_value = str(fmt or "JPEG").strip().upper()
        if format_value not in _ALLOWED_IMAGE_FORMATS:
            raise UnsupportedMediaError("unsupported image output format")
        image = DecompressionService.decompress_image(source, return_pil=True)
        try:
            output = BytesIO()
            if format_value == "JPEG" and image.mode not in {"RGB", "L"}:
                image = image.convert("RGB")
            save_kwargs: dict[str, Any] = {"format": format_value, "optimize": True}
            if format_value in {"JPEG", "WEBP"}:
                save_kwargs["quality"] = quality_value
            image.save(output, **save_kwargs)
        finally:
            with contextlib.suppress(Exception):
                image.close()
        if output.tell() > limits.max_output_bytes:
            raise MediaLimitExceeded("compressed image exceeds configured output limit")
        output.seek(0)
        output.name = f"image.{format_value.casefold()}"
        return output

    @staticmethod
    def compress_text_to_gzip(source: Source) -> BytesIO:
        limits = MediaServiceLimits.from_settings()
        if isinstance(source, str) and not Path(source).exists():
            data = source.encode("utf-8")
        else:
            data = _read_source_bytes(source)
        output = BytesIO()
        with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as gz:
            gz.write(data)
        if output.tell() > limits.max_output_bytes:
            raise MediaLimitExceeded("gzip output exceeds configured output limit")
        output.seek(0)
        output.name = "text.gz"
        return output

    @staticmethod
    def compress_pdf(source: Source) -> BytesIO:
        limits = MediaServiceLimits.from_settings()
        data = _read_source_bytes(source)
        try:
            reader = pypdf.PdfReader(BytesIO(data), strict=True)
            if reader.is_encrypted:
                raise InvalidInputError("encrypted PDFs require an explicit decrypt workflow")
            if len(reader.pages) > limits.max_pdf_pages:
                raise MediaLimitExceeded("PDF page count exceeds configured policy")
            writer = pypdf.PdfWriter()
            for page in reader.pages:
                with contextlib.suppress(Exception):
                    page.compress_content_streams()
                writer.add_page(page)
            output = BytesIO()
            writer.write(output)
        except MediaProcessingError:
            raise
        except Exception as exc:
            raise InvalidInputError("invalid PDF input") from exc
        if output.tell() > limits.max_output_bytes:
            raise MediaLimitExceeded("compressed PDF exceeds configured output limit")
        output.seek(0)
        output.name = "compressed.pdf"
        return output

    @staticmethod
    def compress_audio_video(
        source: Source,
        output_format: str = "mp4",
        bitrate: str = "1000k",
        timeout: int | None = None,
        media_type: str = "video",
    ) -> BytesIO:
        media = str(media_type).casefold()
        fmt = _validate_output_format(output_format, media_type=media)
        bitrate_value = str(bitrate).strip()
        if _BITRATE_RE.fullmatch(bitrate_value) is None:
            raise InvalidInputError("bitrate is invalid")
        arguments = (
            ["-b:v", bitrate_value, "-b:a", "128k", "-preset", "medium"]
            if media == "video"
            else ["-b:a", bitrate_value]
        )
        return DecompressionService.decompress_audio_video(
            source,
            output_format=fmt,
            codec_args=arguments,
            timeout=timeout,
            media_type=media,
        )

    @staticmethod
    def compress_file(source: Source, media_type: str, **kwargs: Any) -> BytesIO:
        normalized = str(media_type or "").strip().casefold()
        if normalized in {"image", "img", "jpg", "jpeg", "png", "webp"}:
            return CompressionService.compress_image(
                source,
                quality=kwargs.get("quality", 70),
                fmt=kwargs.get("format", "JPEG"),
            )
        if normalized == "pdf":
            return CompressionService.compress_pdf(source)
        if normalized in {"audio", "video"}:
            default_format = "mp4" if normalized == "video" else "m4a"
            return CompressionService.compress_audio_video(
                source,
                output_format=kwargs.get("output_format", default_format),
                bitrate=kwargs.get("bitrate", "1000k"),
                timeout=kwargs.get("timeout"),
                media_type=normalized,
            )
        if normalized in {"text", "txt"}:
            return CompressionService.compress_text_to_gzip(source)
        raise UnsupportedMediaError(f"unsupported media type: {media_type}")


def detect_media_type(content_type: str, filename: str, sample: bytes = b"") -> str:
    declared = str(content_type or "").strip().casefold()
    by_name = infer_media_type_from_name(filename)
    by_magic = ""
    if sample.startswith(b"%PDF-"):
        by_magic = "pdf"
    elif sample.startswith(b"\x89PNG\r\n\x1a\n") or sample[:3] == b"\xff\xd8\xff":
        by_magic = "image"
    elif sample.startswith((b"GIF87a", b"GIF89a", b"RIFF")):
        by_magic = "image" if sample.startswith(b"GIF") else by_magic
    elif sample.startswith(b"\x1f\x8b"):
        by_magic = "text"

    declared_type = ""
    if declared.startswith("image/"):
        declared_type = "image"
    elif declared.startswith("video/"):
        declared_type = "video"
    elif declared.startswith("audio/"):
        declared_type = "audio"
    elif declared == "application/pdf":
        declared_type = "pdf"
    elif declared.startswith("text/") or declared in {"application/json", "application/xml", "application/gzip"}:
        declared_type = "text"

    strong = by_magic or by_name
    if declared_type and strong and declared_type != strong:
        raise InvalidInputError("declared content type does not match file content or extension")
    return strong or declared_type


class DataProcessingService:
    def __init__(self, logger_name: str | None = None, *, allow_binary: bool = False):
        self.logger = logging.getLogger(logger_name or __name__)
        self.allow_binary = bool(allow_binary)

    def process_incoming_files(
        self,
        files_map: Mapping[str, Any],
        *,
        continue_on_error: bool = False,
    ) -> dict[str, list[dict[str, Any]]]:
        if not isinstance(files_map, Mapping):
            raise InvalidInputError("files_map must be a mapping")
        limits = MediaServiceLimits.from_settings()
        total_files = 0
        results: dict[str, list[dict[str, Any]]] = {}
        errors: list[dict[str, str]] = []
        for raw_field, raw_value in files_map.items():
            field = validate_field_name(raw_field)
            files = list(raw_value) if isinstance(raw_value, (list, tuple)) else [raw_value]
            total_files += len(files)
            if total_files > limits.max_files_per_request:
                raise MediaLimitExceeded("too many files in one processing request")
            results[field] = []
            for source in files:
                filename = validate_filename(
                    getattr(source, "name", None) or f"{field}.bin",
                    limits=limits,
                )
                try:
                    with _open_source(source) as (stream, _owned):
                        sample = stream.read(64)
                        try:
                            stream.seek(0)
                        except Exception:
                            pass
                        media_type = detect_media_type(
                            getattr(source, "content_type", ""), filename, sample
                        )
                    if not media_type:
                        if not self.allow_binary:
                            raise UnsupportedMediaError("unable to determine a supported media type")
                        raw = _read_source_bytes(source)
                        output: Any = BytesIO(raw)
                        output.name = filename
                        media_type = "binary"
                    else:
                        output = DecompressionService.decompress_file(source, media_type)
                    results[field].append(
                        self._build_result_entry(field, filename, media_type, output)
                    )
                except Exception as exc:
                    if not continue_on_error:
                        if isinstance(exc, MediaProcessingError):
                            raise
                        raise InvalidInputError(f"failed processing {filename}") from exc
                    errors.append({"field": field, "filename": filename, "error": type(exc).__name__})
        if errors:
            results["__errors__"] = errors  # type: ignore[assignment]
        return results

    def compress_for_client(self, source: Source, media_type: str, **kwargs: Any) -> BytesIO:
        return CompressionService.compress_file(source, media_type, **kwargs)

    @staticmethod
    def _guess_media_type(content_type: str, filename: str) -> str:
        return detect_media_type(content_type, filename)

    @staticmethod
    def _build_result_entry(
        field: str,
        filename: str,
        media_type: str,
        output: Any,
    ) -> dict[str, Any]:
        if isinstance(output, str):
            encoded = output.encode("utf-8")
            return {
                "field": field,
                "filename": filename,
                "media_type": media_type,
                "data": output,
                "size": len(encoded),
                "sha256": _compute_sha256_bytes(encoded),
            }
        if isinstance(output, BytesIO):
            position = output.tell()
            output.seek(0)
            digest = hashlib.sha256()
            size = 0
            limits = MediaServiceLimits.from_settings()
            while True:
                chunk = output.read(limits.stream_chunk_bytes)
                if not chunk:
                    break
                size += len(chunk)
                if size > limits.max_output_bytes:
                    raise MediaLimitExceeded("processed output exceeds configured limit")
                digest.update(chunk)
            output.seek(0 if position == 0 else min(position, size))
            return {
                "field": field,
                "filename": filename or getattr(output, "name", None),
                "media_type": media_type,
                "data": output,
                "size": size,
                "sha256": digest.hexdigest(),
            }
        raise InvalidInputError("processor returned an unsupported output type")


def decompress_file(source: Source, media_type: str):
    return DecompressionService.decompress_file(source, media_type)


__all__ = [
    "CompressionService",
    "DataProcessingService",
    "DecompressionService",
    "ExternalProcessError",
    "FFmpegNotFoundError",
    "InvalidInputError",
    "MediaLimitExceeded",
    "MediaProcessingError",
    "UnsupportedMediaError",
    "decompress_file",
    "detect_media_type",
    "temp_file_path",
]
