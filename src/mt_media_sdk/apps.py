from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from typing import Optional

from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ClamAVProbeResult:
    available: bool
    transport: str
    address: str | None = None
    port: int | None = None
    message: str | None = None


class MTMediaSDKConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "mt_media_sdk"
    label = "mt_media_sdk"

    """
    Application configuration for the media app.

    This single AppConfig replaces the duplicated variants that previously existed
    in the codebase. It keeps the existing behavior while making startup safer:

    - registers signal handlers once
    - validates storage bootstrap settings
    - optionally probes ClamAV/clamd availability
    - avoids import-time side effects
    - fails closed only for storage misconfiguration when strict validation is enabled
    """



    # Guard against accidental double-execution in uncommon startup paths.
    _ready_ran = False

    def ready(self) -> None:
        if self.__class__._ready_ran:
            return
        self.__class__._ready_ran = True

        self._register_signals()
        self._validate_storage_bootstrap()
        self._probe_clamav()

    def _register_signals(self) -> None:
        try:
            from . import signals  # noqa: F401
        except Exception:
            logger.exception("Failed to import media signals during AppConfig.ready().")
            # Signal registration failure is serious, but do not crash app startup
            # unless you want to enforce it explicitly in your deployment.
            return

    def _validate_storage_bootstrap(self) -> None:
        enabled = bool(
            getattr(settings, "MT_MEDIA_VALIDATE_STORAGE_ON_STARTUP", False)
        )
        if not enabled:
            return
        try:
            from .storage.storage_bootstrap import get_storage_settings
        except Exception:
            logger.exception("Could not import storage bootstrap utilities.")
            return

        try:
            storage_settings = get_storage_settings()
        except Exception as exc:
            raise ImproperlyConfigured(f"Invalid storage configuration: {exc}") from exc

        try:
            if getattr(storage_settings, "health_check_enabled", False):
                report = storage_settings.health_check()
                if not getattr(report, "ok", False):
                    failures = getattr(report, "failures", None) or []
                    message = "Storage health validation failed"
                    if failures:
                        message += ": " + "; ".join(str(item) for item in failures)
                    if getattr(storage_settings, "strict_startup_validation", False):
                        raise ImproperlyConfigured(message)
                    logger.warning(message)
        except ImproperlyConfigured:
            raise
        except Exception:
            logger.exception("Storage bootstrap health check failed unexpectedly.")

    def _probe_clamav(self) -> None:
        enabled = bool(
            getattr(settings, "MT_MEDIA_CLAMAV_STARTUP_PROBE", False)
        ) or os.getenv("CLAMD_ENABLED", "false").strip().lower() == "true"
        if not enabled:
            logger.info("[ClamAV] Scanner is disabled via config.")
            return

        try:
            result = self._connect_clamd()
            if result.available:
                logger.info(
                    "[ClamAV] Service is available via %s%s",
                    result.transport,
                    f" ({result.address}:{result.port})" if result.address else "",
                )
            else:
                logger.warning(
                    "[ClamAV] Scanner probe failed via %s: %s",
                    result.transport,
                    result.message or "unknown error",
                )
        except Exception:
            logger.exception("[ClamAV] Unexpected error while probing scanner availability.")

    def _connect_clamd(self) -> ClamAVProbeResult:
        try:
            from clamd import ClamdNetworkSocket, ClamdUnixSocket, ConnectionError
        except Exception as exc:
            return ClamAVProbeResult(
                available=False,
                transport="unavailable",
                message=f"clamd package not installed: {exc}",
            )

        use_tcp = os.getenv("CLAMAV_USE_TCP", "false").strip().lower() == "true"
        if use_tcp:
            host = os.getenv("CLAMAV_TCP_ADDR") or self._detect_wsl_ip() or "127.0.0.1"
            port = self._safe_int(os.getenv("CLAMAV_TCP_PORT"), default=3310)
            try:
                cd = ClamdNetworkSocket(host=host, port=port)
                response = cd.ping()
                return ClamAVProbeResult(
                    available=bool(response),
                    transport="tcp",
                    address=host,
                    port=port,
                    message=str(response),
                )
            except ConnectionError as exc:
                return ClamAVProbeResult(
                    available=False,
                    transport="tcp",
                    address=host,
                    port=port,
                    message=str(exc),
                )
            except Exception as exc:
                return ClamAVProbeResult(
                    available=False,
                    transport="tcp",
                    address=host,
                    port=port,
                    message=str(exc),
                )

        socket_path = os.getenv("CLAMAV_UNIX_SOCKET", "/var/run/clamav/clamd.ctl")
        try:
            cd = ClamdUnixSocket(path=socket_path)
            response = cd.ping()
            return ClamAVProbeResult(
                available=bool(response),
                transport="unix",
                address=socket_path,
                message=str(response),
            )
        except ConnectionError as exc:
            return ClamAVProbeResult(
                available=False,
                transport="unix",
                address=socket_path,
                message=str(exc),
            )
        except Exception as exc:
            return ClamAVProbeResult(
                available=False,
                transport="unix",
                address=socket_path,
                message=str(exc),
            )

    @staticmethod
    def _safe_int(value: Optional[str], default: int) -> int:
        try:
            return int(str(value).strip()) if value not in (None, "") else default
        except Exception:
            return default

    @staticmethod
    def _detect_wsl_ip() -> Optional[str]:
        """
        Best-effort WSL2 IP discovery for TCP ClamAV connections.

        Tries a command-free Linux path first, then falls back to the original
        `wsl ip addr show eth0` approach when running in a Windows-hosted WSL shell.
        """
        # Prefer a no-shell fallback if an address has been explicitly provided.
        env_ip = os.getenv("CLAMAV_TCP_ADDR")
        if env_ip:
            return env_ip.strip() or None

        candidates = [
            ["ip", "-4", "-o", "addr", "show", "eth0"],
            ["/sbin/ip", "-4", "-o", "addr", "show", "eth0"],
            ["wsl", "ip", "addr", "show", "eth0"],
        ]

        for cmd in candidates:
            try:
                proc = subprocess.run(  # noqa: S603 - fixed command list, no shell
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                output = proc.stdout or ""
                for line in output.splitlines():
                    if "inet " in line:
                        parts = line.strip().split()
                        for idx, part in enumerate(parts):
                            if part == "inet" and idx + 1 < len(parts):
                                return parts[idx + 1].split("/")[0]
            except Exception:
                logger.debug("Could not detect WSL network address using %r", cmd)
                continue

        return None
