"""Runtime file logging setup for CLI and packaged app entry points."""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from forensic_claw.config.paths import get_logs_dir

_SINKS: dict[str, int] = {}


def configure_runtime_file_logging(name: str, *, debug: bool = False) -> Path:
    """Write runtime logs to the active config directory and enable package loggers."""
    safe_name = "".join(
        char if char.isalnum() or char in {"-", "_", "."} else "_" for char in name
    ).strip("._-")
    safe_name = safe_name or "runtime"
    log_path = get_logs_dir() / f"{safe_name}.log"

    if safe_name not in _SINKS:
        _SINKS[safe_name] = logger.add(
            log_path,
            level="DEBUG",
            rotation="10 MB",
            retention="14 days",
            encoding="utf-8",
            enqueue=True,
            backtrace=debug,
            diagnose=False,
            format=(
                "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} | "
                "{name}:{function}:{line} | {message}"
            ),
        )

    logger.enable("forensic_claw")
    return log_path
