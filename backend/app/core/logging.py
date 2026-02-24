"""
Structured logging configuration for ReconScope.

All log records include the fields ``module``, ``action``, and ``target`` so
that every log line is machine-parseable while remaining human-readable.

Usage::

    from app.core.logging import configure_logging, get_logger

    configure_logging()                # call once at startup
    logger = get_logger(__name__)
    logger.info("scan started", extra={"action": "scan_start", "target": "example.com"})
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

from app.config import get_settings

# ── Constants ────────────────────────────────────────────────────────────────

_LOG_FORMAT: str = (
    "%(asctime)s | %(levelname)-8s | %(name)s | "
    "action=%(action)s | target=%(target)s | %(message)s"
)
_DATE_FORMAT: str = "%Y-%m-%dT%H:%M:%S%z"
_ROOT_LOGGER_NAME: str = "reconscope"


# ── Custom Formatter ─────────────────────────────────────────────────────────

class StructuredFormatter(logging.Formatter):
    """Formatter that injects default values for structured fields.

    If a log record is missing the ``action`` or ``target`` attribute, this
    formatter supplies a dash (``-``) so that the format string never raises a
    ``KeyError``.
    """

    _DEFAULTS: dict[str, str] = {
        "action": "-",
        "target": "-",
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format the specified record, injecting defaults for missing fields.

        Args:
            record: The log record to format.

        Returns:
            The formatted log string.
        """
        for key, default in self._DEFAULTS.items():
            if not hasattr(record, key):
                setattr(record, key, default)
        return super().format(record)


# ── Public API ───────────────────────────────────────────────────────────────

def configure_logging(level: Optional[str] = None) -> None:
    """Initialise the application-wide logging configuration.

    This should be called exactly once during application startup (e.g. in a
    FastAPI ``lifespan`` handler or ``on_event("startup")`` callback).

    Args:
        level: Override the log level.  When ``None``, ``DEBUG`` is used if
            ``settings.DEBUG`` is truthy, otherwise ``INFO``.
    """
    settings = get_settings()

    if level is None:
        level = "DEBUG" if settings.DEBUG else "INFO"

    root_logger: logging.Logger = logging.getLogger(_ROOT_LOGGER_NAME)
    root_logger.setLevel(level)

    # Avoid adding duplicate handlers on repeated calls (e.g. in tests).
    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        handler.setFormatter(StructuredFormatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
        root_logger.addHandler(handler)

    # Silence noisy third-party loggers.
    for noisy_logger in ("uvicorn.access", "sqlalchemy.engine", "celery"):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)

    root_logger.info(
        "Logging configured at %s level",
        level,
        extra={"action": "logging_init", "target": settings.APP_NAME},
    )


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``reconscope`` namespace.

    All loggers returned share the handlers and level configured by
    :func:`configure_logging`.

    Args:
        name: Typically ``__name__`` of the calling module.  The logger is
            created as ``reconscope.<name>``.

    Returns:
        A :class:`logging.Logger` instance.
    """
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")
