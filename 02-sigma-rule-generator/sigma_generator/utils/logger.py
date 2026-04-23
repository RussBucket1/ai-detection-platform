"""Structured JSON logging via structlog — mirrors the module 01 pattern."""
from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(log_level: str, *, json_logs: bool = True) -> None:
    """Configure structlog and stdlib logging for production or development output.

    In production (json_logs=True), emits newline-delimited JSON with ISO UTC
    timestamps. In development, emits colored console output with aligned columns.
    Suppresses noisy third-party loggers to WARNING.

    Args:
        log_level: Standard log level string, e.g. "INFO", "DEBUG", "WARNING".
        json_logs: True for JSON output (production), False for colored console (dev).
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
    ]

    if json_logs:
        shared_processors.append(structlog.processors.format_exc_info)
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        shared_processors.append(structlog.dev.set_exc_info)
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level)

    for noisy in ("httpx", "httpcore", "anthropic", "asyncio", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a named structlog BoundLogger supporting .bind(), .info(), .error(), etc."""
    return structlog.get_logger(name)
