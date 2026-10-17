"""In-memory ring buffer of recent log records, shown in the admin console."""

from __future__ import annotations

import collections
import logging
from datetime import datetime, timezone

from .config import settings

log_buffer: collections.deque = collections.deque(maxlen=2000)


class MemoryHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            log_buffer.append(
                {
                    "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
                    "level": record.levelname,
                    "logger": record.name,
                    "msg": self.format(record),
                }
            )
        except Exception:
            pass


def configure_logging() -> None:
    """Attach the memory handler and a stream handler to the app loggers."""
    memory = MemoryHandler()
    stream = logging.StreamHandler()
    stream.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    app_logger = logging.getLogger("app")
    app_logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))
    if not any(isinstance(h, MemoryHandler) for h in app_logger.handlers):
        app_logger.addHandler(memory)
        app_logger.addHandler(stream)
        logging.getLogger("uvicorn.error").addHandler(memory)
        logging.getLogger("uvicorn.access").addHandler(memory)
