"""Structured JSON logging (SPEC §15.3). Never log secrets; never `print` in library code."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_REDACT_KEYS = {"password", "secret", "token", "private_key", "api_key", "authorization", "cookie"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            payload.update({k: ("***" if k.lower() in _REDACT_KEYS else v) for k, v in extra.items()})
        if record.exc_info:
            payload["exc"] = record.exc_info[0].__name__ if record.exc_info[0] else "Exception"
        return json.dumps(payload, default=str, ensure_ascii=False)


class _ExtraAdapter(logging.LoggerAdapter[logging.Logger]):
    def process(self, msg: str, kwargs: Any) -> tuple[str, Any]:
        extra = kwargs.pop("extra", None) or {}
        kwargs["extra"] = {"extra": extra}
        return msg, kwargs


def configure(level: str = "INFO") -> None:
    root = logging.getLogger()
    if any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        root.setLevel(level.upper())
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.handlers[:] = [handler]
    root.setLevel(level.upper())


def get_logger(name: str) -> _ExtraAdapter:
    return _ExtraAdapter(logging.getLogger(name), {})
