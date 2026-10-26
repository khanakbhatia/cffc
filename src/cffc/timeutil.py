"""UTC-aware time helpers. All timestamps in the pipeline go through these.

Naive (timezone-less) timestamps are rejected rather than silently assumed to be UTC
(Stage 2 §14: "never string-matched, to avoid silent timezone bugs").
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Union


class TimeParseError(ValueError):
    pass


def parse_utc(value: Union[str, datetime]) -> datetime:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        s = value.strip()
        if s[-1:] in ("Z", "z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError as exc:
            raise TimeParseError(f"unparseable timestamp: {value!r}") from exc
    else:
        raise TimeParseError(f"timestamp must be str or datetime, got {type(value).__name__}")
    if dt.tzinfo is None:
        raise TimeParseError(f"naive timestamp (no timezone) rejected: {value!r}")
    return dt.astimezone(timezone.utc)


def format_utc(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    if dt.microsecond:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_now_str() -> str:
    return format_utc(datetime.now(timezone.utc).replace(microsecond=0))
