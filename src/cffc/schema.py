"""Canonical forensic-event schema (SCHEMA.md) and validation.

16 fields: the 14 fields of Stage 2 §13 plus ``schema_version`` and ``provider_specific``
(Stage 2 §14 "Schema versioning" and "provider_specific" paragraphs). Stage 3.3 §1 was not
available when this was implemented; see docs/ASSUMPTIONS.md (A1).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .timeutil import TimeParseError, parse_utc

SCHEMA_VERSION = "1.0"
UNKNOWN = "unknown"

CANONICAL_FIELDS: Tuple[str, ...] = (
    "event_id", "event_time_utc", "cloud_provider", "cloud_service", "event_type",
    "action", "principal_id", "source_ip", "resource_id", "region", "result",
    "raw_event_ref", "source_log_file", "evidence_hash", "schema_version", "provider_specific",
)
OPTIONAL_FIELDS: Tuple[str, ...] = ("source_ip", "resource_id", "region")
REQUIRED_FIELDS: Tuple[str, ...] = tuple(f for f in CANONICAL_FIELDS if f not in OPTIONAL_FIELDS)

PROVIDERS = ("aws", "azure", "gcp")
EVENT_TYPES = ("api_call", "console_login", "config_change", "network_flow")
RESULTS = ("success", "failure", "unknown")

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")
_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
_REF_RE = re.compile(r"^.+#\d+$")


@dataclass
class CanonicalEvent:
    event_id: str
    event_time_utc: str
    cloud_provider: str
    cloud_service: str
    event_type: str
    action: str
    principal_id: str
    result: str
    raw_event_ref: str
    source_log_file: str
    evidence_hash: str
    source_ip: Optional[str] = None
    resource_id: Optional[str] = None
    region: Optional[str] = None
    schema_version: str = SCHEMA_VERSION
    provider_specific: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {name: getattr(self, name) for name in CANONICAL_FIELDS}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "CanonicalEvent":
        return cls(**{k: d.get(k) for k in CANONICAL_FIELDS if k in d})

    @cached_property
    def event_dt(self):
        return parse_utc(self.event_time_utc)

    @cached_property
    def record_index(self) -> int:
        return int(self.raw_event_ref.rsplit("#", 1)[1])

    @property
    def sort_key(self):
        """Deterministic ordering: time, then delivery position (file, record index), then id.

        CloudTrail ``eventTime`` has 1-second granularity and delivery order inside a file is
        not guaranteed to be causal, so same-second ordering is a documented limitation
        (docs/ASSUMPTIONS.md A6), not a solved problem.
        """
        return (self.event_dt, self.source_log_file, self.record_index, self.event_id)


def _populated(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, dict, list)) and len(value) == 0:
        return False
    return True


def populated_field_count(event: CanonicalEvent) -> int:
    d = event.to_dict()
    return sum(1 for f in CANONICAL_FIELDS if _populated(d[f]))


def validate_event(event: Any) -> List[str]:
    """Return a list of human-readable problems (empty list == valid)."""
    d = event.to_dict() if isinstance(event, CanonicalEvent) else dict(event)
    errs: List[str] = []
    for key in d:
        if key not in CANONICAL_FIELDS:
            errs.append(f"unexpected field: {key}")
    for key in REQUIRED_FIELDS:
        if key not in d or d[key] is None:
            errs.append(f"missing required field: {key}")
    for key in REQUIRED_FIELDS:
        if key == "provider_specific" or key not in d or d[key] is None:
            continue
        if not isinstance(d[key], str) or not d[key].strip():
            errs.append(f"{key} must be a non-empty string")
    for key in OPTIONAL_FIELDS:
        v = d.get(key)
        if v is not None and (not isinstance(v, str) or not v.strip()):
            errs.append(f"{key} must be null or a non-empty string")

    ts = d.get("event_time_utc")
    if isinstance(ts, str):
        if not _TS_RE.match(ts):
            errs.append(f"event_time_utc not ISO-8601 UTC 'Z' format: {ts!r}")
        else:
            try:
                parse_utc(ts)
            except TimeParseError:
                errs.append(f"event_time_utc not a valid timestamp: {ts!r}")
    if d.get("cloud_provider") is not None and d["cloud_provider"] not in PROVIDERS:
        errs.append(f"cloud_provider must be one of {PROVIDERS}")
    if d.get("event_type") is not None and d["event_type"] not in EVENT_TYPES:
        errs.append(f"event_type must be one of {EVENT_TYPES}")
    if d.get("result") is not None and d["result"] not in RESULTS:
        errs.append(f"result must be one of {RESULTS}")
    h = d.get("evidence_hash")
    if isinstance(h, str) and not _HASH_RE.match(h):
        errs.append("evidence_hash must match ^[a-f0-9]{64}$")
    ref = d.get("raw_event_ref")
    if isinstance(ref, str) and not _REF_RE.match(ref):
        errs.append("raw_event_ref must look like '<file>#<record_index>'")
    if d.get("schema_version") is not None and d["schema_version"] != SCHEMA_VERSION:
        errs.append(f"schema_version must be {SCHEMA_VERSION!r}")
    ps = d.get("provider_specific")
    if ps is not None and not isinstance(ps, dict):
        errs.append("provider_specific must be an object")
    return errs
