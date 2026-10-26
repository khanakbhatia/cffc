"""Azure Activity Log -> CanonicalEvent.  DESIGN-LEVEL ONLY.

Implements the Stage 2 §14 field mapping so RQ1 (schema structural portability) can be
checked on hand-written synthetic samples. It has NOT been validated against live Azure
data and must not be described as empirically validated (Stage 2 §23).
"""
from __future__ import annotations

import uuid
from typing import Any, Mapping

from ..schema import CanonicalEvent
from ..timeutil import TimeParseError, format_utc, parse_utc
from .aws_cloudtrail import NormalizationError, _ID_NAMESPACE, _clean_str


def _get(rec: Mapping[str, Any], *names: str):
    for n in names:
        if n in rec and rec[n] not in (None, ""):
            return rec[n]
    return None


def normalize_record(record: Any, *, source_log_file: str, record_index: int,
                     evidence_hash: str) -> CanonicalEvent:
    if not isinstance(record, Mapping):
        raise NormalizationError("record is not a JSON object")
    ts = _get(record, "eventTimestamp", "EventTimestamp", "time")
    op = _get(record, "operationName", "OperationNameValue")
    if isinstance(op, Mapping):
        op = op.get("value")
    if not _clean_str(ts) or not _clean_str(op):
        raise NormalizationError("missing eventTimestamp/operationName")
    try:
        t = format_utc(parse_utc(ts))
    except TimeParseError as exc:
        raise NormalizationError(str(exc)) from exc
    ref = f"{source_log_file}#{record_index}"
    service = _get(record, "resourceProvider", "ResourceProvider") or op.split("/")[0]
    rtype = _get(record, "resultType", "ResultType")
    result = {"success": "success", "succeeded": "success", "failure": "failure", "failed": "failure"}.get(
        str(rtype).lower() if rtype else "", "unknown")
    return CanonicalEvent(
        event_id=_clean_str(_get(record, "eventDataId", "EventDataId", "correlationId", "CorrelationId"))
        or str(uuid.uuid5(_ID_NAMESPACE, ref)),
        event_time_utc=t, cloud_provider="azure", cloud_service=service, event_type="api_call",
        action=op, principal_id=_clean_str(_get(record, "caller", "Caller")) or "unknown",
        source_ip=_clean_str(_get(record, "callerIpAddress", "CallerIpAddress")),
        resource_id=_clean_str(_get(record, "resourceId", "ResourceId")), region=None, result=result,
        raw_event_ref=ref, source_log_file=source_log_file, evidence_hash=evidence_hash,
        provider_specific={k: record[k] for k in ("category", "level", "durationMs") if k in record},
    )
