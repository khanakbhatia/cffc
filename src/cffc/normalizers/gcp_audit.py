"""GCP Cloud Audit Log -> CanonicalEvent.  DESIGN-LEVEL ONLY (see azure_activity.py note)."""
from __future__ import annotations

import uuid
from typing import Any, Mapping

from ..schema import CanonicalEvent
from ..timeutil import TimeParseError, format_utc, parse_utc
from .aws_cloudtrail import NormalizationError, _ID_NAMESPACE, _clean_str


def normalize_record(record: Any, *, source_log_file: str, record_index: int,
                     evidence_hash: str) -> CanonicalEvent:
    if not isinstance(record, Mapping):
        raise NormalizationError("record is not a JSON object")
    pp = record.get("protoPayload")
    if not isinstance(pp, Mapping):
        raise NormalizationError("missing protoPayload")
    method, ts = _clean_str(pp.get("methodName")), _clean_str(record.get("timestamp"))
    if not method or not ts:
        raise NormalizationError("missing methodName/timestamp")
    try:
        t = format_utc(parse_utc(ts))
    except TimeParseError as exc:
        raise NormalizationError(str(exc)) from exc
    ref = f"{source_log_file}#{record_index}"
    status = pp.get("status")
    code = status.get("code", 0) if isinstance(status, Mapping) else 0
    return CanonicalEvent(
        event_id=_clean_str(record.get("insertId")) or str(uuid.uuid5(_ID_NAMESPACE, ref)),
        event_time_utc=t, cloud_provider="gcp",
        cloud_service=_clean_str(pp.get("serviceName")) or "unknown", event_type="api_call", action=method,
        principal_id=_clean_str((pp.get("authenticationInfo") or {}).get("principalEmail")) or "unknown",
        source_ip=_clean_str((pp.get("requestMetadata") or {}).get("callerIp")),
        resource_id=_clean_str(pp.get("resourceName")), region=None,
        result="success" if code == 0 else "failure",
        raw_event_ref=ref, source_log_file=source_log_file, evidence_hash=evidence_hash,
        provider_specific={"authorizationInfo": pp["authorizationInfo"]} if "authorizationInfo" in pp else {},
    )
