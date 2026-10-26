"""AWS CloudTrail record -> CanonicalEvent (Stage 2 §14 field mapping)."""
from __future__ import annotations

import uuid
from typing import Any, Dict, Mapping, Optional

from ..schema import CanonicalEvent, SCHEMA_VERSION, UNKNOWN
from ..timeutil import TimeParseError, format_utc, parse_utc

_ID_NAMESPACE = uuid.UUID("6f1d5a2e-0c1b-4c55-9d7e-3b6a1c0f0a11")
_PRINCIPAL_SENTINELS = {"unknown", "hidden_due_to_security_reasons", ""}


class NormalizationError(ValueError):
    """A raw record cannot be mapped to the canonical schema (reported, never silently dropped)."""


def _principal(user_identity: Any) -> str:
    if not isinstance(user_identity, Mapping):
        return UNKNOWN
    for key in ("arn", "principalId", "userName", "invokedBy"):
        v = user_identity.get(key)
        if isinstance(v, str) and v.strip().lower() not in _PRINCIPAL_SENTINELS:
            return v.strip()
    return UNKNOWN


def _result(rec: Mapping[str, Any]) -> str:
    if rec.get("errorCode"):
        return "failure"
    if rec.get("eventName") == "ConsoleLogin":
        resp = rec.get("responseElements")
        status = resp.get("ConsoleLogin") if isinstance(resp, Mapping) else None
        return {"Success": "success", "Failure": "failure"}.get(status, "unknown")
    return "success"


def _resource(rec: Mapping[str, Any]) -> Optional[str]:
    res = rec.get("resources")
    if isinstance(res, list):
        for r in res:
            if isinstance(r, Mapping) and isinstance(r.get("ARN"), str) and r["ARN"].strip():
                return r["ARN"].strip()
    params = rec.get("requestParameters")
    if isinstance(params, Mapping):
        if isinstance(params.get("roleArn"), str):
            return params["roleArn"]
        if isinstance(params.get("bucketName"), str):
            return f"arn:aws:s3:::{params['bucketName']}"
    resp = rec.get("responseElements")
    if isinstance(resp, Mapping):
        items = (resp.get("instancesSet") or {}).get("items") if isinstance(resp.get("instancesSet"), Mapping) else None
        if isinstance(items, list) and items and isinstance(items[0], Mapping):
            iid = items[0].get("instanceId")
            if isinstance(iid, str):
                return iid
    return None


def _clean_str(v: Any) -> Optional[str]:
    return v.strip() if isinstance(v, str) and v.strip() else None


def normalize_record(record: Any, *, source_log_file: str, record_index: int,
                     evidence_hash: str) -> CanonicalEvent:
    if not isinstance(record, Mapping):
        raise NormalizationError(f"record is not a JSON object (got {type(record).__name__})")
    for key in ("eventTime", "eventName", "eventSource"):
        if not _clean_str(record.get(key)):
            raise NormalizationError(f"missing/empty required CloudTrail field: {key}")
    try:
        t = format_utc(parse_utc(record["eventTime"]))
    except TimeParseError as exc:
        raise NormalizationError(f"bad eventTime: {exc}") from exc

    ref = f"{source_log_file}#{record_index}"
    event_id = _clean_str(record.get("eventID")) or str(uuid.uuid5(_ID_NAMESPACE, ref))
    is_login = record.get("eventType") == "AwsConsoleSignIn" or record["eventName"] == "ConsoleLogin"

    ui = record.get("userIdentity") if isinstance(record.get("userIdentity"), Mapping) else {}
    ps: Dict[str, Any] = {}
    for k in ("eventVersion", "eventType", "readOnly", "managementEvent", "requestID",
              "recipientAccountId", "userAgent", "errorCode", "errorMessage",
              "requestParameters", "responseElements", "resources"):
        if record.get(k) is not None:
            ps[k] = record[k]
    ui_keep = {k: ui[k] for k in ("type", "accountId", "userName", "accessKeyId") if k in ui}
    mfa = ((ui.get("sessionContext") or {}).get("attributes") or {}).get("mfaAuthenticated") \
        if isinstance(ui.get("sessionContext"), Mapping) else None
    if mfa is not None:
        ui_keep["mfaAuthenticated"] = mfa
    if ui_keep:
        ps["userIdentity"] = ui_keep

    return CanonicalEvent(
        event_id=event_id,
        event_time_utc=t,
        cloud_provider="aws",
        cloud_service=record["eventSource"].strip(),
        event_type="console_login" if is_login else "api_call",
        action=record["eventName"].strip(),
        principal_id=_principal(ui),
        source_ip=_clean_str(record.get("sourceIPAddress")),
        resource_id=_resource(record),
        region=_clean_str(record.get("awsRegion")),
        result=_result(record),
        raw_event_ref=ref,
        source_log_file=source_log_file,
        evidence_hash=evidence_hash,
        schema_version=SCHEMA_VERSION,
        provider_specific=ps,
    )
