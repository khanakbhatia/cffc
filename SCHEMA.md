# Canonical forensic-event schema - version 1.0

Implemented in `src/cffc/schema.py` (`CanonicalEvent`, `validate_event`). Every normalized record has exactly
these 16 fields. Stage 2 §13 defined 14; `schema_version` and `provider_specific` (Stage 2 §14) bring it to 16
(see `docs/ASSUMPTIONS.md` A1).

| # | Field | Type | Required | Meaning / rule |
|---|---|---|---|---|
| 1 | `event_id` | string | yes | Provider-native ID (CloudTrail `eventID`), else deterministic UUIDv5 of `raw_event_ref` |
| 2 | `event_time_utc` | string | yes | ISO-8601 UTC ending in `Z` (`2026-01-15T09:00:00Z`; up to 6 fractional digits). Naive timestamps are rejected |
| 3 | `cloud_provider` | enum | yes | `aws` \| `azure` \| `gcp` |
| 4 | `cloud_service` | string | yes | CloudTrail `eventSource` (e.g. `s3.amazonaws.com`) |
| 5 | `event_type` | enum | yes | `api_call` \| `console_login` \| `config_change` \| `network_flow` (CloudTrail normalizer emits the first two) |
| 6 | `action` | string | yes | CloudTrail `eventName` |
| 7 | `principal_id` | string | yes | `userIdentity.arn`, else `principalId`, else `userName`, else `invokedBy`, else the sentinel `unknown`. The values `Unknown` / `HIDDEN_DUE_TO_SECURITY_REASONS` are treated as absent |
| 8 | `source_ip` | string \| null | no | CloudTrail `sourceIPAddress` as delivered (may be a service name, which is never used as a correlation key) |
| 9 | `resource_id` | string \| null | no | First `resources[].ARN`; else `requestParameters.roleArn`; else `arn:aws:s3:::<bucketName>`; else first `responseElements.instancesSet` instance ID |
| 10 | `region` | string \| null | no | CloudTrail `awsRegion` |
| 11 | `result` | enum | yes | `failure` if `errorCode` present; for `ConsoleLogin` from `responseElements.ConsoleLogin` (`Success`/`Failure`, else `unknown`); otherwise `success` |
| 12 | `raw_event_ref` | string | yes | `<source_log_file>#<record index in file>` - pointer back to the exact raw record |
| 13 | `source_log_file` | string | yes | Path of the preserved raw file relative to `<data_root>/raw/` |
| 14 | `evidence_hash` | string | yes | SHA-256 (64 lowercase hex) of the raw file **as collected**, taken from the manifest |
| 15 | `schema_version` | string | yes | Always `"1.0"` here; bump on any schema change |
| 16 | `provider_specific` | object | yes | Forensic detail with no canonical slot (`requestParameters`, `responseElements`, `errorCode`, `errorMessage`, `resources`, `userAgent`, selected `userIdentity` attributes incl. `mfaAuthenticated`, ...). Never discarded |

**Populated** (for the schema-coverage metric) means not `null`, not an empty string/object/list. The `unknown`
sentinel counts as populated.

## Field mappings (Stage 2 §14)

| Canonical | AWS CloudTrail (implemented, tested on synthetic data) | Azure Activity Log (design-level) | GCP Audit Log (design-level) |
|---|---|---|---|
| `event_time_utc` | `eventTime` | `eventTimestamp` | `timestamp` |
| `cloud_service` | `eventSource` | `resourceProvider` / prefix of `operationName` | `protoPayload.serviceName` |
| `action` | `eventName` | `operationName` | `protoPayload.methodName` |
| `principal_id` | `userIdentity.arn`... | `caller` | `protoPayload.authenticationInfo.principalEmail` |
| `source_ip` | `sourceIPAddress` | `callerIpAddress` | `protoPayload.requestMetadata.callerIp` |
| `resource_id` | `resources[].ARN`... | `resourceId` | `protoPayload.resourceName` |
| `result` | `errorCode` presence | `resultType` | `protoPayload.status.code` |
| `event_id` | `eventID` | `eventDataId` / `correlationId` | `insertId` |

Azure and GCP normalizers (`src/cffc/normalizers/azure_activity.py`, `gcp_audit.py`) exist only to check that the
schema can structurally represent those records (RQ1). They are tested on a few hand-written synthetic records and
**have not been validated against live Azure/GCP data**. Cross-provider identity resolution is out of scope.

## Validation rules (`validate_event`)

Required fields present and non-empty; no unexpected fields; enums respected; `event_time_utc` matches
`YYYY-MM-DDTHH:MM:SS[.ffffff]Z` and parses; `evidence_hash` matches `^[a-f0-9]{64}$`; `raw_event_ref` matches
`<file>#<int>`; `schema_version == "1.0"`; `provider_specific` is an object. Records failing normalization or
validation are **reported** (`normalization_failures.json`), never silently dropped.
