#!/usr/bin/env bash
# S3 DATA events (object-level GetObject/PutObject) on the Scenario-B bucket ONLY (Stage 2 §8/§11
# step 2). Deliberately NOT account-wide: data events are billed per event and voluminous.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../lib/common.sh" "$@"
require_preflight; require_cost_ack

BUCKET_ARN="arn:aws:s3:::${SCENARIO_B_BUCKET}"
echo "== Enabling S3 data-event logging for $BUCKET_ARN only (trail: $TRAIL_NAME) =="
if ! awscli_read s3api head-bucket --bucket "$SCENARIO_B_BUCKET" >/dev/null 2>&1 && [ "$DRY_RUN" != "1" ]; then
  echo "ERROR: s3://$SCENARIO_B_BUCKET does not exist yet. Create it (see docs/MANUAL_AWS_STEPS.md" >&2
  echo "       item 3, or add it to 03_preservation_bucket.sh's pattern) before enabling data events." >&2
  exit 1
fi

# IMPORTANT: put-event-selectors REPLACES a trail's entire selector set in one call - it does not
# merge with whatever CloudTrail defaulted to. So this one selector must explicitly keep management
# events ON (IncludeManagementEvents: true) as well as adding the narrow S3 data-event scope;
# otherwise this call would silently turn OFF the management-event logging Scenarios A/C depend on.
cat > "$SCRATCH_DIR/event_selectors.json" <<JSON
[
  {
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [
      {"Type": "AWS::S3::Object", "Values": ["${BUCKET_ARN}/"]}
    ]
  }
]
JSON

awscli cloudtrail put-event-selectors --trail-name "$TRAIL_NAME" \
  --event-selectors "file://$SCRATCH_DIR/event_selectors.json"

echo "-- Verifying event selectors (read-only) --"
awscli_read cloudtrail get-event-selectors --trail-name "$TRAIL_NAME" || true
echo
echo "NOTE: this call REPLACES the trail's entire selector set with the one above - management events"
echo "      (IncludeManagementEvents: true) are kept on in the same call, specifically so this script"
echo "      does not silently disable Scenario A/C's management-event logging while adding S3 data events."
echo "[VERIFY AT RUNTIME] Confirm the AWS Billing console shows data-event pricing before Scenario B,"
echo "      not after - see docs/COST_NOTES.md."
