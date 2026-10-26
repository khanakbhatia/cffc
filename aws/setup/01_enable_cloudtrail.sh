#!/usr/bin/env bash
# Multi-region CloudTrail trail with log file validation (Stage 2 §11 step 1). Management events only
# here; S3 data events are enabled separately and narrowly in 02_s3_data_events.sh.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../lib/common.sh" "$@"
require_preflight; require_cost_ack

ACCT=$(account_id)
BUCKET="${PRESERVATION_BUCKET}"
echo "== Enabling CloudTrail trail '$TRAIL_NAME' (multi-region, log file validation) =="
echo "   Delivery bucket: s3://$BUCKET  (must already exist - run 03_preservation_bucket.sh first)"

if ! awscli_read s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1 && [ "$DRY_RUN" != "1" ]; then
  echo "ERROR: s3://$BUCKET does not exist yet. Run aws/setup/03_preservation_bucket.sh first." >&2
  exit 1
fi

awscli cloudtrail create-trail \
  --name "$TRAIL_NAME" \
  --s3-bucket-name "$BUCKET" \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --tags-list "Key=Project,Value=$PROJECT_TAG"

awscli cloudtrail start-logging --name "$TRAIL_NAME"

echo "-- Verifying trail status (read-only) --"
awscli_read cloudtrail get-trail-status --name "$TRAIL_NAME" || true
echo
echo "[VERIFY AT RUNTIME] Confirm in the CloudTrail console that the trail shows 'Logging: On' and that"
echo "the delivery bucket matches. CloudTrail's own hourly digest-file / log-file-validation feature"
echo "(docs/MANUAL_AWS_STEPS.md item 7) depends on this trail actually being active before any scenario runs."
