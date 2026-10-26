#!/usr/bin/env bash
# Scenario B - suspicious S3 access pattern (Stage 2 §9 Scenario B).
# Prereqs: setup/02 (S3 data events), setup/03 (bucket + seeded objects), setup/04 (svc-reader).
#
# Real-world limitation (see aws/README.md): without a second network path, every CLI call below
# shares one sourceIPAddress, so the synthetic design's "burst from an unfamiliar IP" signal is not
# present here. Pass --alt-profile <profile-name> (a second AWS CLI profile reachable from a genuinely
# different network, e.g. a phone hotspot or a second machine) to restore that signal for the burst
# half of the scenario; otherwise it runs single-IP and says so in the ground truth notes.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../lib/common.sh" "$@"
require_preflight; require_cost_ack
GT_SCENARIO=scenario_b
source "$HERE/../lib/gt_logger.sh"

ALT_PROFILE=""
args=("$@")
for i in "${!args[@]}"; do
  [ "${args[$i]}" = "--alt-profile" ] && ALT_PROFILE="${args[$((i+1))]}"
done
BURST_PROFILE="${ALT_PROFILE:-svc-reader-temp}"
IP_NOTE="single sourceIPAddress (no --alt-profile given - see aws/README.md real-world limitation note)"
[ -n "$ALT_PROFILE" ] && IP_NOTE="burst half run via --alt-profile $ALT_PROFILE (genuinely different network, if you confirmed that)"

BUCKET_ARN="arn:aws:s3:::${SCENARIO_B_BUCKET}"
ACCT=$(account_id)
SVC_ARN="arn:aws:iam::${ACCT}:user/svc-reader"
SVC_KEY_FILE="$SCRATCH_DIR/svc_reader_access_key.json"

cleanup_svc_key() {
  if [ -f "$SVC_KEY_FILE" ] && [ "$DRY_RUN" != "1" ]; then
    local akid; akid=$(python3 -c "import json;print(json.load(open('$SVC_KEY_FILE'))['AccessKey']['AccessKeyId'])" 2>/dev/null || true)
    [ -n "$akid" ] && { echo "-- Deleting short-lived access key for svc-reader ($akid) --"; awscli iam delete-access-key --user-name svc-reader --access-key-id "$akid" || true; }
    shred -u "$SVC_KEY_FILE" 2>/dev/null || rm -f "$SVC_KEY_FILE"
  fi
}
trap cleanup_svc_key EXIT

echo "== Scenario B: suspicious S3 access pattern == ($IP_NOTE)"
confirm "PROCEED" "This performs real S3 GetObject/ListBuckets calls as svc-reader against $BUCKET_ARN."

if [ -z "$ALT_PROFILE" ] && [ "$DRY_RUN" != "1" ]; then
  echo "-- Creating short-lived access key for svc-reader (single-IP mode) --"
  awscli iam create-access-key --user-name svc-reader --output json > "$SVC_KEY_FILE"
  AKID=$(python3 -c "import json;print(json.load(open('$SVC_KEY_FILE'))['AccessKey']['AccessKeyId'])")
  ASEC=$(python3 -c "import json;print(json.load(open('$SVC_KEY_FILE'))['AccessKey']['SecretAccessKey'])")
  aws configure set aws_access_key_id "$AKID" --profile "$BURST_PROFILE"
  aws configure set aws_secret_access_key "$ASEC" --profile "$BURST_PROFILE"
  aws configure set region "$AWS_REGION" --profile "$BURST_PROFILE"
  unset ASEC
  echo "   temp profile '$BURST_PROFILE' configured (key id only: ${AKID:0:4}********)"
  sleep 10
fi
call_as_svc() { if [ "$DRY_RUN" = "1" ]; then echo "[dry-run] aws --profile $BURST_PROFILE $*"; else aws --profile "$BURST_PROFILE" --region "$AWS_REGION" "$@"; fi; }

echo "-- Step 1: baseline GetObject on the known/benign object --"
call_as_svc s3api get-object --bucket "$SCENARIO_B_BUCKET" --key "reports/q3.csv" "$SCRATCH_DIR/q3.csv" >/dev/null || true
log_step "GetObject" "$SVC_ARN" "NULL" "${BUCKET_ARN}/reports/q3.csv" "group_0" "false" "baseline_access" "known object, baseline"

echo "-- Step 2: ListBuckets (discovery) --"
call_as_svc s3api list-buckets >/dev/null || true
log_step "ListBuckets" "$SVC_ARN" "NULL" "NULL" "group_1" "true" "discovery" "$IP_NOTE"

echo "-- Steps 3-5: burst GetObject on secret/{a,b,c}.csv --"
for key in a b c; do
  call_as_svc s3api get-object --bucket "$SCENARIO_B_BUCKET" --key "secret/${key}.csv" "$SCRATCH_DIR/${key}.csv" >/dev/null || true
  stage="collection"; [ "$key" = "c" ] && stage="exfiltration"
  log_step "GetObject" "$SVC_ARN" "NULL" "${BUCKET_ARN}/secret/${key}.csv" "group_1" "true" "$stage" "burst access; $IP_NOTE"
  sleep 2
done

echo "-- Finalizing and freezing ground truth --"
python3 "$HERE/../lib/gt_finalize.py" --scenario scenario_b --jsonl "$GT_SCRATCH" \
  --groups '[{"group_id":"group_0","rationale":"known baseline access"},{"group_id":"group_1","rationale":"same principal, burst discovery+collection pattern"}]' \
  --out "$REPO_ROOT/data/real/ground_truth/scenario_b_ground_truth.json" --author "${USER:-researcher}"

echo
echo "Scenario B script complete. Next: aws/collection/05_export_evidence.sh scenario_b"
