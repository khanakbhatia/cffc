#!/usr/bin/env bash
# Export raw CloudTrail files for one scenario's time window into data/real/raw/<scenario>/,
# preserving CloudTrail's original filenames exactly (Stage 2 §11 step 4 - never rename/re-serialize
# before hashing). Waits for CloudTrail's typical 5-15 minute delivery latency (Stage 2 §10 step 3).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../lib/common.sh" "$@"
require_preflight

SCENARIO="${1:-}"
[[ "$SCENARIO" =~ ^scenario_[abc]$ ]] || { echo "usage: $0 <scenario_a|scenario_b|scenario_c> [--dry-run]" >&2; exit 1; }
GT_FILE="$REPO_ROOT/data/real/ground_truth/${SCENARIO}_ground_truth.json"
[ -f "$GT_FILE" ] || { echo "ERROR: $GT_FILE not found - run the scenario script first." >&2; exit 1; }

START_UTC=$(python3 -c "import json;d=json.load(open('$GT_FILE'));print(d['steps'][0]['wall_clock_time_utc'])")
DATE_PREFIX=$(python3 -c "print('$START_UTC'[:10].replace('-',''))")
ACCT=$(account_id)
S3_PREFIX="AWSLogs/${ACCT}/CloudTrail/${AWS_REGION}/${DATE_PREFIX:0:4}/${DATE_PREFIX:4:2}/${DATE_PREFIX:6:2}/"
DEST="$REPO_ROOT/data/real/raw/${SCENARIO}"
mkdir -p "$DEST"

echo "== Exporting evidence for $SCENARIO =="
echo "   scenario started $START_UTC UTC; delivery bucket prefix: s3://$PRESERVATION_BUCKET/$S3_PREFIX"
echo "-- Waiting for CloudTrail delivery latency (typically 5-15 minutes; Stage 2 §10) --"
if [ "$DRY_RUN" = "1" ]; then
  echo "[dry-run] would wait, then list+copy objects under that prefix with LastModified >= $START_UTC"
else
  echo "   Polling every 60s, up to 20 minutes, for at least one object under that prefix..."
  for i in $(seq 1 20); do
    COUNT=$(awscli_read s3api list-objects-v2 --bucket "$PRESERVATION_BUCKET" --prefix "$S3_PREFIX" \
            --query 'length(Contents[])' --output text 2>/dev/null || echo 0)
    [ "$COUNT" != "None" ] && [ "${COUNT:-0}" -gt 0 ] && { echo "   found $COUNT object(s) after ${i}m."; break; }
    echo "   [$i/20] not yet delivered, waiting 60s..."; sleep 60
  done
fi

echo "-- Listing objects under the prefix and filtering by LastModified >= scenario start --"
if [ "$DRY_RUN" = "1" ]; then
  echo "[dry-run] aws s3api list-objects-v2 --bucket $PRESERVATION_BUCKET --prefix $S3_PREFIX --query \"Contents[?LastModified >= \\\`$START_UTC\\\`].Key\""
  echo "[]" > "$SCRATCH_DIR/${SCENARIO}_keys.json"
else
  awscli_read s3api list-objects-v2 --bucket "$PRESERVATION_BUCKET" --prefix "$S3_PREFIX" \
    --query "Contents[?LastModified >= \`$START_UTC\`].Key" --output json > "$SCRATCH_DIR/${SCENARIO}_keys.json" \
    || echo "[]" > "$SCRATCH_DIR/${SCENARIO}_keys.json"
fi
N=$(python3 -c "import json;print(len(json.load(open('$SCRATCH_DIR/${SCENARIO}_keys.json'))))")
echo "   $N candidate object(s)."
if [ "$N" = "0" ] && [ "$DRY_RUN" != "1" ]; then
  echo "WARNING: no CloudTrail files found yet for this window. CloudTrail delivery can occasionally" >&2
  echo "         take longer than 20 minutes - re-run this script later; it is safe to re-run (it only" >&2
  echo "         copies, never deletes, and preserves filenames so re-copies are idempotent)." >&2
fi

python3 - "$SCRATCH_DIR/${SCENARIO}_keys.json" <<'PYEOF'
import json, sys
keys = json.load(open(sys.argv[1]))
for k in keys:
    print(k)
PYEOF
while IFS= read -r key; do
  [ -z "$key" ] && continue
  fname=$(basename "$key")
  if [ "$DRY_RUN" = "1" ]; then
    echo "[dry-run] aws s3 cp s3://$PRESERVATION_BUCKET/$key $DEST/$fname"
  else
    awscli s3 cp "s3://$PRESERVATION_BUCKET/$key" "$DEST/$fname"
  fi
done < <(python3 -c "import json;[print(k) for k in json.load(open('$SCRATCH_DIR/${SCENARIO}_keys.json'))]")

echo
echo "Export complete. Files preserved under $DEST with their original CloudTrail names."
echo "Next: aws/collection/06_hash_and_manifest.sh $SCENARIO"
