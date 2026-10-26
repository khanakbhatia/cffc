#!/usr/bin/env bash
# Preservation bucket for CloudTrail delivery (Stage 2 §7/§12), plus the scenario-B data bucket.
# Object Lock must be requested AT BUCKET CREATION and cannot be retrofitted - this script tries it
# and falls back to versioning + a deny-delete bucket policy if Object Lock is unavailable on this
# account/tier. [VERIFY AT RUNTIME] Object Lock availability on your account tier is something the
# AWS Console/CLI will tell you authoritatively at creation time; Stage 1/3 flagged this as
# unverified against free-tier constraints and this script does not assert an answer either way.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../lib/common.sh" "$@"
require_preflight; require_cost_ack

make_bucket() {
  local bucket="$1" try_object_lock="$2"
  if awscli_read s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
    echo "s3://$bucket already exists - leaving it as-is."
    return 0
  fi
  echo "-- Creating s3://$bucket (object-lock attempt: $try_object_lock) --"
  local extra=()
  [ "$AWS_REGION" != "us-east-1" ] && extra+=(--create-bucket-configuration "LocationConstraint=$AWS_REGION")
  if [ "$try_object_lock" = "1" ]; then
    if awscli s3api create-bucket --bucket "$bucket" --object-lock-enabled-for-bucket "${extra[@]}"; then
      awscli s3api put-object-lock-configuration --bucket "$bucket" --object-lock-configuration \
        '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"GOVERNANCE","Days":30}}}'
      echo "Object Lock enabled (GOVERNANCE, 30 days default retention)."
      awscli s3api put-bucket-tagging --bucket "$bucket" --tagging "TagSet=[{Key=Project,Value=$PROJECT_TAG}]"
      return 0
    fi
    echo "Object Lock creation failed/unsupported here - falling back to versioning + deny-delete policy." >&2
  fi
  awscli s3api create-bucket --bucket "$bucket" "${extra[@]}"
  awscli s3api put-bucket-versioning --bucket "$bucket" --versioning-configuration Status=Enabled
  cat > "$SCRATCH_DIR/${bucket}_deny_delete.json" <<JSON
{"Version":"2012-10-17","Statement":[{"Sid":"DenyObjectDeletion","Effect":"Deny",
  "Principal":"*","Action":["s3:DeleteObject","s3:DeleteObjectVersion"],
  "Resource":"arn:aws:s3:::${bucket}/*",
  "Condition":{"StringNotEquals":{"aws:PrincipalArn":"$(account_id | sed 's/.*/arn:aws:iam::&:root/')"}}}]}
JSON
  awscli s3api put-bucket-policy --bucket "$bucket" --policy "file://$SCRATCH_DIR/${bucket}_deny_delete.json"
  awscli s3api put-bucket-tagging --bucket "$bucket" --tagging "TagSet=[{Key=Project,Value=$PROJECT_TAG}]"
  echo "Versioning + deny-delete policy applied (Object Lock not used for this bucket)."
}

awscli s3api put-public-access-block --bucket "$PRESERVATION_BUCKET" --public-access-block-configuration \
  'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true' 2>/dev/null || true
make_bucket "$PRESERVATION_BUCKET" 1

make_bucket "$SCENARIO_B_BUCKET" 0
awscli s3api put-public-access-block --bucket "$SCENARIO_B_BUCKET" --public-access-block-configuration \
  'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true' 2>/dev/null || true

# Seed scenario B's objects now (Stage 2 §9 Scenario B: a baseline object + three "secret" objects)
for key in "reports/q3.csv" "secret/a.csv" "secret/b.csv" "secret/c.csv"; do
  if [ "$DRY_RUN" = "1" ]; then
    echo "[dry-run] aws s3api put-object --bucket $SCENARIO_B_BUCKET --key $key --body <placeholder>"
  else
    tmp="$SCRATCH_DIR/seed.csv"; echo "col_a,col_b
1,2" > "$tmp"
    awscli s3api put-object --bucket "$SCENARIO_B_BUCKET" --key "$key" --body "$tmp" >/dev/null
  fi
done
echo "Seeded $SCENARIO_B_BUCKET with reports/q3.csv and secret/{a,b,c}.csv."
echo
echo "[VERIFY AT RUNTIME] Confirm bucket policies/public-access-block in the S3 console match the"
echo "intent above before running any scenario - a misconfigured bucket could affect result validity."
