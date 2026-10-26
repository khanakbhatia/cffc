#!/usr/bin/env bash
# Safety gate. Run this first, always. Confirms identity/region, warns about cost, and sets
# CFFC_PREFLIGHT_OK=yes in config.env only after you explicitly confirm. Nothing billable happens here.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../lib/common.sh" "$@"

echo "== Preflight checks =="
echo "Profile: $AWS_PROFILE    Region: $AWS_REGION    Project tag: $PROJECT_TAG"

echo "-- Checking the profile is configured and reachable (read-only call: sts:GetCallerIdentity) --"
if ! IDENTITY_JSON=$(awscli_read sts get-caller-identity --output json 2>&1); then
  echo "ERROR: could not call sts get-caller-identity with profile '$AWS_PROFILE'." >&2
  echo "       Run 'aws configure --profile $AWS_PROFILE' yourself first (this script never asks for keys)." >&2
  echo "$IDENTITY_JSON" >&2
  exit 1
fi
echo "$IDENTITY_JSON"
ACCT=$(echo "$IDENTITY_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["Account"])')
ARN=$(echo "$IDENTITY_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["Arn"])')

echo
echo "-- Checking for leftover resources tagged Project=$PROJECT_TAG from a previous run --"
EXISTING=$(awscli_read resourcegroupstaggingapi get-resources \
  --tag-filters "Key=Project,Values=$PROJECT_TAG" --query 'ResourceTagMappingList[].ResourceARN' \
  --output text 2>/dev/null || true)
if [ -n "${EXISTING:-}" ]; then
  echo "WARNING: resources already tagged Project=$PROJECT_TAG exist:" >&2
  echo "$EXISTING" | tr '\t' '\n' >&2
  echo "Consider running aws/collection/08_cleanup.sh before a fresh collection run." >&2
fi

echo
echo "== You are about to run AWS setup/scenario scripts against: =="
echo "   Account: $ACCT"
echo "   Identity: $ARN"
echo "   Region:  $AWS_REGION"
echo "This account WILL be charged a small amount (see docs/COST_NOTES.md): CloudTrail S3 data-event"
echo "logging, a handful of S3 PUT/GET requests, and one short-lived t3.micro EC2 instance."
echo
confirm "PROCEED" "Only confirm if this is the correct, non-production AWS account for this research project."

echo
echo "-- Cost acknowledgment --"
if [ "${CFFC_ACK_COSTS:-no}" != "yes" ]; then
  echo "CFFC_ACK_COSTS is not 'yes' in aws/config.env. Read docs/COST_NOTES.md, then set it yourself." >&2
  echo "(Not auto-set here on purpose - it should be a deliberate edit, not a side effect of this script.)" >&2
  exit 1
fi
echo "Cost acknowledgment: OK (CFFC_ACK_COSTS=yes)"

if [ "$DRY_RUN" = "1" ]; then
  echo "[dry-run] would set CFFC_PREFLIGHT_OK=yes in $CONFIG_FILE"
else
  python3 - "$CONFIG_FILE" <<'PYEOF'
import sys, re
path = sys.argv[1]
text = open(path).read()
if re.search(r"^CFFC_PREFLIGHT_OK=", text, re.M):
    text = re.sub(r"^CFFC_PREFLIGHT_OK=.*$", "CFFC_PREFLIGHT_OK=yes", text, flags=re.M)
else:
    text += "\nCFFC_PREFLIGHT_OK=yes\n"
open(path, "w").write(text)
PYEOF
  echo "Preflight OK. CFFC_PREFLIGHT_OK=yes written to $CONFIG_FILE."
fi
