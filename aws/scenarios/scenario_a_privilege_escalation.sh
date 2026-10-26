#!/usr/bin/env bash
# Scenario A - unauthorized IAM privilege escalation attempt (Stage 2 §9 Scenario A).
# Prereqs: setup/01, setup/04 already run (trail logging, lowpriv-user + admin-role exist).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../lib/common.sh" "$@"
require_preflight; require_cost_ack
GT_SCENARIO=scenario_a
source "$HERE/../lib/gt_logger.sh"

ACCT=$(account_id)
ADMIN_ARN=$(caller_arn)
LOWPRIV_ARN="arn:aws:iam::${ACCT}:user/lowpriv-user"
ROLE_ARN="arn:aws:iam::${ACCT}:role/admin-role"
LOWPRIV_KEY_FILE="$SCRATCH_DIR/lowpriv_user_access_key.json"
LOWPRIV_PROFILE="cffc-lowpriv-temp"

cleanup_lowpriv_key() {
  if [ -f "$LOWPRIV_KEY_FILE" ] && [ "$DRY_RUN" != "1" ]; then
    local akid; akid=$(python3 -c "import json;print(json.load(open('$LOWPRIV_KEY_FILE'))['AccessKey']['AccessKeyId'])" 2>/dev/null || true)
    if [ -n "$akid" ]; then
      echo "-- Deleting short-lived access key for lowpriv-user ($akid) --"
      awscli iam delete-access-key --user-name lowpriv-user --access-key-id "$akid" || true
    fi
    shred -u "$LOWPRIV_KEY_FILE" 2>/dev/null || rm -f "$LOWPRIV_KEY_FILE"
  fi
}
trap cleanup_lowpriv_key EXIT

echo "== Scenario A: privilege escalation attempt =="
confirm "PROCEED" "This performs real, denied IAM calls against principal $LOWPRIV_ARN. Read-only otherwise."

echo "-- Step 1: CreateUser lowpriv-user (as operator $ADMIN_ARN; benign setup) --"
echo "   (lowpriv-user is normally created by setup/04_least_privilege_iam.sh - this call is idempotent"
echo "    and only logged here if the user did not already exist, matching ground truth step 1's intent.)"
if ! awscli_read iam get-user --user-name lowpriv-user >/dev/null 2>&1; then
  awscli iam create-user --user-name lowpriv-user --tags "Key=Project,Value=$PROJECT_TAG"
  awscli iam attach-user-policy --user-name lowpriv-user --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
fi
log_step "CreateUser" "$ADMIN_ARN" "NULL" "NULL" "group_0" "false" "setup" "operator creates lowpriv-user (idempotent)"

echo "-- Creating a short-lived access key for lowpriv-user so the next two calls are logged AS that principal --"
if [ "$DRY_RUN" = "1" ]; then
  echo "[dry-run] aws iam create-access-key --user-name lowpriv-user"
else
  awscli iam create-access-key --user-name lowpriv-user --output json > "$LOWPRIV_KEY_FILE"
  AKID=$(python3 -c "import json;print(json.load(open('$LOWPRIV_KEY_FILE'))['AccessKey']['AccessKeyId'])")
  ASEC=$(python3 -c "import json;print(json.load(open('$LOWPRIV_KEY_FILE'))['AccessKey']['SecretAccessKey'])")
  aws configure set aws_access_key_id "$AKID" --profile "$LOWPRIV_PROFILE"
  aws configure set aws_secret_access_key "$ASEC" --profile "$LOWPRIV_PROFILE"
  aws configure set region "$AWS_REGION" --profile "$LOWPRIV_PROFILE"
  unset ASEC
  echo "   temp profile '$LOWPRIV_PROFILE' configured (key id only, never printed: ${AKID:0:4}********)"
  echo "   waiting 10s for IAM credential propagation..."; sleep 10
fi

echo "-- Step 2: AttachUserPolicy AdministratorAccess, run AS lowpriv-user (expect AccessDenied) --"
if [ "$DRY_RUN" = "1" ]; then
  echo "[dry-run] aws --profile $LOWPRIV_PROFILE iam attach-user-policy --user-name lowpriv-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
else
  set +e
  OUT=$(aws --profile "$LOWPRIV_PROFILE" --region "$AWS_REGION" iam attach-user-policy \
        --user-name lowpriv-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>&1)
  RC=$?
  set -e
  echo "$OUT"
  if [ $RC -eq 0 ]; then
    echo "WARNING: AttachUserPolicy SUCCEEDED - lowpriv-user is not actually least-privilege." >&2
    echo "         Check aws/iam/lowpriv-user-policy-notes.md and your IAM setup before continuing." >&2
  else
    echo "Denied as expected (RC=$RC)."
  fi
fi
log_step "AttachUserPolicy" "$LOWPRIV_ARN" "NULL" "NULL" "group_1" "true" "privilege_escalation" "expect AccessDenied - no iam:AttachUserPolicy permission"

echo "-- Step 3: AssumeRole admin-role, AS lowpriv-user (expect AccessDenied) --"
if [ "$DRY_RUN" = "1" ]; then
  echo "[dry-run] aws --profile $LOWPRIV_PROFILE sts assume-role --role-arn $ROLE_ARN --role-session-name x"
else
  set +e
  OUT=$(aws --profile "$LOWPRIV_PROFILE" --region "$AWS_REGION" sts assume-role \
        --role-arn "$ROLE_ARN" --role-session-name "scenario-a-attempt" 2>&1)
  RC=$?
  set -e
  echo "$OUT"
  [ $RC -ne 0 ] && echo "Denied as expected (RC=$RC)." || echo "WARNING: AssumeRole SUCCEEDED unexpectedly." >&2
fi
log_step "AssumeRole" "$LOWPRIV_ARN" "NULL" "$ROLE_ARN" "group_1" "true" "privilege_escalation" "expect AccessDenied - admin-role trust policy does not grant lowpriv-user"

echo "-- Step 4: GetCallerIdentity AS lowpriv-user (succeeds; discovery) --"
if [ "$DRY_RUN" = "1" ]; then
  echo "[dry-run] aws --profile $LOWPRIV_PROFILE sts get-caller-identity"
else
  aws --profile "$LOWPRIV_PROFILE" --region "$AWS_REGION" sts get-caller-identity
fi
log_step "GetCallerIdentity" "$LOWPRIV_ARN" "NULL" "NULL" "group_1" "true" "discovery" "succeeds - confirms identity after denied escalation attempts"

echo "-- Finalizing and freezing ground truth --"
python3 "$HERE/../lib/gt_finalize.py" --scenario scenario_a --jsonl "$GT_SCRATCH" \
  --groups '[{"group_id":"group_0","rationale":"benign setup action"},{"group_id":"group_1","rationale":"same principal (lowpriv-user) across steps 2-4"}]' \
  --out "$REPO_ROOT/data/real/ground_truth/scenario_a_ground_truth.json" --author "${USER:-researcher}"

echo
echo "Scenario A script complete. The lowpriv-user access key is being deleted now (trap). Next:"
echo "  aws/collection/05_export_evidence.sh scenario_a"
