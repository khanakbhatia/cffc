#!/usr/bin/env bash
# Creates the four scenario principals (see aws/iam/lowpriv-user-policy-notes.md), all tagged
# Project=$PROJECT_TAG so 08_cleanup.sh can find and remove exactly these and nothing else.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../lib/common.sh" "$@"
require_preflight; require_cost_ack

ACCT=$(account_id)
TAGS="Key=Project,Value=$PROJECT_TAG"

create_user() {
  local name="$1"
  if awscli_read iam get-user --user-name "$name" >/dev/null 2>&1; then
    echo "iam user $name already exists - leaving it as-is."; return 0
  fi
  awscli iam create-user --user-name "$name" --tags "$TAGS"
}

echo "== lowpriv-user (ReadOnlyAccess only) =="
create_user lowpriv-user
awscli iam attach-user-policy --user-name lowpriv-user \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

echo "== svc-reader (S3 read-only on the scenario-B bucket only) =="
create_user svc-reader
cat > "$SCRATCH_DIR/svc_reader_policy.json" <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":["s3:GetObject","s3:ListBucket"],
  "Resource":["arn:aws:s3:::${SCENARIO_B_BUCKET}","arn:aws:s3:::${SCENARIO_B_BUCKET}/*"]}]}
JSON
awscli iam put-user-policy --user-name svc-reader --policy-name scenario-b-read-only \
  --policy-document "file://$SCRATCH_DIR/svc_reader_policy.json"

echo "== analyst-bob (console login + ReadOnlyAccess + EC2) =="
create_user analyst-bob
awscli iam attach-user-policy --user-name analyst-bob --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
awscli iam attach-user-policy --user-name analyst-bob --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
BOB_PW="$SCRATCH_DIR/analyst_bob_console_password.txt"
if [ "$DRY_RUN" != "1" ] && ! awscli_read iam get-login-profile --user-name analyst-bob >/dev/null 2>&1; then
  PW="$(python3 -c 'import secrets,string;a=string.ascii_letters+string.digits+"!@#%^&*";print("".join(secrets.choice(a) for _ in range(20)))')"
  awscli iam create-login-profile --user-name analyst-bob --password "$PW" --password-reset-required
  umask 177; echo "$PW" > "$BOB_PW"
  echo "Console password for analyst-bob written to $BOB_PW (local, gitignored, NOT printed here)."
  echo "You need it for the manual Scenario C browser steps - read the file yourself when ready."
fi

echo "== admin-role (AdministratorAccess, trust restricted to this account) =="
sed "s/ACCOUNT_ID/$ACCT/" "$HERE/../iam/admin-role-trust-policy.json" > "$SCRATCH_DIR/admin_role_trust.json"
if ! awscli_read iam get-role --role-name admin-role >/dev/null 2>&1; then
  awscli iam create-role --role-name admin-role --assume-role-policy-document "file://$SCRATCH_DIR/admin_role_trust.json" --tags "$TAGS"
  awscli iam attach-role-policy --role-name admin-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
else
  echo "iam role admin-role already exists - leaving it as-is."
fi

echo
echo "All four principals created/verified. None was granted more than its scenario script needs"
echo "(aws/iam/lowpriv-user-policy-notes.md documents why each denial in Scenario A is real, not staged)."
