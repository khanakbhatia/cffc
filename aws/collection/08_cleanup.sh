#!/usr/bin/env bash
# Tear-down, scoped ONLY to resources tagged Project=$PROJECT_TAG (so it cannot touch anything else
# in the account). Nothing here runs without you typing DELETE. Preservation bucket contents are
# kept by default (pass --delete-preservation-bucket to also remove them - a second, separate
# confirmation is required for that, since it is your actual collected evidence).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../lib/common.sh" "$@"

DELETE_PRESERVATION=0
for a in "$@"; do [ "$a" = "--delete-preservation-bucket" ] && DELETE_PRESERVATION=1; done

echo "== Cleanup: tearing down resources tagged Project=$PROJECT_TAG =="
echo "-- Resources currently tagged Project=$PROJECT_TAG (read-only lookup) --"
awscli_read resourcegroupstaggingapi get-resources --tag-filters "Key=Project,Values=$PROJECT_TAG" \
  --query 'ResourceTagMappingList[].ResourceARN' --output table || true

confirm "DELETE" "This will delete the IAM users/role/access-keys, the scenario-B bucket's objects and bucket, and stop/delete the CloudTrail trail created by this package. Type DELETE to proceed."

echo "-- EC2: terminating any instance tagged Project=$PROJECT_TAG that is still running --"
IDS=$(awscli_read ec2 describe-instances --filters "Name=tag:Project,Values=$PROJECT_TAG" \
  "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null || true)
[ -n "${IDS:-}" ] && awscli ec2 terminate-instances --instance-ids $IDS || echo "   none found."

echo "-- IAM: deleting access keys, login profiles, policies, and the four scenario principals --"
for user in lowpriv-user svc-reader analyst-bob; do
  if awscli_read iam get-user --user-name "$user" >/dev/null 2>&1; then
    for akid in $(awscli_read iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
      awscli iam delete-access-key --user-name "$user" --access-key-id "$akid" || true
    done
    awscli iam delete-login-profile --user-name "$user" 2>/dev/null || true
    for pol in $(awscli_read iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[].PolicyArn' --output text); do
      awscli iam detach-user-policy --user-name "$user" --policy-arn "$pol" || true
    done
    for pol in $(awscli_read iam list-user-policies --user-name "$user" --query 'PolicyNames[]' --output text); do
      awscli iam delete-user-policy --user-name "$user" --policy-name "$pol" || true
    done
    awscli iam delete-user --user-name "$user" || true
    echo "   deleted $user"
  fi
done
if awscli_read iam get-role --role-name admin-role >/dev/null 2>&1; then
  for pol in $(awscli_read iam list-attached-role-policies --role-name admin-role --query 'AttachedPolicies[].PolicyArn' --output text); do
    awscli iam detach-role-policy --role-name admin-role --policy-arn "$pol" || true
  done
  awscli iam delete-role --role-name admin-role || true
  echo "   deleted admin-role"
fi

echo "-- S3: emptying and deleting the scenario-B bucket --"
if awscli_read s3api head-bucket --bucket "$SCENARIO_B_BUCKET" >/dev/null 2>&1; then
  awscli s3 rm "s3://$SCENARIO_B_BUCKET" --recursive || true
  awscli s3api delete-bucket --bucket "$SCENARIO_B_BUCKET" || true
  echo "   deleted s3://$SCENARIO_B_BUCKET"
fi

echo "-- CloudTrail: stopping and deleting the trail (delivery bucket is untouched by this) --"
if awscli_read cloudtrail get-trail-status --name "$TRAIL_NAME" >/dev/null 2>&1; then
  awscli cloudtrail stop-logging --name "$TRAIL_NAME" || true
  awscli cloudtrail delete-trail --name "$TRAIL_NAME" || true
  echo "   deleted trail $TRAIL_NAME"
fi

if [ "$DELETE_PRESERVATION" = "1" ]; then
  echo
  echo "-- Preservation bucket deletion requested --"
  confirm "DELETE EVIDENCE" "s3://$PRESERVATION_BUCKET holds your collected CloudTrail evidence. Deleting it is IRREVERSIBLE and is almost certainly NOT what you want once real evidence has been collected and exported - make sure 05_export_evidence.sh has already copied everything you need into data/real/raw/ first."
  if awscli_read s3api head-bucket --bucket "$PRESERVATION_BUCKET" >/dev/null 2>&1; then
    awscli s3api put-object-lock-configuration --bucket "$PRESERVATION_BUCKET" \
      --object-lock-configuration '{"ObjectLockEnabled":"Enabled"}' 2>/dev/null || true
    awscli s3 rm "s3://$PRESERVATION_BUCKET" --recursive || true
    awscli s3api delete-bucket --bucket "$PRESERVATION_BUCKET" || true
    echo "   deleted s3://$PRESERVATION_BUCKET"
  fi
else
  echo
  echo "Preservation bucket s3://$PRESERVATION_BUCKET was left in place (default). Re-run with"
  echo "--delete-preservation-bucket if you really want to remove your collected evidence too."
fi

echo
echo "Cleanup complete. [VERIFY AT RUNTIME] Check the Billing, IAM, EC2, S3 and CloudTrail consoles"
echo "yourself to confirm nothing tagged Project=$PROJECT_TAG remains (or, for the preservation bucket,"
echo "that it remains exactly if you intended to keep it)."
