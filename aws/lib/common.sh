# Shared helpers. Sourced by every script in aws/ - never executed directly.
# Deliberately does not read, request, or print AWS secret credentials anywhere.
set -euo pipefail

CFFC_AWS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$CFFC_AWS_ROOT/.." && pwd)"
CONFIG_FILE="$CFFC_AWS_ROOT/config.env"
SCRATCH_DIR="$CFFC_AWS_ROOT/.scratch"
DRY_RUN=0

for arg in "$@"; do
  [ "$arg" = "--dry-run" ] && DRY_RUN=1
done

if [ ! -f "$CONFIG_FILE" ]; then
  echo "ERROR: $CONFIG_FILE not found. Copy aws/config.env.example to aws/config.env and edit it." >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$CONFIG_FILE"
mkdir -p "$SCRATCH_DIR"

: "${AWS_PROFILE:?set AWS_PROFILE in aws/config.env}"
: "${AWS_REGION:?set AWS_REGION in aws/config.env}"
: "${BUCKET_SUFFIX:?set BUCKET_SUFFIX in aws/config.env (must be non-empty and unique)}"
: "${PROJECT_TAG:?set PROJECT_TAG in aws/config.env}"

awscli() {
  if [ "$DRY_RUN" = "1" ]; then
    echo "[dry-run] aws --profile $AWS_PROFILE --region $AWS_REGION $*"
  else
    aws --profile "$AWS_PROFILE" --region "$AWS_REGION" "$@"
  fi
}

# Calls that must happen even in --dry-run (pure reads, no side effects) use this instead.
awscli_read() {
  aws --profile "$AWS_PROFILE" --region "$AWS_REGION" "$@"
}

utc_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

require_preflight() {
  if [ "${CFFC_PREFLIGHT_OK:-no}" != "yes" ] && [ "$DRY_RUN" != "1" ]; then
    echo "ERROR: aws/setup/00_preflight_checks.sh has not been run (or did not pass)." >&2
    echo "       Run it first: it confirms your identity/region/cost acknowledgment before anything else executes." >&2
    exit 1
  fi
}

require_cost_ack() {
  if [ "${CFFC_ACK_COSTS:-no}" != "yes" ] && [ "$DRY_RUN" != "1" ]; then
    echo "ERROR: CFFC_ACK_COSTS is not 'yes' in aws/config.env. Read docs/COST_NOTES.md first." >&2
    exit 1
  fi
}

confirm() {
  # confirm "PROCEED" "This will create billable resources."
  local word="$1" msg="${2:-}"
  if [ "$DRY_RUN" = "1" ]; then return 0; fi
  [ -n "$msg" ] && echo "$msg" >&2
  echo "Type '$word' to continue, anything else to abort:" >&2
  read -r reply
  if [ "$reply" != "$word" ]; then
    echo "Aborted (confirmation not given)." >&2
    exit 1
  fi
}

DRY_RUN_PLACEHOLDER_ACCOUNT="000000000000"
DRY_RUN_PLACEHOLDER_ARN="arn:aws:iam::000000000000:user/dry-run-placeholder"

# Both are dry-run-safe: under --dry-run they return a fixed placeholder and make NO AWS call, so
# every script in this package that only calls account_id()/caller_arn() (not a raw awscli_read sts
# get-caller-identity) can be dry-run before any credentials are even configured.
account_id() {
  if [ "$DRY_RUN" = "1" ]; then echo "$DRY_RUN_PLACEHOLDER_ACCOUNT"; return 0; fi
  awscli_read sts get-caller-identity --query Account --output text
}
caller_arn() {
  if [ "$DRY_RUN" = "1" ]; then echo "$DRY_RUN_PLACEHOLDER_ARN"; return 0; fi
  awscli_read sts get-caller-identity --query Arn --output text
}
