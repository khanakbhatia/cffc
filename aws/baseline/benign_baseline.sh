#!/usr/bin/env bash
# Benign background activity (Stage 2 §7 "Event categories": benign baseline + 3 labeled attacks).
# NOT ground-truth-logged - these events exist so the dataset isn't 100% attack-labeled traffic,
# mirroring cffc.synthetic's _noise() in the Stage 4 synthetic generator. Safe to run any time,
# any number of times, before/after/between scenario scripts - read-only AWS calls only.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../lib/common.sh" "$@"
require_preflight; require_cost_ack

echo "== Benign baseline activity (read-only AWS calls, no ground truth logged) =="
CALLS=(
  "iam list-users"
  "iam get-account-summary"
  "ec2 describe-instances"
  "ec2 describe-volumes"
  "s3api list-buckets"
  "cloudtrail describe-trails"
)
N="${1:-8}"
[[ "$N" == --* ]] && N=8   # ignore --dry-run etc. if passed positionally
for i in $(seq 1 "$N"); do
  call="${CALLS[$((RANDOM % ${#CALLS[@]}))]}"
  echo "-- [$i/$N] aws $call --"
  if [ "$DRY_RUN" = "1" ]; then echo "[dry-run]"; else awscli $call >/dev/null || true; sleep 3; fi
done
echo "Benign baseline complete ($N calls)."
