#!/usr/bin/env bash
# Thin wrapper around the Stage 4 `cffc build-manifest` CLI (SHA-256, append-only manifest -
# Stage 3.5 §A.1/§A.2). Nothing AWS-specific here; this is the integrity step from the already-
# approved and already-tested Stage 4 pipeline, run against the files 05_export_evidence.sh copied.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO="${1:-}"
[[ "$SCENARIO" =~ ^scenario_[abc]$ ]] || { echo "usage: $0 <scenario_a|scenario_b|scenario_c>" >&2; exit 1; }
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
RAW_DIR="$REPO_ROOT/data/real/raw/$SCENARIO"
[ -d "$RAW_DIR" ] && [ -n "$(ls -A "$RAW_DIR" 2>/dev/null)" ] || { echo "ERROR: $RAW_DIR is empty - run 05_export_evidence.sh first." >&2; exit 1; }

export PYTHONPATH="$REPO_ROOT/src"
echo "== Building/updating manifest for $SCENARIO =="
python3 -m cffc build-manifest --data-root "$REPO_ROOT/data/real" --scenario "$SCENARIO" --collector "${USER:-researcher}"
echo "-- Verifying --"
python3 -m cffc verify --data-root "$REPO_ROOT/data/real" --scenario "$SCENARIO"
echo
echo "Manifest OK. Next: python3 -m cffc run --data-root data/real --out-root outputs  (or run all 3 scenarios first)"
