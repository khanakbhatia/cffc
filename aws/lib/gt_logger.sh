# Ground-truth logging helper (Stage 2 §10). Source this AFTER aws/lib/common.sh.
# Each scenario script sets GT_SCENARIO and GT_SCRATCH before the first log_step call.
: "${GT_SCENARIO:?GT_SCENARIO must be set by the calling scenario script}"
: "${GT_SCRATCH:=$SCRATCH_DIR/${GT_SCENARIO}_ground_truth.jsonl}"
: > "$GT_SCRATCH"   # truncate: one fresh scratch log per scenario run

_GT_STEP_COUNTER_FILE="$SCRATCH_DIR/${GT_SCENARIO}_step_counter"
echo 0 > "$_GT_STEP_COUNTER_FILE"

# log_step <expected_event_name> <expected_principal|NULL> <expected_source_ip|NULL> \
#          <expected_resource_id|NULL> <group_id> <is_attack_related:true|false> \
#          <attack_stage> <notes...>
log_step() {
  local name="$1" principal="$2" ip="$3" resource="$4" group="$5" attack="$6" stage="$7"; shift 7
  local notes="$*"
  local n; n=$(($(cat "$_GT_STEP_COUNTER_FILE") + 1)); echo "$n" > "$_GT_STEP_COUNTER_FILE"
  local t; t=$(utc_now)
  python3 - "$GT_SCRATCH" "$n" "$t" "$name" "$principal" "$ip" "$resource" "$group" "$attack" "$stage" "$notes" <<'PYEOF'
import json, sys
path, n, t, name, principal, ip, resource, group, attack, stage, notes = sys.argv[1:12]
nullify = lambda v: None if v in ("NULL", "") else v
row = {"step_id": int(n), "wall_clock_time_utc": t, "expected_event_name": name,
       "expected_principal": nullify(principal), "expected_source_ip": nullify(ip),
       "expected_resource_id": nullify(resource), "expected_correlation_group_id": group,
       "is_attack_related": attack == "true", "attack_stage": nullify(stage), "notes": notes}
with open(path, "a") as f:
    f.write(json.dumps(row) + "\n")
PYEOF
  echo "  [gt] step $n @ $t  $name  (group=$group attack=$attack)" >&2
}

# log_step_prompt: like log_step but PAUSES and asks YOU to press Enter right after you perform the
# action yourself (used only for the Scenario C manual browser sign-in attempts). The timestamp
# recorded is the moment you press Enter, i.e. as close as practical to the real action time.
log_step_prompt() {
  local name="$1" principal="$2" ip="$3" resource="$4" group="$5" attack="$6" stage="$7"; shift 7
  echo ">>> MANUAL STEP: $* " >&2
  if [ "${DRY_RUN:-0}" = "1" ]; then
    echo ">>> [dry-run] would pause here for you to perform it in the AWS Console, then press Enter." >&2
  else
    echo ">>> Perform it now in the AWS Console, THEN press Enter here." >&2
    read -r _
  fi
  log_step "$name" "$principal" "$ip" "$resource" "$group" "$attack" "$stage" "$*"
}
