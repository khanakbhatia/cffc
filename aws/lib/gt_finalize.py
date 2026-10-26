#!/usr/bin/env python3
"""Assemble the scratch ground-truth log into the frozen Stage 2 §10 / Stage 3.5 Part C file.

Validates against the Stage 4 cffc package (schema + freeze-protocol checks) BEFORE freezing.
On any validation error, prints the problems and exits non-zero WITHOUT writing or freezing
anything - the scenario script's ground truth is not considered real until this passes.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from cffc.ground_truth import GroundTruthError, load_ground_truth, freeze_file  # noqa: E402
from cffc.timeutil import utc_now_str  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", required=True)
    p.add_argument("--jsonl", required=True, type=Path)
    p.add_argument("--groups", required=True, help="JSON list: [{\"group_id\":..,\"rationale\":..}, ...]")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--author", required=True)
    a = p.parse_args()

    if not a.jsonl.is_file() or a.jsonl.stat().st_size == 0:
        print(f"ERROR: {a.jsonl} is missing or empty - did the scenario script call log_step?", file=sys.stderr)
        return 2
    steps = [json.loads(line) for line in a.jsonl.read_text().splitlines() if line.strip()]
    group_specs = json.loads(a.groups)
    members: dict[str, list[int]] = {}
    for s in steps:
        members.setdefault(s["expected_correlation_group_id"], []).append(s["step_id"])
    groups = [{"group_id": g["group_id"], "member_step_ids": sorted(members.get(g["group_id"], [])),
               "rationale": g["rationale"]} for g in group_specs]

    doc = {"schema_version": "1.0", "scenario": a.scenario, "created_at_utc": utc_now_str(),
           "author": a.author, "frozen": True, "steps": steps, "expected_correlation_groups": groups}

    a.out.parent.mkdir(parents=True, exist_ok=True)
    if a.out.exists():
        print(f"ERROR: {a.out} already exists. Ground truth is frozen; delete it deliberately "
              f"(and document why) before regenerating, per the Stage 2 §10 freeze protocol.", file=sys.stderr)
        return 2
    tmp = a.out.with_suffix(".tmp.json")
    tmp.write_text(json.dumps(doc, indent=2) + "\n")

    try:
        gt = load_ground_truth(tmp, require_frozen=True)
    except GroundTruthError as exc:
        print("GROUND TRUTH INVALID - not frozen, not written as final. Fix the scenario script / "
              "log_step calls and re-run. Problems:\n  - " + "\n  - ".join(exc.problems), file=sys.stderr)
        tmp.unlink()
        return 1

    tmp.rename(a.out)
    freeze_file(a.out)
    print(f"OK: {a.out} written and frozen (chmod 444). {gt.n_steps} steps, groups={list(gt.groups)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
