"""Command-line interface:  python -m cffc <command> ..."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import integrity
from .config import load_config
from .experiment import NoEvidenceError, ProvenanceError, run_experiments
from .ground_truth import GroundTruthError, load_ground_truth
from .ingestion import IngestionError, ingest_scenario
from .synthetic import generate_synthetic_dataset


def _cmd_generate(a):
    print(json.dumps(generate_synthetic_dataset(a.root), indent=2))
    return 0


def _cmd_manifest(a):
    m = integrity.build_manifest_for_directory(Path(a.data_root) / "raw", a.scenario,
                                               Path(a.data_root) / "manifests" / f"{a.scenario}_manifest.json", a.collector)
    print(f"manifest has {len(m['entries'])} entries")
    return 0


def _cmd_verify(a):
    root = Path(a.data_root)
    m = integrity.load_manifest(root / "manifests" / f"{a.scenario}_manifest.json")
    res = integrity.verify_manifest(root / "raw", m, a.scenario)
    bad = [r for r in res if r.status != "OK"]
    for r in res:
        print(f"{r.status:12s} {r.filename}")
    return 1 if bad else 0


def _cmd_validate_gt(a):
    try:
        gt = load_ground_truth(a.path, require_frozen=not a.allow_unfrozen)
    except GroundTruthError as exc:
        print("INVALID:", *exc.problems, sep="\n  - ")
        return 1
    print(f"OK: {gt.scenario}: {gt.n_steps} steps, groups={list(gt.groups)}, read_only_on_disk={gt.read_only_on_disk}")
    return 0


def _cmd_normalize(a):
    import pandas as pd
    root = Path(a.data_root)
    res = ingest_scenario(root / "raw", a.scenario, root / "manifests" / f"{a.scenario}_manifest.json")
    df = pd.DataFrame([{**e.to_dict(), "provider_specific": json.dumps(e.provider_specific)} for e in res.events])
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(a.out, index=False)
    print(f"{len(res.events)} events, {len(res.failures)} failures, {len(res.duplicates)} duplicates -> {a.out}")
    return 0


def _cmd_run(a):
    cfg = load_config(a.config)
    try:
        out = run_experiments(a.data_root, a.out_root, cfg, config_path=a.config)
    except (NoEvidenceError, ProvenanceError, IngestionError, integrity.IntegrityError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"{len(out['results'])} runs -> {out['out_dir']}  (provenance: {out['provenance']})")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="cffc", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("generate-synthetic", help="(re)generate synthetic TEST data"); s.add_argument("--root", default="data/synthetic"); s.set_defaults(f=_cmd_generate)
    s = sub.add_parser("build-manifest", help="hash evidence files into an append-only manifest")
    s.add_argument("--data-root", required=True); s.add_argument("--scenario", required=True); s.add_argument("--collector", required=True); s.set_defaults(f=_cmd_manifest)
    s = sub.add_parser("verify", help="verify evidence files against their manifest")
    s.add_argument("--data-root", required=True); s.add_argument("--scenario", required=True); s.set_defaults(f=_cmd_verify)
    s = sub.add_parser("validate-gt", help="validate a ground-truth file"); s.add_argument("path"); s.add_argument("--allow-unfrozen", action="store_true"); s.set_defaults(f=_cmd_validate_gt)
    s = sub.add_parser("normalize", help="normalize a scenario to a CSV of canonical events")
    s.add_argument("--data-root", required=True); s.add_argument("--scenario", required=True); s.add_argument("--out", required=True); s.set_defaults(f=_cmd_normalize)
    s = sub.add_parser("run", help="run the experiment matrix")
    s.add_argument("--data-root", required=True); s.add_argument("--out-root", default="outputs"); s.add_argument("--config", default="configs/default.toml"); s.set_defaults(f=_cmd_run)
    a = p.parse_args(argv)
    return a.f(a)


if __name__ == "__main__":
    sys.exit(main())
