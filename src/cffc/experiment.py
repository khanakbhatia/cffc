"""Experiment runner: executes the Stage 3.5 Part D matrix and writes all generated outputs.

Outputs go to ``<out_root>/<provenance>/`` so synthetic and real results can never share a folder.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__, integrity, metrics, reporting
from .config import correlation_config
from .correlation import correlate
from .ground_truth import GroundTruthError, load_ground_truth
from .ingestion import ingest_scenario
from .matching import candidates_from_events, match_steps
from .timeline import annotate_with_ground_truth, reconstruct_timeline
from .timeutil import utc_now_str


class NoEvidenceError(RuntimeError):
    pass


class ProvenanceError(RuntimeError):
    pass


def read_provenance(data_root) -> str:
    p = Path(data_root) / "PROVENANCE.json"
    if not p.is_file():
        raise ProvenanceError(f"{data_root} has no PROVENANCE.json; refusing to run on data of unknown origin")
    kind = json.loads(p.read_text()).get("kind")
    if kind not in ("synthetic", "real"):
        raise ProvenanceError(f"PROVENANCE.json kind must be 'synthetic' or 'real', got {kind!r}")
    return kind


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, default=str)
        f.write("\n")


def _sha(path) -> str:
    return integrity.hash_file(path)


def _blank_result(run_id, scenario, label, mode, window, provenance, executor) -> Dict[str, Any]:
    r: Dict[str, Any] = {
        "run_id": run_id, "scenario": scenario, "config_label": label, "mode": mode,
        "time_window_seconds": window, "data_provenance": provenance,
        "schema_coverage": None, "collection_completeness": None, "correlation_precision": None,
        "correlation_recall": None, "f1_score": None, "false_correlation_rate": None,
        "timeline_ordering_accuracy": None, "timeline_completeness": None, "tamper_detection_rate": None,
        "processing_time_seconds": {"normalization": None, "correlation": None, "timeline": None, "evaluation": None},
        "notes": "", "undefined_metrics": [], "executed_at_utc": utc_now_str(), "executor": executor, "details": {},
    }
    if provenance == "synthetic":
        r["WARNING"] = reporting.SYNTH_BANNER
    return r


def run_experiments(data_root, out_root, cfg: Dict[str, Any], *, executor: Optional[str] = None,
                    config_path: Optional[str] = None) -> Dict[str, Any]:
    started = utc_now_str()
    data_root, out_root = Path(data_root), Path(out_root)
    provenance = read_provenance(data_root)
    executor = executor or os.environ.get("CFFC_EXECUTOR", "unspecified")
    out = out_root / provenance
    if out.exists():
        shutil.rmtree(out)           # generated outputs are fully reproducible; never mix runs
    for sub in ("results", "timelines", "groups", "tables", "figures", "scratch"):
        (out / sub).mkdir(parents=True, exist_ok=True)

    templates: List[Dict[str, Any]] = cfg["experiments"]["templates"]
    scenarios: List[str] = cfg["experiments"]["scenarios"]
    tol = float(cfg["evaluation"]["gt_match_tolerance_seconds"])
    scope = cfg["evaluation"]["pair_scope"]
    raw_root = data_root / "raw"
    all_results: List[Dict[str, Any]] = []
    timelines_for_plot: Dict[str, Any] = {}
    skipped: Dict[str, str] = {}
    scenario_info: Dict[str, Any] = {}
    tamper_items = []
    warnings: List[str] = []

    for si, sc in enumerate(scenarios):
        gt_path = data_root / "ground_truth" / f"{sc}_ground_truth.json"
        man_path = data_root / "manifests" / f"{sc}_manifest.json"
        if not (raw_root / sc).is_dir() or not gt_path.is_file() or not man_path.is_file():
            skipped[sc] = "missing raw directory, ground truth file, or manifest"
            continue
        try:
            gt = load_ground_truth(gt_path, require_frozen=cfg["evaluation"]["require_frozen_ground_truth"])
        except GroundTruthError as exc:
            skipped[sc] = f"ground truth invalid: {exc}"
            continue
        if not gt.read_only_on_disk:
            warnings.append(f"{sc}: ground-truth file is writable on disk (freeze protocol says chmod 444)")
        t0 = time.perf_counter()
        ing = ingest_scenario(raw_root, sc, man_path, strict_integrity=cfg["ingestion"]["strict_integrity"],
                              deduplicate=cfg["ingestion"]["deduplicate_event_ids"])
        t_norm = time.perf_counter() - t0
        events = ing.events
        sc_cov = metrics.schema_coverage(events)
        match_ev = match_steps(gt.steps, candidates_from_events(events), tol)
        cc = metrics.collection_completeness(match_ev)
        step_group = {gt.step(s).step_id: gt.step(s).group_id for s in match_ev.step_to_id}
        true_group_of = {e.event_id: None for e in events}
        for sid, eid in match_ev.step_to_id.items():
            if eid is not None:
                true_group_of[eid] = step_group[sid]
        scenario_info[sc] = {"n_files": len(ing.files), "n_records_read": ing.n_records_read, "n_events": len(events),
                             "n_normalization_failures": len(ing.failures), "n_duplicates_dropped": len(ing.duplicates),
                             "integrity_ok": ing.integrity_ok, "ground_truth_sha256": gt.sha256,
                             "manifest_sha256": _sha(man_path), "gt_steps": gt.n_steps}
        for v in ing.manifest["entries"]:
            tamper_items.append((raw_root / v["filename"], v))
        if ing.failures:
            _write_json(out / "results" / f"{sc}_normalization_failures.json",
                        [f.__dict__ for f in ing.failures])

        for ti, tpl in enumerate(templates):
            run_id = f"R{si * len(templates) + ti + 1:02d}"
            mode, window = tpl["mode"], tpl.get("window_seconds")
            res = _blank_result(run_id, sc, tpl["label"], mode, window, provenance, executor)
            res["schema_coverage"] = sc_cov["value"]
            res["collection_completeness"] = cc["value"]
            ccfg = correlation_config(cfg, mode, window)

            t1 = time.perf_counter(); corr = correlate(events, ccfg); t_corr = time.perf_counter() - t1
            t2 = time.perf_counter(); tl = reconstruct_timeline(events, corr); t_tl = time.perf_counter() - t2
            t3 = time.perf_counter()
            ann, match_tl, positions = annotate_with_ground_truth(tl, gt, tol)
            tc = metrics.timeline_completeness(match_tl)
            toa = metrics.timeline_ordering_accuracy(gt, positions)
            scores_by_scope = {}
            for sco in metrics.PAIR_SCOPES:
                cnt = metrics.pair_counts(corr.group_of, true_group_of, sco)
                scores_by_scope[sco] = {**cnt, **metrics.correlation_scores(cnt)}
            primary = scores_by_scope[scope]
            t_eval = time.perf_counter() - t3

            res["timeline_ordering_accuracy"] = toa["value"]
            res["timeline_completeness"] = tc["value"]
            if mode == "baseline":
                res["notes"] = ("Baseline performs no correlation: precision/recall/F1/FCR are undefined per the "
                                "approved Part D matrix.")
            else:
                res["correlation_precision"] = primary["precision"]
                res["correlation_recall"] = primary["recall"]
                res["f1_score"] = primary["f1"]
                res["false_correlation_rate"] = primary["false_correlation_rate"]
            inv: List[str] = []
            if tc["value"] is not None and cc["value"] is not None and tc["value"] > cc["value"] + 1e-12:
                inv.append("TC > CC: impossible by construction (pipeline bug)")
            if tc["value"] is not None and cc["value"] is not None and tc["value"] < cc["value"] - 1e-12:
                inv.append("TC < CC: event collected but lost downstream (pipeline bug) - investigate")
            res["processing_time_seconds"] = {"normalization": round(t_norm, 4), "correlation": round(t_corr, 4),
                                              "timeline": round(t_tl, 4), "evaluation": round(t_eval, 4)}
            res["undefined_metrics"] = [k for k in ("schema_coverage", "collection_completeness", "correlation_precision",
                                                    "correlation_recall", "f1_score", "false_correlation_rate",
                                                    "timeline_ordering_accuracy", "timeline_completeness") if res[k] is None]
            res["details"] = {
                "pair_scope_primary": scope, "pair_metrics_by_scope": scores_by_scope,
                "n_groups": corr.n_groups, "n_multi_event_groups": corr.n_multi_event_groups,
                "n_links": len(corr.edges), "n_pairs_examined": corr.n_pairs_examined,
                "schema_coverage": sc_cov, "collection_completeness": cc, "timeline_ordering": toa,
                "timeline_completeness": tc, "invariant_violations": inv,
                "gt_match_delta_seconds": match_ev.delta_seconds, "ground_truth_sha256": gt.sha256,
                "normalization_time_is_per_scenario": True,
            }
            _write_json(out / "results" / f"{sc}_{run_id}_metrics.json", res)
            ann.to_csv(out / "timelines" / f"{sc}_{run_id}_timeline.csv", index=False)
            _write_json(out / "groups" / f"{sc}_{run_id}_groups.json", {
                "mode": mode, "window_seconds": window, "groups": dict(zip(corr.group_ids, corr.groups)),
                "links": [{"a": e.a, "b": e.b, "matched_keys": list(e.matched_keys), "delta_s": e.delta_seconds}
                          for e in corr.edges]})
            all_results.append(res)
            if mode == "or" and window == 300 and sc not in [k.split("_R")[0] for k in timelines_for_plot]:
                timelines_for_plot[f"{sc}_{run_id}"] = ann

    if not all_results:
        shutil.rmtree(out, ignore_errors=True)
        raise NoEvidenceError(f"no runnable scenarios under {data_root}: {skipped or 'none configured'}")

    # tamper run
    tamper_id = f"R{len(scenarios) * len(templates) + 1:02d}"
    rep = integrity.run_tamper_suite(tamper_items, out / "scratch", out / "results" / "tamper_test_report.json")
    shutil.rmtree(out / "scratch", ignore_errors=True)
    tres = _blank_result(tamper_id, "all", "Tamper test", "tamper", None, provenance, executor)
    tdr = metrics.tamper_detection_rate(rep)
    tres["tamper_detection_rate"] = tdr["value"]
    tres["details"] = {"tamper": tdr, "files_tested": rep["files_tested"]}
    tres["notes"] = "Implementation-correctness check of byte-level tamper evidence (not a research finding)."
    tres["undefined_metrics"] = [] if tdr["value"] is not None else ["tamper_detection_rate"]
    tres["processing_time_seconds"] = {"normalization": None, "correlation": None, "timeline": None, "evaluation": None}
    _write_json(out / "results" / f"{tamper_id}_tamper_metrics.json", tres)
    all_results.append(tres)

    tables = reporting.write_tables(all_results, out / "tables", provenance)
    figures = reporting.write_figures(all_results, timelines_for_plot, out / "figures", provenance)
    manifest = {
        "cffc_version": __version__, "data_provenance": provenance, "data_root": str(data_root),
        "started_at_utc": started, "finished_at_utc": utc_now_str(), "executor": executor,
        "python": sys.version.split()[0], "platform": platform.platform(),
        "config_path": config_path, "config_sha256": hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest(),
        "scenarios_run": scenario_info, "scenarios_skipped": skipped, "n_runs": len(all_results),
        "tables": tables, "figures": figures, "warnings": warnings,
        "notice": reporting.SYNTH_BANNER if provenance == "synthetic" else "Generated from data marked 'real'.",
    }
    _write_json(out / "run_manifest.json", manifest)
    return {"out_dir": str(out), "provenance": provenance, "results": all_results, "manifest": manifest}
