"""Result tables and figures. Figures/tables carry the data-provenance banner."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

SYNTH_BANNER = "SYNTHETIC TEST DATA - NOT AWS EVIDENCE - NOT RESEARCH RESULTS"

METRIC_COLS = [("SC", "schema_coverage"), ("CC", "collection_completeness"), ("P", "correlation_precision"),
               ("R", "correlation_recall"), ("F1", "f1_score"), ("FCR", "false_correlation_rate"),
               ("TOA", "timeline_ordering_accuracy"), ("TC", "timeline_completeness"),
               ("TDR", "tamper_detection_rate")]


def _fmt(v: Any, name: str, undefined: List[str], fmt: str) -> str:
    if v is not None:
        return f"{v * 100:.1f}%" if fmt == "pct" else f"{v:.6f}"
    return "undef" if name in undefined else "—"


def summary_frame(results: List[Dict[str, Any]], fmt: str = "raw") -> pd.DataFrame:
    rows = []
    for r in results:
        row = {"run": r["run_id"], "scenario": r["scenario"], "config": r["config_label"], "mode": r["mode"],
               "window_s": r["time_window_seconds"] if r["time_window_seconds"] is not None else "N/A"}
        und = r.get("undefined_metrics", [])
        for short, key in METRIC_COLS:
            row[short] = _fmt(r.get(key), key, und, fmt)
        pt = r.get("processing_time_seconds") or {}
        vals = [v for v in pt.values() if isinstance(v, (int, float))]
        row["time_s"] = f"{sum(vals):.2f}" if vals else "—"
        rows.append(row)
    return pd.DataFrame(rows)


def to_markdown(df: pd.DataFrame) -> str:
    cols = list(df.columns)
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for _, r in df.iterrows():
        lines.append("| " + " | ".join(str(r[c]) for c in cols) + " |")
    return "\n".join(lines)


def write_tables(results: List[Dict[str, Any]], out_dir, provenance: str) -> Dict[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    raw, pct = summary_frame(results, "raw"), summary_frame(results, "pct")
    raw.to_csv(out / "results_summary.csv", index=False)
    banner = f"> **{SYNTH_BANNER}**\n\n" if provenance == "synthetic" else ""
    legend = ("\n\n`—` = not measured/not applicable for this run; `undef` = mathematically undefined "
              "(e.g., zero grouped pairs). Values are never estimated.\n")
    md = out / "results_summary.md"
    md.write_text("# Results summary\n\n" + banner + f"Data provenance: **{provenance}**\n\n" + to_markdown(pct) + legend)
    return {"csv": str(out / "results_summary.csv"), "md": str(md)}


def write_figures(results: List[Dict[str, Any]], timelines: Dict[str, "pd.DataFrame"], out_dir, provenance: str) -> List[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    banner = SYNTH_BANNER if provenance == "synthetic" else f"data provenance: {provenance}"
    written: List[str] = []
    scen = sorted({r["scenario"] for r in results if r["mode"] != "tamper"})

    # 1. OR vs AND at the default window
    fig, axes = plt.subplots(1, len(scen), figsize=(4.2 * len(scen), 3.8), sharey=True, squeeze=False)
    for ax, sc in zip(axes[0], scen):
        sel = {r["mode"]: r for r in results if r["scenario"] == sc and r["time_window_seconds"] == 300
               and r["mode"] in ("or", "and")}
        w = 0.35
        for k, (mode, color) in enumerate((("or", "#4C78A8"), ("and", "#F58518"))):
            r = sel.get(mode)
            vals = [(r or {}).get(m) or 0.0 for m in ("correlation_precision", "correlation_recall", "f1_score")]
            ax.bar([i + (k - 0.5) * w for i in range(3)], vals, w, label=mode.upper(), color=color)
        ax.set_xticks(range(3)); ax.set_xticklabels(["P", "R", "F1"]); ax.set_ylim(0, 1.05); ax.set_title(sc)
    axes[0][0].set_ylabel("score"); axes[0][-1].legend()
    fig.suptitle(f"Correlation quality, 300 s window\n{banner}", fontsize=9, color="crimson" if provenance == "synthetic" else "black")
    fig.tight_layout(); p = out / "correlation_quality.png"; fig.savefig(p, dpi=130); plt.close(fig); written.append(str(p))

    # 2. window sensitivity (OR)
    fig, axes = plt.subplots(1, len(scen), figsize=(4.2 * len(scen), 3.6), sharey=True, squeeze=False)
    for ax, sc in zip(axes[0], scen):
        rows = sorted([r for r in results if r["scenario"] == sc and r["mode"] == "or"], key=lambda r: r["time_window_seconds"])
        xs = [r["time_window_seconds"] for r in rows]
        for key, lab in (("correlation_precision", "P"), ("correlation_recall", "R"), ("f1_score", "F1")):
            ax.plot(xs, [r.get(key) for r in rows], marker="o", label=lab)
        ax.set_xscale("log"); ax.set_xticks(xs); ax.set_xticklabels([str(x) for x in xs]); ax.set_title(sc)
        ax.set_xlabel("window (s)"); ax.set_ylim(0, 1.05)
    axes[0][-1].legend()
    fig.suptitle(f"OR-matching window sensitivity\n{banner}", fontsize=9, color="crimson" if provenance == "synthetic" else "black")
    fig.tight_layout(); p = out / "window_sensitivity.png"; fig.savefig(p, dpi=130); plt.close(fig); written.append(str(p))

    # 3. timeline plots (OR, default window)
    for key, df in timelines.items():
        ev = df[df["row_type"] == "EVENT"].copy()
        if ev.empty:
            continue
        ev["t"] = pd.to_datetime(ev["event_time_utc"], utc=True)
        gids = {g: i for i, g in enumerate(dict.fromkeys(ev["group_id"]))}
        fig, ax = plt.subplots(figsize=(9, 3.6))
        ax.scatter(ev["t"], ev["group_id"].map(gids), c="lightgray", s=18, label="unlabeled event")
        gt = ev[ev["gt_step_id"].notna()]
        ax.scatter(gt["t"], gt["group_id"].map(gids), c="crimson", s=70, marker="*", label="ground-truth step")
        for _, r in gt.iterrows():
            ax.annotate(str(int(r["gt_step_id"])), (r["t"], gids[r["group_id"]]), textcoords="offset points", xytext=(4, 5), fontsize=8)
        ax.set_yticks([]); ax.set_xlabel("event time (UTC)"); ax.set_ylabel("correlation group")
        ax.set_title(f"{key}\n{banner}", fontsize=9, color="crimson" if provenance == "synthetic" else "black"); ax.legend(loc="upper left", fontsize=7)
        fig.autofmt_xdate(); fig.tight_layout()
        p = out / f"timeline_{key}.png"; fig.savefig(p, dpi=130); plt.close(fig); written.append(str(p))
    return written
