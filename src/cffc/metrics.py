"""Evaluation metrics (Stage 3.5 Part B). Pure functions; no I/O. See docs/METRICS.md."""
from __future__ import annotations

from collections import Counter
from math import comb
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .ground_truth import GroundTruth
from .matching import MatchResult
from .schema import CANONICAL_FIELDS, CanonicalEvent, populated_field_count

PAIR_SCOPES = ("all", "labeled_vs_unlabeled", "labeled_only")


def _div(num: float, den: float) -> Optional[float]:
    return None if den == 0 else num / den


# --- E. schema coverage
def schema_coverage(events: Sequence[CanonicalEvent]) -> Dict[str, Any]:
    n = len(events)
    total = n * len(CANONICAL_FIELDS)
    pop = sum(populated_field_count(e) for e in events)
    return {"value": _div(pop, total), "populated_fields": pop, "possible_fields": total, "n_events": n}


# --- F / L. completeness
def collection_completeness(match: MatchResult) -> Dict[str, Any]:
    return {"value": _div(match.n_matched, match.n_total), "matched": match.n_matched, "total": match.n_total,
            "missing_steps": match.missing_steps, "ambiguous_steps": match.ambiguous_steps,
            "tolerance_seconds": match.tolerance_seconds}


def timeline_completeness(match_in_timeline: MatchResult) -> Dict[str, Any]:
    return {"value": _div(match_in_timeline.n_matched, match_in_timeline.n_total),
            "present": match_in_timeline.n_matched, "total": match_in_timeline.n_total,
            "missing_steps": match_in_timeline.missing_steps}


# --- G/H/I/J. pair-based correlation metrics
def pair_counts(algo_group_of: Mapping[str, str], true_group_of: Mapping[str, Optional[str]],
                scope: str = "labeled_vs_unlabeled") -> Dict[str, int]:
    """Closed-form pair counting (verified against brute force in tests).

    ``true_group_of[event_id]`` is the ground-truth group label, or None for events not matched
    to any ground-truth step ("unlabeled"). Scopes: see docs/ASSUMPTIONS.md A5.
    """
    if scope not in PAIR_SCOPES:
        raise ValueError(f"scope must be one of {PAIR_SCOPES}")
    ids = [e for e in algo_group_of]
    if scope == "labeled_only":
        ids = [e for e in ids if true_group_of.get(e) is not None]
    cell = Counter()      # (algo group, true group) over labeled events
    algo_l = Counter()    # labeled count per algo group
    algo_u = Counter()    # unlabeled count per algo group
    true_n = Counter()    # labeled count per true group
    for e in ids:
        a, t = algo_group_of[e], true_group_of.get(e)
        if t is None:
            algo_u[a] += 1
        else:
            cell[(a, t)] += 1
            algo_l[a] += 1
            true_n[t] += 1
    tp = sum(comb(n, 2) for n in cell.values())
    true_pairs = sum(comb(n, 2) for n in true_n.values())
    if scope == "labeled_vs_unlabeled":
        algo_pairs = sum(comb(algo_l[a], 2) + algo_l[a] * algo_u[a] for a in set(algo_l) | set(algo_u))
    elif scope == "labeled_only":
        algo_pairs = sum(comb(n, 2) for n in algo_l.values())
    else:  # "all": unlabeled events are their own singleton truth groups
        sizes = Counter()
        for e in ids:
            sizes[algo_group_of[e]] += 1
        algo_pairs = sum(comb(n, 2) for n in sizes.values())
    return {"tp": tp, "fp": algo_pairs - tp, "fn": true_pairs - tp,
            "algo_pairs": algo_pairs, "true_pairs": true_pairs}


def brute_force_pair_counts(algo_group_of, true_group_of, scope="labeled_vs_unlabeled") -> Dict[str, int]:
    """O(n^2) reference implementation used only by tests."""
    ids = list(algo_group_of)
    if scope == "labeled_only":
        ids = [e for e in ids if true_group_of.get(e) is not None]
    tp = fp = fn = 0
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            a, b = ids[i], ids[j]
            ta, tb = true_group_of.get(a), true_group_of.get(b)
            algo_same = algo_group_of[a] == algo_group_of[b]
            true_same = ta is not None and ta == tb
            if scope == "labeled_vs_unlabeled" and ta is None and tb is None:
                algo_same = False   # unlabeled-unlabeled pairs carry no ground-truth claim
            if algo_same and true_same:
                tp += 1
            elif algo_same:
                fp += 1
            elif true_same:
                fn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "algo_pairs": tp + fp, "true_pairs": tp + fn}


def correlation_scores(c: Mapping[str, int]) -> Dict[str, Optional[float]]:
    p = _div(c["tp"], c["algo_pairs"])
    r = _div(c["tp"], c["true_pairs"])
    if p is None or r is None:
        f1 = None
    elif p + r == 0:
        f1 = 0.0   # both defined and zero: convention F1 = 0 (docs/METRICS.md)
    else:
        f1 = 2 * p * r / (p + r)
    fcr = _div(c["fp"], c["algo_pairs"])
    return {"precision": p, "recall": r, "f1": f1, "false_correlation_rate": fcr}


# --- K. ordering accuracy
def timeline_ordering_accuracy(gt: GroundTruth, positions: Mapping[int, int]) -> Dict[str, Any]:
    ordered = [s.step_id for s in gt.steps]
    full_den = max(len(ordered) - 1, 0)
    correct = eff = 0
    wrong: List[List[int]] = []
    for a, b in zip(ordered, ordered[1:]):
        if a in positions and b in positions:
            eff += 1
            if positions[a] < positions[b]:
                correct += 1
            else:
                wrong.append([a, b])
    return {"value": _div(correct, eff), "correct_pairs": correct, "effective_denominator": eff,
            "full_denominator": full_den, "misordered_adjacent_pairs": wrong}


# --- M. tamper detection
def tamper_detection_rate(report: Mapping[str, Any]) -> Dict[str, Any]:
    return {"value": report.get("tamper_detection_rate"), "detected": report.get("modifications_detected"),
            "attempted": report.get("modifications_attempted")}
