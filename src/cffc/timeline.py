"""Timeline reconstruction (Stage 2 §17).

Group-contiguous ordering: groups are ordered by their earliest member; members inside a group
are ordered chronologically with the deterministic tie-break in ``CanonicalEvent.sort_key``.
With baseline correlation (all singletons) this is a plain chronological sort. The pipeline never
reads ground truth; ``annotate_with_ground_truth`` is an evaluation-only step.
"""
from __future__ import annotations

from typing import Dict, Tuple

import pandas as pd

from .correlation import CorrelationResult
from .ground_truth import GroundTruth
from .matching import MatchResult, candidates_from_timeline, match_steps
from .timeutil import format_utc

TIMELINE_COLUMNS = ["step_number", "event_time_utc", "cloud_service", "action", "principal_id",
                    "source_ip", "resource_id", "result", "group_id", "event_id", "raw_event_ref"]


def reconstruct_timeline(events, corr: CorrelationResult) -> pd.DataFrame:
    by_id = {e.event_id: e for e in events}
    rows = []
    for gid, members in zip(corr.group_ids, corr.groups):
        for eid in members:
            e = by_id[eid]
            rows.append({"event_time_utc": e.event_time_utc, "cloud_service": e.cloud_service,
                         "action": e.action, "principal_id": e.principal_id, "source_ip": e.source_ip,
                         "resource_id": e.resource_id, "result": e.result, "group_id": gid,
                         "event_id": e.event_id, "raw_event_ref": e.raw_event_ref})
    df = pd.DataFrame(rows, columns=TIMELINE_COLUMNS[1:])
    df.insert(0, "step_number", range(1, len(df) + 1))
    return df


def annotate_with_ground_truth(timeline: pd.DataFrame, gt: GroundTruth,
                               tolerance_seconds: float) -> Tuple[pd.DataFrame, MatchResult, Dict[int, int]]:
    """Match GT steps against timeline rows. Returns (annotated df incl. MISSING rows, match, positions)."""
    match = match_steps(gt.steps, candidates_from_timeline(timeline), tolerance_seconds)
    id_to_step = {v: k for k, v in match.step_to_id.items() if v is not None}
    df = timeline.copy()
    df["gt_step_id"] = df["event_id"].map(id_to_step)
    df["row_type"] = "EVENT"
    positions = {sid: int(df.loc[df["event_id"] == eid, "step_number"].iloc[0])
                 for sid, eid in match.step_to_id.items() if eid is not None}
    missing = []
    for sid in match.missing_steps:
        st = gt.step(sid)
        missing.append({"step_number": None, "event_time_utc": format_utc(st.wall_clock), "action": st.expected_event_name,
                        "principal_id": st.expected_principal, "source_ip": st.expected_source_ip,
                        "gt_step_id": sid, "row_type": "MISSING"})
    if missing:
        df = pd.concat([df, pd.DataFrame(missing)], ignore_index=True)
    return df, match, positions
