"""One-to-one matching of ground-truth steps to collected events (or timeline rows).

Rule (Stage 3.5 §F): ``action`` equals ``expected_event_name`` AND |event_time - wall_clock| <= tolerance.
Concretization (docs/ASSUMPTIONS.md A4): when several candidates qualify, assignment is global-greedy
by (identity mismatches, |delta t|) using expected_principal / expected_source_ip as soft preferences
only; steps with >1 qualifying candidates are flagged ``ambiguous`` for manual review.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence

from .ground_truth import GTStep
from .timeutil import parse_utc


@dataclass(frozen=True)
class Candidate:
    id: str
    action: str
    dt: datetime
    principal: Optional[str]
    ip: Optional[str]


@dataclass
class MatchResult:
    step_to_id: Dict[int, Optional[str]]
    delta_seconds: Dict[int, float] = field(default_factory=dict)
    ambiguous_steps: List[int] = field(default_factory=list)
    tolerance_seconds: float = 30.0

    @property
    def n_total(self) -> int:
        return len(self.step_to_id)

    @property
    def n_matched(self) -> int:
        return sum(1 for v in self.step_to_id.values() if v is not None)

    @property
    def missing_steps(self) -> List[int]:
        return sorted(k for k, v in self.step_to_id.items() if v is None)


def candidates_from_events(events) -> List[Candidate]:
    return [Candidate(e.event_id, e.action, e.event_dt, e.principal_id, e.source_ip) for e in events]


def candidates_from_timeline(timeline) -> List[Candidate]:
    out = []
    for r in timeline.itertuples(index=False):
        out.append(Candidate(r.event_id, r.action, parse_utc(r.event_time_utc),
                             r.principal_id, None if _isnull(r.source_ip) else r.source_ip))
    return out


def _isnull(v) -> bool:
    return v is None or (isinstance(v, float) and v != v)


def match_steps(steps: Sequence[GTStep], candidates: Iterable[Candidate], tolerance_seconds: float = 30.0) -> MatchResult:
    cands = list(candidates)
    edges = []
    ambiguous: List[int] = []
    for s in steps:
        n_ok = 0
        for ci, c in enumerate(cands):
            if c.action != s.expected_event_name:
                continue
            delta = abs((c.dt - s.wall_clock).total_seconds())
            if delta > tolerance_seconds:
                continue
            n_ok += 1
            mism = 0
            if s.expected_principal is not None and c.principal != s.expected_principal:
                mism += 1
            if s.expected_source_ip is not None and c.ip != s.expected_source_ip:
                mism += 1
            edges.append((mism, delta, s.step_id, ci))
        if n_ok > 1:
            ambiguous.append(s.step_id)
    edges.sort()
    step_to_id: Dict[int, Optional[str]] = {s.step_id: None for s in steps}
    deltas: Dict[int, float] = {}
    used = set()
    for mism, delta, sid, ci in edges:
        if step_to_id[sid] is not None or ci in used:
            continue
        step_to_id[sid] = cands[ci].id
        deltas[sid] = delta
        used.add(ci)
    return MatchResult(step_to_id=step_to_id, delta_seconds=deltas,
                       ambiguous_steps=sorted(ambiguous), tolerance_seconds=tolerance_seconds)
