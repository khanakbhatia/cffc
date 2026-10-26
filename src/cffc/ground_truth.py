"""Ground-truth file loading and validation (Stage 3.5 Part C)."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .timeutil import TimeParseError, parse_utc


class GroundTruthError(Exception):
    def __init__(self, problems: List[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass
class GTStep:
    step_id: int
    wall_clock: datetime
    expected_event_name: str
    group_id: str
    is_attack_related: bool
    expected_principal: Optional[str] = None
    expected_source_ip: Optional[str] = None
    expected_resource_id: Optional[str] = None
    attack_stage: Optional[str] = None
    notes: str = ""


@dataclass
class GroundTruth:
    scenario: str
    steps: List[GTStep]
    groups: Dict[str, List[int]]
    frozen: bool
    author: Optional[str]
    path: str
    sha256: str
    read_only_on_disk: bool = field(default=False)

    def step(self, step_id: int) -> GTStep:
        return next(s for s in self.steps if s.step_id == step_id)

    @property
    def n_steps(self) -> int:
        return len(self.steps)


def load_ground_truth(path, *, require_frozen: bool = True) -> GroundTruth:
    path = Path(path)
    problems: List[str] = []
    raw = path.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GroundTruthError([f"not valid JSON: {exc}"]) from exc
    if not isinstance(data, dict):
        raise GroundTruthError(["top level must be an object"])
    for k in ("schema_version", "scenario", "steps", "expected_correlation_groups", "frozen"):
        if k not in data:
            problems.append(f"missing top-level key: {k}")
    steps_raw = data.get("steps") if isinstance(data.get("steps"), list) else []
    if not steps_raw:
        problems.append("steps must be a non-empty list")
    if require_frozen and data.get("frozen") is not True:
        problems.append("ground truth is not frozen ('frozen' must be true; Stage 2 §10 protocol)")

    steps: List[GTStep] = []
    seen_ids = set()
    for i, s in enumerate(steps_raw):
        if not isinstance(s, dict):
            problems.append(f"steps[{i}] is not an object")
            continue
        for k in ("step_id", "wall_clock_time_utc", "expected_event_name",
                  "expected_correlation_group_id", "is_attack_related"):
            if k not in s:
                problems.append(f"steps[{i}] missing {k}")
        if any(k not in s for k in ("step_id", "wall_clock_time_utc", "expected_event_name",
                                    "expected_correlation_group_id", "is_attack_related")):
            continue
        if not isinstance(s["step_id"], int) or isinstance(s["step_id"], bool):
            problems.append(f"steps[{i}].step_id must be an integer")
            continue
        if s["step_id"] in seen_ids:
            problems.append(f"duplicate step_id {s['step_id']}")
        seen_ids.add(s["step_id"])
        try:
            wc = parse_utc(s["wall_clock_time_utc"])
        except TimeParseError as exc:
            problems.append(f"steps[{i}] bad wall_clock_time_utc: {exc}")
            continue
        steps.append(GTStep(
            step_id=s["step_id"], wall_clock=wc, expected_event_name=s["expected_event_name"],
            group_id=s["expected_correlation_group_id"], is_attack_related=bool(s["is_attack_related"]),
            expected_principal=s.get("expected_principal"), expected_source_ip=s.get("expected_source_ip"),
            expected_resource_id=s.get("expected_resource_id"), attack_stage=s.get("attack_stage"),
            notes=s.get("notes", "")))
    steps.sort(key=lambda s: s.step_id)
    for a, b in zip(steps, steps[1:]):
        if b.wall_clock < a.wall_clock:
            problems.append(f"wall-clock time decreases between step {a.step_id} and {b.step_id}")

    groups: Dict[str, List[int]] = {}
    groups_raw = data.get("expected_correlation_groups")
    if isinstance(groups_raw, list):
        for g in groups_raw:
            if not isinstance(g, dict) or "group_id" not in g or "member_step_ids" not in g:
                problems.append("each expected_correlation_groups entry needs group_id and member_step_ids")
                continue
            if g["group_id"] in groups:
                problems.append(f"duplicate group_id {g['group_id']}")
            groups[g["group_id"]] = list(g["member_step_ids"])
        for gid, members in groups.items():
            for m in members:
                if m not in seen_ids:
                    problems.append(f"group {gid} references unknown step_id {m}")
        for st in steps:
            if st.group_id not in groups:
                problems.append(f"step {st.step_id} uses undeclared group {st.group_id}")
            elif st.step_id not in groups[st.group_id]:
                problems.append(f"step {st.step_id} not listed in members of its group {st.group_id}")
        listed = [m for ms in groups.values() for m in ms]
        if len(listed) != len(set(listed)):
            problems.append("a step appears in more than one correlation group")
    if problems:
        raise GroundTruthError(problems)
    mode = path.stat().st_mode
    read_only = not (mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    return GroundTruth(scenario=data["scenario"], steps=steps, groups=groups, frozen=bool(data.get("frozen")),
                       author=data.get("author"), path=str(path), sha256=hashlib.sha256(raw).hexdigest(),
                       read_only_on_disk=read_only)


def freeze_file(path) -> None:
    """chmod 444 (Stage 3.5 Part C freeze protocol step 3)."""
    os.chmod(path, 0o444)
