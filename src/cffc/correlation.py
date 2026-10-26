"""Rule-based + temporal-window correlation (Stage 2 §15/§16).

Modes
  or        link two events (|dt| <= window) if ANY comparable key is equal:
            principal_id, source_ip (valid IPs only), resource_id.
  and       link only if >= ``and_min_comparable_keys`` keys are non-null on BOTH events and ALL of
            those comparable keys are equal (concretization, docs/ASSUMPTIONS.md A3).
  baseline  no correlation: every event is its own group (single-source chronological baseline).
Groups are the connected components of the link graph (union-find), so linking is transitive.
Null / sentinel values never link ("unknown" principals must not merge unrelated events).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

MODES = ("or", "and", "baseline")
KEY_NAMES = ("principal_id", "source_ip", "resource_id")


@dataclass(frozen=True)
class CorrelationConfig:
    mode: str = "or"
    window_seconds: float = 300.0
    ignore_non_ip_source: bool = True
    null_sentinels: Tuple[str, ...] = ("unknown", "hidden_due_to_security_reasons", "")
    and_min_comparable_keys: int = 2

    def __post_init__(self):
        if self.mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        if self.window_seconds < 0:
            raise ValueError("window_seconds must be >= 0")
        if self.and_min_comparable_keys < 1:
            raise ValueError("and_min_comparable_keys must be >= 1")


@dataclass
class LinkEdge:
    a: str
    b: str
    matched_keys: Tuple[str, ...]
    delta_seconds: float


@dataclass
class CorrelationResult:
    mode: str
    window_seconds: float
    group_ids: List[str]
    groups: List[List[str]]
    group_of: Dict[str, str]
    edges: List[LinkEdge] = field(default_factory=list)
    n_events: int = 0
    n_pairs_examined: int = 0

    @property
    def n_groups(self) -> int:
        return len(self.groups)

    @property
    def n_multi_event_groups(self) -> int:
        return sum(1 for g in self.groups if len(g) > 1)


def extract_keys(ev, cfg: CorrelationConfig) -> Dict[str, Optional[str]]:
    sentinels = {s.lower() for s in cfg.null_sentinels}

    def clean(v):
        if v is None:
            return None
        v = str(v).strip()
        return None if (not v or v.lower() in sentinels) else v

    ip = clean(ev.source_ip)
    if ip is not None:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            if cfg.ignore_non_ip_source:
                ip = None
    return {"principal_id": clean(ev.principal_id), "source_ip": ip, "resource_id": clean(ev.resource_id)}


def _link(ka: Dict[str, Optional[str]], kb: Dict[str, Optional[str]], cfg: CorrelationConfig):
    comparable = [k for k in KEY_NAMES if ka[k] is not None and kb[k] is not None]
    equal = tuple(k for k in comparable if ka[k] == kb[k])
    if cfg.mode == "or":
        return equal or None
    if len(comparable) >= cfg.and_min_comparable_keys and len(equal) == len(comparable):
        return equal
    return None


def _find(parent: List[int], i: int) -> int:
    while parent[i] != i:
        parent[i] = parent[parent[i]]
        i = parent[i]
    return i


def correlate(events: Sequence, cfg: CorrelationConfig) -> CorrelationResult:
    ordered = sorted(events, key=lambda e: e.sort_key)
    ids = [e.event_id for e in ordered]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate event_id in correlation input (deduplicate at ingestion)")
    n = len(ordered)
    parent = list(range(n))
    edges: List[LinkEdge] = []
    examined = 0
    if cfg.mode != "baseline" and n:
        keys = [extract_keys(e, cfg) for e in ordered]
        dts = [e.event_dt for e in ordered]
        for i in range(n):
            for j in range(i + 1, n):
                delta = (dts[j] - dts[i]).total_seconds()
                if delta > cfg.window_seconds:
                    break
                examined += 1
                matched = _link(keys[i], keys[j], cfg)
                if matched:
                    ri, rj = _find(parent, i), _find(parent, j)
                    if ri != rj:
                        parent[max(ri, rj)] = min(ri, rj)
                    edges.append(LinkEdge(ids[i], ids[j], matched, delta))
    comp: Dict[int, List[int]] = {}
    for i in range(n):
        comp.setdefault(_find(parent, i), []).append(i)
    ordered_roots = sorted(comp, key=lambda r: min(comp[r]))
    width = max(3, len(str(len(ordered_roots))))
    group_ids, groups, group_of = [], [], {}
    for k, r in enumerate(ordered_roots, 1):
        gid = f"G{k:0{width}d}"
        members = [ids[i] for i in sorted(comp[r])]
        group_ids.append(gid)
        groups.append(members)
        for m in members:
            group_of[m] = gid
    return CorrelationResult(mode=cfg.mode, window_seconds=cfg.window_seconds, group_ids=group_ids,
                             groups=groups, group_of=group_of, edges=edges, n_events=n,
                             n_pairs_examined=examined)
