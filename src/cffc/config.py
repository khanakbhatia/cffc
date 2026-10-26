"""Configuration loading (TOML, stdlib tomllib; Python >= 3.11)."""
from __future__ import annotations

import copy
import tomllib
from pathlib import Path
from typing import Any, Dict

from .correlation import CorrelationConfig, MODES
from .metrics import PAIR_SCOPES

DEFAULTS: Dict[str, Any] = {
    "ingestion": {"strict_integrity": True, "deduplicate_event_ids": True},
    "correlation": {"ignore_non_ip_source": True,
                    "null_sentinels": ["unknown", "hidden_due_to_security_reasons", ""],
                    "and_min_comparable_keys": 2},
    "evaluation": {"gt_match_tolerance_seconds": 30.0, "pair_scope": "labeled_vs_unlabeled",
                   "require_frozen_ground_truth": True},
    "experiments": {"scenarios": ["scenario_a", "scenario_b", "scenario_c"], "templates": []},
}


class ConfigError(ValueError):
    pass


def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in over.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_config(path) -> Dict[str, Any]:
    with open(path, "rb") as f:
        cfg = _merge(DEFAULTS, tomllib.load(f))
    validate_config(cfg)
    return cfg


def validate_config(cfg: Dict[str, Any]) -> None:
    if cfg["evaluation"]["pair_scope"] not in PAIR_SCOPES:
        raise ConfigError(f"evaluation.pair_scope must be one of {PAIR_SCOPES}")
    if cfg["evaluation"]["gt_match_tolerance_seconds"] < 0:
        raise ConfigError("gt_match_tolerance_seconds must be >= 0")
    if not cfg["experiments"]["scenarios"]:
        raise ConfigError("experiments.scenarios must not be empty")
    if not cfg["experiments"]["templates"]:
        raise ConfigError("experiments.templates must define at least one run template")
    for t in cfg["experiments"]["templates"]:
        if t.get("mode") not in MODES:
            raise ConfigError(f"template {t.get('label')}: mode must be one of {MODES}")
        if t["mode"] != "baseline" and not isinstance(t.get("window_seconds"), (int, float)):
            raise ConfigError(f"template {t.get('label')}: window_seconds required for mode {t['mode']}")


def correlation_config(cfg: Dict[str, Any], mode: str, window_seconds) -> CorrelationConfig:
    c = cfg["correlation"]
    return CorrelationConfig(mode=mode, window_seconds=float(window_seconds or 0),
                             ignore_non_ip_source=c["ignore_non_ip_source"],
                             null_sentinels=tuple(c["null_sentinels"]),
                             and_min_comparable_keys=c["and_min_comparable_keys"])
