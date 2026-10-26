"""Evidence ingestion: read CloudTrail files, enforce the integrity gate, normalize, validate."""
from __future__ import annotations

import gzip
import json
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import integrity
from .normalizers import NORMALIZERS, NormalizationError
from .schema import CanonicalEvent, validate_event


class IngestionError(Exception):
    pass


@dataclass
class NormalizationFailure:
    source_log_file: str
    record_index: int
    reason: str


@dataclass
class IngestResult:
    scenario: str
    events: List[CanonicalEvent] = field(default_factory=list)
    failures: List[NormalizationFailure] = field(default_factory=list)
    duplicates: List[Dict[str, Any]] = field(default_factory=list)
    verification: List[integrity.VerificationResult] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    n_records_read: int = 0
    manifest: Dict[str, Any] = field(default_factory=dict)

    @property
    def integrity_ok(self) -> bool:
        return all(v.status == "OK" for v in self.verification)


def read_cloudtrail_file(path) -> List[Any]:
    """Return the ``Records`` list of a CloudTrail log file (.json or .json.gz)."""
    path = Path(path)
    try:
        raw = gzip.decompress(path.read_bytes()) if integrity.is_gzip_name(path) else path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, EOFError, zlib.error, gzip.BadGzipFile) as exc:
        raise IngestionError(f"cannot read {path}: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IngestionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("Records"), list):
        raise IngestionError(f"{path}: expected an object with a 'Records' list")
    return data["Records"]


def ingest_scenario(raw_root, scenario: str, manifest_path, *, provider: str = "aws",
                    strict_integrity: bool = True, deduplicate: bool = True) -> IngestResult:
    raw_root = Path(raw_root)
    if provider not in NORMALIZERS:
        raise IngestionError(f"no normalizer for provider {provider!r}")
    try:
        manifest = integrity.load_manifest(manifest_path)
    except integrity.ManifestError as exc:
        raise IngestionError(str(exc)) from exc
    res = IngestResult(scenario=scenario, manifest=manifest)
    res.verification = integrity.verify_manifest(raw_root, manifest, scenario)
    problems = [v for v in res.verification if v.status != "OK"]
    if problems and strict_integrity:
        detail = "; ".join(f"{v.filename}: {v.status}" for v in problems)
        raise integrity.IntegrityError(f"integrity gate failed for {scenario}: {detail}")

    hash_by_file = {e["filename"]: integrity.canonical_hash(e) for e in manifest["entries"]}
    actual_by_file = {v.filename: v.actual for v in res.verification if v.status == "UNMANIFESTED"}
    normalize = NORMALIZERS[provider]
    seen: Dict[str, str] = {}

    names = sorted(set(hash_by_file) | set(actual_by_file))
    for rel in names:
        path = raw_root / rel
        if not path.is_file():
            continue
        evidence_hash = hash_by_file.get(rel) or actual_by_file[rel]
        records = read_cloudtrail_file(path)
        res.files.append(rel)
        for idx, rec in enumerate(records):
            res.n_records_read += 1
            try:
                ev = normalize(rec, source_log_file=rel, record_index=idx, evidence_hash=evidence_hash)
            except NormalizationError as exc:
                res.failures.append(NormalizationFailure(rel, idx, str(exc)))
                continue
            problems_ev = validate_event(ev)
            if problems_ev:
                res.failures.append(NormalizationFailure(rel, idx, "schema: " + "; ".join(problems_ev)))
                continue
            if deduplicate and ev.event_id in seen:
                res.duplicates.append({"event_id": ev.event_id, "kept": seen[ev.event_id],
                                       "dropped": ev.raw_event_ref})
                continue
            seen[ev.event_id] = ev.raw_event_ref
            res.events.append(ev)
    return res
