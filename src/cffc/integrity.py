"""SHA-256 evidence hashing, append-only manifests, verification, tamper testing.

Scope (Stage 3.5 §A.5): tamper-EVIDENCE from the moment of hashing forward. This module does
NOT establish pre-collection integrity, completeness, or legal chain-of-custody.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .timeutil import utc_now_str

CHUNK_SIZE = 65536
MANIFEST_SCHEMA_VERSION = "1.0"
MODIFICATION_TYPES = ("field_edit", "byte_truncation", "line_reorder")


class IntegrityError(Exception):
    pass


class ManifestError(Exception):
    pass


class TamperTestError(Exception):
    pass


# ----------------------------------------------------------------------------- hashing
def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path) -> str:
    """SHA-256 of the file's bytes, streamed in 64 KB chunks (Stage 3.5 §A.1)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def is_gzip_name(path) -> bool:
    return str(path).lower().endswith(".gz")


def hash_decompressed(path) -> str:
    """SHA-256 of the decompressed content (== hash_file for non-gzip files)."""
    if not is_gzip_name(path):
        return hash_file(path)
    h = hashlib.sha256()
    with gzip.open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ----------------------------------------------------------------------------- manifest
def canonical_hash(entry: Dict[str, Any]) -> str:
    """Canonical evidence hash = hash of the as-delivered bytes (sha256_gz if gzip, else sha256_json)."""
    return entry.get("sha256_gz") or entry["sha256_json"]


def build_entry(path, rel_name: str, collected_at_utc: Optional[str] = None) -> Dict[str, Any]:
    path = Path(path)
    gz = is_gzip_name(path)
    size = path.stat().st_size
    entry: Dict[str, Any] = {
        "filename": rel_name.replace(os.sep, "/"),
        "sha256_gz": hash_file(path) if gz else None,
        "sha256_json": hash_decompressed(path),
        "file_size_bytes_gz": size if gz else None,
        "file_size_bytes_json": size if not gz else _decompressed_size(path),
        "collected_at_utc": collected_at_utc or utc_now_str(),
        "cloudtrail_validation_digest_available": False,
        "cloudtrail_validation_result": None,
    }
    return entry


def _decompressed_size(path) -> int:
    n = 0
    with gzip.open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                return n
            n += len(chunk)


def load_manifest(path) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            m = json.load(f)
    except FileNotFoundError as exc:
        raise ManifestError(f"manifest not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"manifest is not valid JSON: {path}: {exc}") from exc
    if not isinstance(m, dict) or not isinstance(m.get("entries"), list):
        raise ManifestError(f"manifest malformed (no 'entries' list): {path}")
    seen = set()
    for e in m["entries"]:
        if not isinstance(e, dict) or "filename" not in e or not (e.get("sha256_gz") or e.get("sha256_json")):
            raise ManifestError(f"manifest entry malformed: {e!r}")
        if e["filename"] in seen:
            raise ManifestError(f"duplicate manifest entry: {e['filename']}")
        seen.add(e["filename"])
        h = canonical_hash(e)
        if not re.fullmatch(r"[a-f0-9]{64}", h):
            raise ManifestError(f"manifest entry has invalid hash: {e['filename']}")
    return m


def write_manifest(path, manifest: Dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def append_entries(manifest_path, scenario: str, collector: str, entries: Iterable[Dict[str, Any]],
                   created_at_utc: Optional[str] = None) -> Dict[str, Any]:
    """Append-only update. Existing entries are never modified; a conflicting re-hash raises."""
    manifest_path = Path(manifest_path)
    if manifest_path.exists():
        manifest = load_manifest(manifest_path)
    else:
        manifest = {"schema_version": MANIFEST_SCHEMA_VERSION, "scenario": scenario,
                    "created_at_utc": created_at_utc or utc_now_str(), "collector": collector, "entries": []}
    by_name = {e["filename"]: e for e in manifest["entries"]}
    for new in entries:
        old = by_name.get(new["filename"])
        if old is None:
            manifest["entries"].append(new)
            by_name[new["filename"]] = new
        elif canonical_hash(old) != canonical_hash(new):
            raise ManifestError(
                f"append-only violation: {new['filename']} already recorded with a different hash")
    write_manifest(manifest_path, manifest)
    return manifest


def list_evidence_files(directory) -> List[Path]:
    d = Path(directory)
    if not d.is_dir():
        return []
    return sorted(p for p in d.rglob("*") if p.is_file() and p.name.lower().endswith((".json", ".json.gz")))


def build_manifest_for_directory(raw_root, scenario: str, manifest_path, collector: str,
                                 collected_at_utc: Optional[str] = None) -> Dict[str, Any]:
    raw_root = Path(raw_root)
    files = list_evidence_files(raw_root / scenario)
    if not files:
        raise ManifestError(f"no evidence files under {raw_root / scenario}")
    entries = [build_entry(p, p.relative_to(raw_root).as_posix(), collected_at_utc) for p in files]
    return append_entries(manifest_path, scenario, collector, entries, collected_at_utc)


@dataclass
class VerificationResult:
    filename: str
    status: str            # OK | MISMATCH | MISSING_FILE | UNMANIFESTED
    expected: Optional[str]
    actual: Optional[str]


def verify_manifest(raw_root, manifest: Dict[str, Any], scenario: Optional[str] = None) -> List[VerificationResult]:
    raw_root = Path(raw_root)
    scenario = scenario or manifest.get("scenario")
    results: List[VerificationResult] = []
    known = set()
    for e in manifest["entries"]:
        known.add(e["filename"])
        p = raw_root / e["filename"]
        if not p.is_file():
            results.append(VerificationResult(e["filename"], "MISSING_FILE", canonical_hash(e), None))
            continue
        actual = hash_file(p)
        status = "OK" if actual == canonical_hash(e) else "MISMATCH"
        results.append(VerificationResult(e["filename"], status, canonical_hash(e), actual))
    for p in list_evidence_files(raw_root / scenario) if scenario else []:
        rel = p.relative_to(raw_root).as_posix()
        if rel not in known:
            results.append(VerificationResult(rel, "UNMANIFESTED", None, hash_file(p)))
    return results


# ----------------------------------------------------------------------------- tamper testing
_IP_RE = re.compile(rb'("sourceIPAddress"\s*:\s*")([^"]+)(")')
_NAME_RE = re.compile(rb'("eventName"\s*:\s*")([^"]+)(")')


def _flip_last_char(value: bytes) -> bytes:
    last = value[-1:]
    repl = bytes([(int(last) + 1) % 10 + 48]) if last.isdigit() else b"x"
    if repl == last:
        repl = b"y"
    return value[:-1] + repl


def _edit_field(payload: bytes) -> bytes:
    for rx in (_IP_RE, _NAME_RE):
        m = rx.search(payload)
        if m:
            return payload[:m.start(2)] + _flip_last_char(m.group(2)) + payload[m.end(2):]
    raise TamperTestError("no sourceIPAddress/eventName field found to edit")


def _swap_records(payload: bytes) -> bytes:
    data = json.loads(payload.decode("utf-8"))
    recs = data.get("Records") if isinstance(data, dict) else None
    if not isinstance(recs, list) or len(recs) < 2 or recs[0] == recs[1]:
        raise TamperTestError("line_reorder needs >=2 distinct records")
    recs[0], recs[1] = recs[1], recs[0]
    return json.dumps(data, separators=(",", ":")).encode("utf-8")


def apply_modification(stored: bytes, mod_type: str, gz: bool, truncate_bytes: int = 16) -> bytes:
    if mod_type == "byte_truncation":
        if len(stored) <= truncate_bytes:
            raise TamperTestError("file too small to truncate")
        return stored[:-truncate_bytes]
    payload = gzip.decompress(stored) if gz else stored
    if mod_type == "field_edit":
        out = _edit_field(payload)
    elif mod_type == "line_reorder":
        out = _swap_records(payload)
    else:
        raise TamperTestError(f"unknown modification type: {mod_type}")
    return gzip.compress(out, mtime=0) if gz else out


def _safe_content_hash(path) -> Optional[str]:
    try:
        return hash_decompressed(path)
    except (OSError, EOFError, zlib.error, gzip.BadGzipFile):
        return None


def run_tamper_test(original_path, entry: Dict[str, Any], scratch_dir) -> List[Dict[str, Any]]:
    """Apply each modification to a COPY in ``scratch_dir`` and check the hash mismatch.

    Detection basis: for field_edit / line_reorder the *decompressed-content* hash is compared
    (re-compressing a gzip file changes its bytes even when nothing was edited, so comparing
    the gzip bytes would make detection trivially true). For byte_truncation the as-stored
    bytes hash is compared. A control (unmodified copy + no-op recompression) must hash
    identically first; otherwise the test is invalid and raises.
    """
    original_path, scratch_dir = Path(original_path), Path(scratch_dir)
    scratch_dir.mkdir(parents=True, exist_ok=True)
    if original_path.resolve().parent in scratch_dir.resolve().parents or \
            scratch_dir.resolve() == original_path.resolve().parent:
        raise TamperTestError("scratch_dir must not be the evidence directory")
    gz = is_gzip_name(original_path)
    stored = original_path.read_bytes()
    canonical = canonical_hash(entry)
    content_ref = entry["sha256_json"]
    if hash_bytes(stored) != canonical:
        raise IntegrityError(f"{original_path} does not match its manifest hash; refusing tamper test")

    suffix = ".json.gz" if gz else ".json"
    ctl = scratch_dir / f"control_copy{suffix}"
    ctl.write_bytes(stored)
    control_copy_ok = hash_file(ctl) == canonical
    payload = gzip.decompress(stored) if gz else stored
    control_recompress_ok = hash_bytes(payload) == content_ref and (
        hash_bytes(gzip.decompress(gzip.compress(payload, mtime=0))) == content_ref)
    ctl.unlink()
    if not (control_copy_ok and control_recompress_ok):
        raise TamperTestError("control checks failed; tamper test invalid")

    results = []
    for mod in MODIFICATION_TYPES:
        modified = apply_modification(stored, mod, gz)
        cp = scratch_dir / f"{mod}_copy{suffix}"
        cp.write_bytes(modified)
        post_canonical = hash_file(cp)
        post_content = _safe_content_hash(cp)
        content_changed = post_content is None or post_content != content_ref
        canonical_changed = post_canonical != canonical
        detected = canonical_changed if mod == "byte_truncation" else content_changed
        results.append({
            "file": entry["filename"], "modification_type": mod,
            "original_hash": canonical, "post_modification_hash": post_canonical,
            "original_content_hash": content_ref, "post_content_hash": post_content,
            "detected": bool(detected), "control_ok": True,
        })
        cp.unlink()
    if hash_file(original_path) != canonical:
        raise IntegrityError("original evidence file changed during tamper test (must never happen)")
    return results


def run_tamper_suite(items: Sequence[Tuple[Path, Dict[str, Any]]], scratch_dir, report_path=None) -> Dict[str, Any]:
    all_results: List[Dict[str, Any]] = []
    for path, entry in items:
        all_results.extend(run_tamper_test(path, entry, scratch_dir))
    attempted = len(all_results)
    detected = sum(1 for r in all_results if r["detected"])
    report = {
        "files_tested": len(items), "modifications_attempted": attempted,
        "modifications_detected": detected,
        "tamper_detection_rate": (detected / attempted) if attempted else None,
        "results": all_results,
        "scope_note": ("Implementation-correctness check of byte-level tamper evidence only; it does not "
                       "test pre-collection alteration, manifest forgery, or legal chain-of-custody."),
    }
    if report_path is not None:
        Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    return report
