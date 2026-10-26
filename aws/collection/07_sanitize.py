#!/usr/bin/env python3
"""Sanitize raw evidence for release (Stage 2 §24 reproducibility plan: "after a manual pass to
strip real AWS account IDs/keys"). NEVER touches data/real/raw/ (the preserved originals) - reads
them, writes a redacted copy to data/real/sanitized/<scenario>/, and writes a report of what was
redacted for a human to review before anything is committed or shared.

This is a mechanical first pass, not a guarantee. A human must review the report and the output
before treating it as safe to share (docs/MANUAL_AWS_STEPS.md item 8).
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

PATTERNS = [
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "AKIAREDACTEDXXXXXXXX"),
    ("aws_secret_access_key_like", re.compile(r'"(?:SecretAccessKey|aws_secret_access_key)"\s*:\s*"[^"]{30,}"'),
     '"SecretAccessKey": "REDACTED"'),
    ("session_token_like", re.compile(r'"SessionToken"\s*:\s*"[^"]{50,}"'), '"SessionToken": "REDACTED"'),
]


def account_id_pattern(account_id: str):
    return re.compile(re.escape(account_id)), "ACCOUNTIDREDACTED"


def sanitize_text(text: str, account_id: str | None) -> tuple[str, dict]:
    counts: dict = {}
    for name, rx, repl in PATTERNS:
        text, n = rx.subn(repl, text)
        if n:
            counts[name] = counts.get(name, 0) + n
    if account_id:
        rx, repl = account_id_pattern(account_id)
        text, n = rx.subn(repl, text)
        if n:
            counts["account_id"] = counts.get("account_id", 0) + n
    return text, counts


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("scenario")
    p.add_argument("--account-id", help="your real AWS account ID, redacted everywhere it appears "
                                        "(omit to skip account-ID redaction and rely on key-pattern redaction only)")
    p.add_argument("--data-root", default=str(REPO_ROOT / "data" / "real"))
    a = p.parse_args()

    raw_dir = Path(a.data_root) / "raw" / a.scenario
    out_dir = Path(a.data_root) / "sanitized" / a.scenario
    if not raw_dir.is_dir() or not any(raw_dir.iterdir()):
        print(f"ERROR: {raw_dir} is empty or missing - nothing to sanitize.", file=sys.stderr)
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)

    report = {"scenario": a.scenario, "account_id_redacted": bool(a.account_id), "files": []}
    for src in sorted(raw_dir.rglob("*")):
        if not src.is_file():
            continue
        gz = src.name.endswith(".gz")
        raw_bytes = gzip.decompress(src.read_bytes()) if gz else src.read_bytes()
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            print(f"SKIPPED (not UTF-8 text): {src}", file=sys.stderr)
            continue
        sanitized, counts = sanitize_text(text, a.account_id)
        dest = out_dir / src.name
        dest.write_bytes(gzip.compress(sanitized.encode("utf-8"), mtime=0) if gz else sanitized.encode("utf-8"))
        report["files"].append({"file": src.name, "redaction_counts": counts})
        if counts:
            print(f"{src.name}: redacted {counts}")
        else:
            print(f"{src.name}: nothing matched (review manually anyway - this is a mechanical pass)")

    report_path = out_dir / "SANITIZATION_REPORT.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"\nWrote {len(report['files'])} sanitized file(s) to {out_dir}")
    print(f"Report: {report_path}")
    print("\n*** This is a mechanical first pass. A human must review every file in data/real/sanitized/")
    print("*** before it is committed, shared, or released, per Stage 2 §24. Account ID redaction only")
    print("*** ran if you passed --account-id; IAM access keys/secrets/session tokens are pattern-matched")
    print("*** regardless, but pattern matching cannot guarantee it caught everything sensitive.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
