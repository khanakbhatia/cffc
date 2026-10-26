"""Shared test helpers. All data built here is hand-made synthetic test data."""
import gzip
import json
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cffc.config import load_config
from cffc.schema import CanonicalEvent
from cffc.synthetic import generate_synthetic_dataset
from cffc.timeutil import format_utc

REPO = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
HASH = "a" * 64


def ev(eid, offset, action="GetObject", principal="p1", ip=None, resource=None, idx=0, file="f1.json.gz",
       result="success"):
    return CanonicalEvent(
        event_id=eid, event_time_utc=format_utc(T0 + timedelta(seconds=offset)), cloud_provider="aws",
        cloud_service="s3.amazonaws.com", event_type="api_call", action=action, principal_id=principal,
        result=result, raw_event_ref=f"{file}#{idx}", source_log_file=file, evidence_hash=HASH,
        source_ip=ip, resource_id=resource, region="us-east-1", provider_specific={"k": 1})


def cloudtrail_record(name="GetObject", t="2026-01-15T09:00:00Z", **over):
    r = {"eventVersion": "1.08", "eventTime": t, "eventSource": "s3.amazonaws.com", "eventName": name,
         "awsRegion": "us-east-1", "sourceIPAddress": "198.51.100.1", "eventID": f"id-{name}-{t}",
         "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::000000000000:user/u1", "accountId": "000000000000"}}
    r.update(over)
    return r


def write_ct_file(path, records, gz=True):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"Records": records}).encode()
    path.write_bytes(gzip.compress(payload, mtime=0) if gz else payload)
    return path


def gt_dict(scenario="s", steps=None, groups=None, frozen=True):
    steps = steps if steps is not None else [
        {"step_id": 1, "wall_clock_time_utc": "2026-01-15T09:00:00Z", "expected_event_name": "A",
         "expected_correlation_group_id": "g1", "is_attack_related": True},
        {"step_id": 2, "wall_clock_time_utc": "2026-01-15T09:00:10Z", "expected_event_name": "B",
         "expected_correlation_group_id": "g1", "is_attack_related": True}]
    groups = groups if groups is not None else [{"group_id": "g1", "member_step_ids": [s["step_id"] for s in steps]}]
    return {"schema_version": "1.0", "scenario": scenario, "frozen": frozen, "steps": steps,
            "expected_correlation_groups": groups}


def write_gt(path, **kw):
    Path(path).write_text(json.dumps(gt_dict(**kw)))
    return path


class TmpDirMixin:
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()


def synthetic_copy(dest: Path) -> Path:
    generate_synthetic_dataset(dest)
    return dest


def cfg(**eval_over):
    c = load_config(REPO / "configs" / "default.toml")
    c["evaluation"].update(eval_over)
    return c
