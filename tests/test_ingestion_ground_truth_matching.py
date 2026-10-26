import gzip
import json
import unittest

from cffc import integrity
from cffc.ground_truth import GroundTruthError, freeze_file, load_ground_truth
from cffc.ingestion import IngestionError, ingest_scenario, read_cloudtrail_file
from cffc.matching import Candidate, match_steps
from cffc.timeutil import parse_utc
from .helpers import TmpDirMixin, cloudtrail_record, gt_dict, write_ct_file, write_gt


class IngestionTests(TmpDirMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.raw = self.tmp / "raw"
        self.man = self.tmp / "m.json"

    def _build(self, records, name="a.json.gz"):
        write_ct_file(self.raw / "s" / name, records)
        integrity.build_manifest_for_directory(self.raw, "s", self.man, "tester")

    def test_happy_path_sets_evidence_hash_from_manifest(self):
        self._build([cloudtrail_record("A"), cloudtrail_record("B", t="2026-01-15T09:00:01Z")])
        res = ingest_scenario(self.raw, "s", self.man)
        self.assertEqual(len(res.events), 2)
        m = integrity.load_manifest(self.man)
        self.assertTrue(all(e.evidence_hash == integrity.canonical_hash(m["entries"][0]) for e in res.events))
        self.assertTrue(res.integrity_ok)
        self.assertEqual(res.events[1].raw_event_ref, "s/a.json.gz#1")

    def test_integrity_gate_blocks_modified_evidence(self):
        self._build([cloudtrail_record("A")])
        p = self.raw / "s" / "a.json.gz"
        p.write_bytes(gzip.compress(json.dumps({"Records": [cloudtrail_record("TAMPERED")]}).encode(), mtime=0))
        with self.assertRaises(integrity.IntegrityError):
            ingest_scenario(self.raw, "s", self.man)
        res = ingest_scenario(self.raw, "s", self.man, strict_integrity=False)
        self.assertFalse(res.integrity_ok)
        self.assertEqual(res.verification[0].status, "MISMATCH")

    def test_unmanifested_file_blocked_in_strict_mode(self):
        self._build([cloudtrail_record("A")])
        write_ct_file(self.raw / "s" / "extra.json.gz", [cloudtrail_record("X")])
        with self.assertRaises(integrity.IntegrityError):
            ingest_scenario(self.raw, "s", self.man)
        res = ingest_scenario(self.raw, "s", self.man, strict_integrity=False)
        self.assertEqual(len(res.events), 2)

    def test_bad_records_reported_not_dropped_silently(self):
        bad = cloudtrail_record("B"); del bad["eventTime"]
        self._build([cloudtrail_record("A"), bad, "oops"])
        res = ingest_scenario(self.raw, "s", self.man)
        self.assertEqual((len(res.events), len(res.failures), res.n_records_read), (1, 2, 3))
        self.assertEqual({f.record_index for f in res.failures}, {1, 2})

    def test_duplicate_event_ids(self):
        a = cloudtrail_record("A"); b = dict(a)
        self._build([a, b])
        res = ingest_scenario(self.raw, "s", self.man)
        self.assertEqual((len(res.events), len(res.duplicates)), (1, 1))
        res2 = ingest_scenario(self.raw, "s", self.man, deduplicate=False)
        self.assertEqual(len(res2.events), 2)

    def test_missing_manifest_and_bad_files(self):
        write_ct_file(self.raw / "s" / "a.json.gz", [cloudtrail_record("A")])
        with self.assertRaises(IngestionError):
            ingest_scenario(self.raw, "s", self.tmp / "none.json")
        (self.raw / "bad.json").write_text("{not json")
        with self.assertRaises(IngestionError):
            read_cloudtrail_file(self.raw / "bad.json")
        (self.raw / "norecords.json").write_text('{"x": 1}')
        with self.assertRaises(IngestionError):
            read_cloudtrail_file(self.raw / "norecords.json")
        (self.raw / "corrupt.json.gz").write_bytes(b"not gzip")
        with self.assertRaises(IngestionError):
            read_cloudtrail_file(self.raw / "corrupt.json.gz")


class GroundTruthTests(TmpDirMixin, unittest.TestCase):
    def test_valid_loads(self):
        gt = load_ground_truth(write_gt(self.tmp / "g.json"))
        self.assertEqual((gt.n_steps, gt.groups), (2, {"g1": [1, 2]}))
        self.assertEqual(len(gt.sha256), 64)

    def _expect_invalid(self, d, fragment, **kw):
        p = self.tmp / "bad.json"; p.write_text(json.dumps(d))
        with self.assertRaises(GroundTruthError) as cm:
            load_ground_truth(p, **kw)
        self.assertIn(fragment, str(cm.exception))

    def test_invalid_cases(self):
        self._expect_invalid(gt_dict(frozen=False), "not frozen")
        s = gt_dict()["steps"]
        self._expect_invalid(gt_dict(steps=[s[0], {**s[1], "step_id": 1}]), "duplicate step_id")
        self._expect_invalid(gt_dict(steps=[s[0], {**s[1], "wall_clock_time_utc": "2026-01-15T08:00:00Z"}]), "decreases")
        self._expect_invalid(gt_dict(steps=[s[0], {**s[1], "wall_clock_time_utc": "2026-01-15T09:00:10"}]), "bad wall_clock")
        self._expect_invalid(gt_dict(groups=[{"group_id": "g1", "member_step_ids": [1, 99]}]), "unknown step_id")
        self._expect_invalid(gt_dict(groups=[{"group_id": "g1", "member_step_ids": [1]}]), "not listed in members")
        self._expect_invalid(gt_dict(groups=[{"group_id": "gX", "member_step_ids": [1, 2]}]), "undeclared group")
        self._expect_invalid({"scenario": "x"}, "missing top-level key")
        self._expect_invalid(gt_dict(steps=[]), "non-empty")

    def test_unfrozen_allowed_when_not_required(self):
        p = write_gt(self.tmp / "g.json", frozen=False)
        self.assertFalse(load_ground_truth(p, require_frozen=False).frozen)

    def test_freeze_sets_read_only(self):
        p = write_gt(self.tmp / "g.json")
        self.assertFalse(load_ground_truth(p).read_only_on_disk)
        freeze_file(p)
        self.assertTrue(load_ground_truth(p).read_only_on_disk)

    def test_not_json(self):
        p = self.tmp / "x.json"; p.write_text("nope")
        with self.assertRaises(GroundTruthError):
            load_ground_truth(p)


class MatchingTests(TmpDirMixin, unittest.TestCase):
    def steps(self, spec):
        gt = gt_dict(steps=[{"step_id": i, "wall_clock_time_utc": t, "expected_event_name": n,
                             "expected_correlation_group_id": "g1", "is_attack_related": True, **extra}
                            for i, (t, n, extra) in enumerate(spec, 1)])
        return load_ground_truth(write_gt_raw(self.tmp, gt)).steps

    def test_tolerance_boundary_and_action_required(self):
        steps = self.steps([("2026-01-15T09:00:00Z", "A", {})])
        from datetime import timedelta
        base = parse_utc("2026-01-15T09:00:00Z")
        mk = lambda a, off: Candidate("c", a, base + timedelta(seconds=off), None, None)
        self.assertEqual(match_steps(steps, [mk("A", 30)], 30).n_matched, 1)
        self.assertEqual(match_steps(steps, [mk("A", 31)], 30).n_matched, 0)
        self.assertEqual(match_steps(steps, [mk("B", 0)], 30).n_matched, 0)

    def test_one_to_one_and_identity_preference(self):
        steps = self.steps([("2026-01-15T09:01:00Z", "ConsoleLogin", {"expected_principal": "bob"})])
        t = parse_utc("2026-01-15T09:01:00Z")
        from datetime import timedelta
        decoy = Candidate("decoy", "ConsoleLogin", t + timedelta(seconds=1), "carol", None)
        true = Candidate("true", "ConsoleLogin", t + timedelta(seconds=12), "bob", None)
        m = match_steps(steps, [decoy, true], 30)
        self.assertEqual(m.step_to_id[1], "true")
        self.assertEqual(m.ambiguous_steps, [1])

    def test_each_event_used_once(self):
        steps = self.steps([("2026-01-15T09:00:00Z", "A", {}), ("2026-01-15T09:00:05Z", "A", {})])
        t = parse_utc("2026-01-15T09:00:02Z")
        m = match_steps(steps, [Candidate("only", "A", t, None, None)], 30)
        self.assertEqual(m.n_matched, 1)
        self.assertEqual(len(m.missing_steps), 1)


def write_gt_raw(tmp, d):
    import itertools
    p = tmp / f"gt_{next(_c)}.json"
    p.write_text(json.dumps(d))
    return p


import itertools
_c = itertools.count()

if __name__ == "__main__":
    unittest.main()
