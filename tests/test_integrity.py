import gzip
import hashlib
import json
import os
import unittest
from pathlib import Path
from unittest import mock

from cffc import integrity
from .helpers import TmpDirMixin, cloudtrail_record, write_ct_file


class HashingTests(TmpDirMixin, unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(integrity.hash_bytes(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(integrity.hash_bytes(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        p = self.tmp / "abc.bin"; p.write_bytes(b"abc")
        self.assertEqual(integrity.hash_file(p), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_chunk_boundaries_match_hashlib(self):
        for size in (0, 1, 65535, 65536, 65537, 200000):
            p = self.tmp / f"f{size}"; data = os.urandom(size); p.write_bytes(data)
            self.assertEqual(integrity.hash_file(p), hashlib.sha256(data).hexdigest(), size)

    def test_decompressed_hash(self):
        p = write_ct_file(self.tmp / "x.json.gz", [cloudtrail_record()])
        self.assertEqual(integrity.hash_decompressed(p), integrity.hash_bytes(gzip.decompress(p.read_bytes())))
        self.assertNotEqual(integrity.hash_decompressed(p), integrity.hash_file(p))


class ManifestTests(TmpDirMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.raw = self.tmp / "raw"
        write_ct_file(self.raw / "s" / "a.json.gz", [cloudtrail_record("A"), cloudtrail_record("B")])
        write_ct_file(self.raw / "s" / "b.json", [cloudtrail_record("C")], gz=False)
        self.mpath = self.tmp / "m" / "s_manifest.json"

    def test_build_and_verify_ok(self):
        m = integrity.build_manifest_for_directory(self.raw, "s", self.mpath, "tester")
        self.assertEqual(len(m["entries"]), 2)
        gz = next(e for e in m["entries"] if e["filename"].endswith(".gz"))
        plain = next(e for e in m["entries"] if not e["filename"].endswith(".gz"))
        self.assertRegex(gz["sha256_gz"], r"^[a-f0-9]{64}$")
        self.assertIsNone(plain["sha256_gz"])
        self.assertEqual(integrity.canonical_hash(plain), plain["sha256_json"])
        self.assertTrue(all(r.status == "OK" for r in integrity.verify_manifest(self.raw, m, "s")))

    def test_verify_detects_mismatch_missing_unmanifested(self):
        m = integrity.build_manifest_for_directory(self.raw, "s", self.mpath, "tester")
        (self.raw / "s" / "b.json").write_text('{"Records": []}')
        (self.raw / "s" / "a.json.gz").unlink()
        write_ct_file(self.raw / "s" / "new.json.gz", [cloudtrail_record("Z")])
        st = {r.filename: r.status for r in integrity.verify_manifest(self.raw, m, "s")}
        self.assertEqual(st["s/b.json"], "MISMATCH")
        self.assertEqual(st["s/a.json.gz"], "MISSING_FILE")
        self.assertEqual(st["s/new.json.gz"], "UNMANIFESTED")

    def test_append_only(self):
        integrity.build_manifest_for_directory(self.raw, "s", self.mpath, "tester")
        before = json.loads(self.mpath.read_text())
        integrity.build_manifest_for_directory(self.raw, "s", self.mpath, "tester")   # identical re-run: no-op
        self.assertEqual(json.loads(self.mpath.read_text())["entries"], before["entries"])
        (self.raw / "s" / "b.json").write_text('{"Records": [1]}')
        with self.assertRaises(integrity.ManifestError):
            integrity.build_manifest_for_directory(self.raw, "s", self.mpath, "tester")
        self.assertEqual(json.loads(self.mpath.read_text())["entries"], before["entries"])

    def test_new_files_are_appended(self):
        integrity.build_manifest_for_directory(self.raw, "s", self.mpath, "tester")
        write_ct_file(self.raw / "s" / "c.json.gz", [cloudtrail_record("N")])
        m = integrity.build_manifest_for_directory(self.raw, "s", self.mpath, "tester")
        self.assertEqual(len(m["entries"]), 3)

    def test_malformed_manifest_rejected(self):
        self.mpath.parent.mkdir(parents=True)
        self.mpath.write_text("{not json")
        with self.assertRaises(integrity.ManifestError):
            integrity.load_manifest(self.mpath)
        self.mpath.write_text(json.dumps({"entries": [{"filename": "x", "sha256_json": "zz"}]}))
        with self.assertRaises(integrity.ManifestError):
            integrity.load_manifest(self.mpath)
        with self.assertRaises(integrity.ManifestError):
            integrity.load_manifest(self.tmp / "nope.json")


class TamperTests(TmpDirMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.raw = self.tmp / "raw"
        recs = [cloudtrail_record("A", t="2026-01-15T09:00:00Z"), cloudtrail_record("B", t="2026-01-15T09:00:05Z")]
        write_ct_file(self.raw / "s" / "a.json.gz", recs)
        write_ct_file(self.raw / "s" / "b.json", recs, gz=False)
        self.m = integrity.build_manifest_for_directory(self.raw, "s", self.tmp / "m.json", "tester")
        self.items = [(self.raw / e["filename"], e) for e in self.m["entries"]]
        self.scratch = self.tmp / "scratch"

    def test_all_three_modifications_detected_gz_and_plain(self):
        rep = integrity.run_tamper_suite(self.items, self.scratch, self.tmp / "rep.json")
        self.assertEqual(rep["modifications_attempted"], 6)
        self.assertEqual(rep["modifications_detected"], 6)
        self.assertEqual(rep["tamper_detection_rate"], 1.0)
        self.assertEqual({r["modification_type"] for r in rep["results"]}, set(integrity.MODIFICATION_TYPES))
        self.assertTrue((self.tmp / "rep.json").is_file())

    def test_originals_untouched_and_scratch_clean(self):
        before = {p: integrity.hash_file(p) for p, _ in self.items}
        integrity.run_tamper_suite(self.items, self.scratch)
        self.assertEqual(before, {p: integrity.hash_file(p) for p, _ in self.items})
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_modifications_really_change_semantics(self):
        stored = (self.raw / "s" / "a.json.gz").read_bytes()
        orig = json.loads(gzip.decompress(stored))
        edited = json.loads(gzip.decompress(integrity.apply_modification(stored, "field_edit", True)))
        self.assertNotEqual(orig["Records"][0]["sourceIPAddress"], edited["Records"][0]["sourceIPAddress"])
        swapped = json.loads(gzip.decompress(integrity.apply_modification(stored, "line_reorder", True)))
        self.assertEqual([r["eventName"] for r in swapped["Records"]], ["B", "A"])
        truncated = integrity.apply_modification(stored, "byte_truncation", True)
        self.assertEqual(len(truncated), len(stored) - 16)
        with self.assertRaises(Exception):
            gzip.decompress(truncated)

    def test_refuses_when_original_already_differs_from_manifest(self):
        p, e = self.items[0]
        p.write_bytes(p.read_bytes() + b"x")
        with self.assertRaises(integrity.IntegrityError):
            integrity.run_tamper_test(p, e, self.scratch)

    def test_scratch_inside_evidence_dir_rejected(self):
        p, e = self.items[0]
        with self.assertRaises(integrity.TamperTestError):
            integrity.run_tamper_test(p, e, p.parent)

    def test_unmodifiable_inputs_raise(self):
        single = write_ct_file(self.raw / "s2" / "one.json.gz", [cloudtrail_record("A")])
        e = integrity.build_entry(single, "s2/one.json.gz")
        with self.assertRaises(integrity.TamperTestError):   # line_reorder needs >= 2 records
            integrity.run_tamper_test(single, e, self.scratch)

    def test_detector_reports_false_when_nothing_was_modified(self):
        """Negative control: if the 'modification' is a no-op, detection must be False.
        Without this, an implementation that always answers 'detected' would pass every test."""
        noop = lambda stored, mod_type, gz, truncate_bytes=16: stored
        with mock.patch.object(integrity, "apply_modification", noop):
            for p, e in self.items:
                results = integrity.run_tamper_test(p, e, self.scratch)
                self.assertEqual([r["detected"] for r in results], [False, False, False], p.name)
            rep = integrity.run_tamper_suite(self.items, self.scratch)
        self.assertEqual(rep["tamper_detection_rate"], 0.0)

    def test_unmodified_file_is_not_flagged(self):
        """Negative control: re-hashing an untouched file matches its manifest hash."""
        for p, e in self.items:
            self.assertEqual(integrity.hash_file(p), integrity.canonical_hash(e))


if __name__ == "__main__":
    unittest.main()
