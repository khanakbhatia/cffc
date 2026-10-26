import copy
import gzip
import json
import os
import shutil
import unittest
from pathlib import Path

from cffc import integrity
from cffc.cli import main as cli_main
from cffc.experiment import NoEvidenceError, ProvenanceError, read_provenance, run_experiments
from cffc.synthetic import generate_synthetic_dataset
from .helpers import REPO, TmpDirMixin, cfg



def tree_hashes(root):
    return {
        p.relative_to(root).as_posix(): integrity.hash_file(p)
        for p in sorted(Path(root).rglob("*"))
        if p.is_file()
    }



def semantic_tree_hashes(root):
    """Compare dataset content independently of JSON formatting and gzip metadata."""
    import hashlib

    root = Path(root)
    result = {}

    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue

        rel = p.relative_to(root).as_posix()

        if p.name.endswith(".json.gz"):
            content = gzip.decompress(p.read_bytes())

        elif p.suffix == ".json":
            obj = json.loads(p.read_text())

            if rel.startswith("manifests/"):
                for entry in obj.get("entries", []):
                    # These fields depend on the exact stored gzip representation.
                    entry.pop("sha256_gz", None)
                    entry.pop("file_size_bytes_gz", None)

            content = json.dumps(
                obj, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")

        else:
            content = p.read_bytes()

        result[rel] = hashlib.sha256(content).hexdigest()

    return result



class SyntheticGeneratorTests(TmpDirMixin, unittest.TestCase):
    def test_deterministic_and_matches_committed_data(self):
        a, b = self.tmp / "a", self.tmp / "b"
        generate_synthetic_dataset(a); generate_synthetic_dataset(b)
        self.assertEqual(tree_hashes(a), tree_hashes(b))
        self.assertEqual(
            semantic_tree_hashes(a),
            semantic_tree_hashes(REPO / "data" / "synthetic"),
)

    def test_provenance_marker_and_notice(self):
        generate_synthetic_dataset(self.tmp / "s")
        self.assertEqual(read_provenance(self.tmp / "s"), "synthetic")
        f = next((self.tmp / "s" / "raw").rglob("*.json.gz"))
        self.assertIn("SYNTHETIC", json.loads(gzip.decompress(f.read_bytes()))["_synthetic_notice"])

    def test_refuses_to_write_into_real_root(self):
        root = self.tmp / "real"; root.mkdir()
        (root / "PROVENANCE.json").write_text(json.dumps({"kind": "real"}))
        with self.assertRaises(RuntimeError):
            generate_synthetic_dataset(root)
        self.assertEqual(list(root.iterdir()), [root / "PROVENANCE.json"])

    def test_committed_manifests_verify(self):
        root = REPO / "data" / "synthetic"
        for sc in ("scenario_a", "scenario_b", "scenario_c"):
            m = integrity.load_manifest(root / "manifests" / f"{sc}_manifest.json")
            self.assertTrue(all(r.status == "OK" for r in integrity.verify_manifest(root / "raw", m, sc)))


class ExperimentRunnerTests(TmpDirMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile
        cls._t = tempfile.TemporaryDirectory()
        cls.data = Path(cls._t.name) / "data"
        generate_synthetic_dataset(cls.data)
        cls.out1 = run_experiments(cls.data, Path(cls._t.name) / "o1", cfg(), executor="test")
        cls.out2 = run_experiments(cls.data, Path(cls._t.name) / "o2", cfg(), executor="test")
        cls.gold = run_experiments(cls.data, Path(cls._t.name) / "o3", cfg(pair_scope="labeled_only"), executor="test")

    @classmethod
    def tearDownClass(cls):
        cls._t.cleanup()

    def by_run(self, out):
        return {r["run_id"]: r for r in out["results"]}

    def test_sixteen_runs_with_expected_ids(self):
        r = self.by_run(self.out1)
        self.assertEqual(sorted(r), [f"R{i:02d}" for i in range(1, 17)])
        self.assertEqual((r["R01"]["scenario"], r["R06"]["scenario"], r["R11"]["scenario"]), ("scenario_a", "scenario_b", "scenario_c"))
        self.assertEqual((r["R03"]["mode"], r["R04"]["time_window_seconds"], r["R05"]["time_window_seconds"]), ("baseline", 60, 900))
        self.assertEqual(r["R16"]["mode"], "tamper")

    def test_output_files_exist_and_are_partitioned_by_provenance(self):
        out = Path(self.out1["out_dir"])
        self.assertEqual(out.name, "synthetic")
        self.assertEqual(len(list((out / "results").glob("scenario_*_metrics.json"))), 15)
        for rel in ("tables/results_summary.csv", "tables/results_summary.md", "run_manifest.json",
                    "results/tamper_test_report.json", "figures/correlation_quality.png", "figures/window_sensitivity.png"):
            self.assertTrue((out / rel).is_file(), rel)
        self.assertEqual(len(list((out / "timelines").glob("*.csv"))), 15)

    def test_synthetic_outputs_are_stamped_everywhere(self):
        out = Path(self.out1["out_dir"])
        self.assertIn("NOT AWS EVIDENCE", (out / "tables" / "results_summary.md").read_text())
        for p in (out / "results").glob("scenario_*_metrics.json"):
            d = json.loads(p.read_text())
            self.assertEqual(d["data_provenance"], "synthetic")
            self.assertIn("SYNTHETIC", d["WARNING"])
        self.assertEqual(json.loads((out / "run_manifest.json").read_text())["data_provenance"], "synthetic")

    def test_metric_invariants(self):
        for r in self.out1["results"]:
            for k in ("schema_coverage", "collection_completeness", "correlation_precision", "correlation_recall", "f1_score",
                      "false_correlation_rate", "timeline_ordering_accuracy", "timeline_completeness", "tamper_detection_rate"):
                v = r[k]
                self.assertTrue(v is None or 0.0 <= v <= 1.0, (r["run_id"], k, v))
            self.assertEqual(r["details"].get("invariant_violations", []), [])
            if r["mode"] in ("or", "and"):
                self.assertAlmostEqual(r["false_correlation_rate"], 1 - r["correlation_precision"])
            if r["timeline_completeness"] is not None:
                self.assertLessEqual(r["timeline_completeness"], r["collection_completeness"] + 1e-12)

    def test_baseline_correlation_metrics_undefined_per_matrix(self):
        for rid in ("R03", "R08", "R13"):
            r = self.by_run(self.out1)[rid]
            for k in ("correlation_precision", "correlation_recall", "f1_score", "false_correlation_rate"):
                self.assertIsNone(r[k]); self.assertIn(k, r["undefined_metrics"])
            self.assertEqual(r["timeline_completeness"], 1.0)

    def test_tamper_run(self):
        r = self.by_run(self.out1)["R16"]
        self.assertEqual(r["tamper_detection_rate"], 1.0)
        self.assertEqual(r["details"]["tamper"]["attempted"], 18)     # 6 files x 3 modification types
        self.assertTrue(all(r[k] is None for k in ("schema_coverage", "correlation_precision", "timeline_completeness")))

    def test_synthetic_collection_completeness_is_one_by_construction(self):
        for r in self.out1["results"]:
            if r["mode"] in ("or", "and", "baseline"):
                self.assertEqual(r["collection_completeness"], 1.0)

    def test_deterministic_metrics_across_runs(self):
        strip = lambda r: {k: v for k, v in r.items() if k not in ("processing_time_seconds", "executed_at_utc")}
        a, b = self.by_run(self.out1), self.by_run(self.out2)
        for rid in a:
            self.assertEqual(strip(a[rid]), strip(b[rid]), rid)

    def test_hand_verified_golden_values_labeled_only_scope(self):
        """Expected values derived by hand from the scenario definitions in cffc/synthetic.py
        (noise events use other principals/IPs, so labeled_only isolates the scripted steps)."""
        r = self.by_run(self.gold)
        approx = lambda run, p, rc: (self.assertAlmostEqual(r[run]["correlation_precision"], p, msg=run),
                                     self.assertAlmostEqual(r[run]["correlation_recall"], rc, msg=run))
        approx("R01", 1.0, 1.0)          # A, OR 300: steps 2-4 share principal
        approx("R02", 1.0, 1 / 3)        # A, AND 300: only (2,4) share principal+IP; step 3 used another IP
        approx("R04", 1.0, 1.0)          # A, OR 60
        approx("R05", 1.0, 1.0)          # A, OR 900
        approx("R06", 0.6, 1.0)          # B, OR 300: step 1 (same principal, known IP) merges with the burst: 6 TP, 4 FP
        approx("R07", 1.0, 1.0)          # B, AND 300
        approx("R09", 1.0, 1.0)          # B, OR 60: step 1 is 120 s before the burst -> not linked
        approx("R10", 0.6, 1.0)          # B, OR 900
        approx("R11", 1.0, 1.0)          # C, OR 300
        approx("R12", 1.0, 0.4)          # C, AND 300: {1,2,3},{4,5} -> 4 of 10 pairs
        self.assertAlmostEqual(r["R12"]["f1_score"], 4 / 7)
        self.assertAlmostEqual(r["R06"]["f1_score"], 0.75)

    def test_same_second_collision_is_a_documented_limitation(self):
        # steps 3 and 4 of scenario_a share one eventTime second; AND-mode group-contiguous ordering also misorders (3,4)
        r = self.by_run(self.out1)["R02"]
        self.assertEqual(r["details"]["timeline_ordering"]["misordered_adjacent_pairs"], [[3, 4]])

    def test_refuses_unknown_provenance(self):
        d = self.tmp / "d"; d.mkdir()
        with self.assertRaises(ProvenanceError):
            run_experiments(d, self.tmp / "o", cfg())
        (d / "PROVENANCE.json").write_text(json.dumps({"kind": "maybe"}))
        with self.assertRaises(ProvenanceError):
            run_experiments(d, self.tmp / "o", cfg())

    def test_empty_real_data_runs_nothing_and_fabricates_nothing(self):
        with self.assertRaises(NoEvidenceError):
            run_experiments(REPO / "data" / "real", self.tmp / "o", cfg())
        self.assertFalse((self.tmp / "o" / "real").exists())
        self.assertEqual(cli_main(["run", "--data-root", str(REPO / "data" / "real"), "--out-root", str(self.tmp / "o2"),
                                   "--config", str(REPO / "configs" / "default.toml")]), 2)

    def test_integrity_gate_stops_run_on_modified_evidence(self):
        data = self.tmp / "d"; shutil.copytree(self.data, data)
        f = next((data / "raw" / "scenario_a").glob("*.json.gz"))
        f.write_bytes(f.read_bytes()[:-5])
        with self.assertRaises(integrity.IntegrityError):
            run_experiments(data, self.tmp / "o", cfg())

    def test_unfrozen_ground_truth_skips_scenario(self):
        data = self.tmp / "d"; shutil.copytree(self.data, data)
        p = data / "ground_truth" / "scenario_b_ground_truth.json"
        os.chmod(p, 0o644)
        d = json.loads(p.read_text()); d["frozen"] = False; p.write_text(json.dumps(d))
        out = run_experiments(data, self.tmp / "o", cfg())
        self.assertIn("scenario_b", out["manifest"]["scenarios_skipped"])
        self.assertEqual(sorted({r["scenario"] for r in out["results"]}), ["all", "scenario_a", "scenario_c"])

    def test_degraded_collection_lowers_cc_tc_and_uses_effective_denominator(self):
        data = self.tmp / "d"; shutil.copytree(self.data, data)
        for p in (data / "raw" / "scenario_c").glob("*.json.gz"):
            payload = json.loads(gzip.decompress(p.read_bytes()))
            kept = [r for r in payload["Records"] if r["eventName"] != "RunInstances"]
            if len(kept) != len(payload["Records"]):
                payload["Records"] = kept
                p.write_bytes(gzip.compress(json.dumps(payload, separators=(",", ":")).encode(), mtime=0))
        (data / "manifests" / "scenario_c_manifest.json").unlink()
        integrity.build_manifest_for_directory(data / "raw", "scenario_c", data / "manifests" / "scenario_c_manifest.json", "test")
        c = cfg(); c["experiments"]["scenarios"] = ["scenario_c"]
        out = run_experiments(data, self.tmp / "o", c)
        r = {x["run_id"]: x for x in out["results"]}["R01"]
        self.assertAlmostEqual(r["collection_completeness"], 0.8)
        self.assertAlmostEqual(r["timeline_completeness"], 0.8)
        self.assertEqual(r["details"]["collection_completeness"]["missing_steps"], [5])
        toa = r["details"]["timeline_ordering"]
        self.assertEqual((toa["effective_denominator"], toa["full_denominator"]), (3, 4))
        rows = (Path(out["out_dir"]) / "timelines" / "scenario_c_R01_timeline.csv").read_text()
        self.assertIn("MISSING", rows)


class CliTests(TmpDirMixin, unittest.TestCase):
    def test_validate_gt_and_verify_and_normalize(self):
        root = REPO / "data" / "synthetic"
        self.assertEqual(cli_main(["validate-gt", str(root / "ground_truth" / "scenario_a_ground_truth.json")]), 0)
        self.assertEqual(cli_main(["verify", "--data-root", str(root), "--scenario", "scenario_b"]), 0)
        out = self.tmp / "n.csv"
        self.assertEqual(cli_main(["normalize", "--data-root", str(root), "--scenario", "scenario_c", "--out", str(out)]), 0)
        self.assertEqual(len(out.read_text().strip().splitlines()), 22)   # header + 21 events
        bad = self.tmp / "bad.json"; bad.write_text("{}")
        self.assertEqual(cli_main(["validate-gt", str(bad)]), 1)

    def test_build_manifest_command(self):
        from .helpers import write_ct_file, cloudtrail_record
        write_ct_file(self.tmp / "raw" / "sx" / "a.json.gz", [cloudtrail_record()])
        self.assertEqual(cli_main(["build-manifest", "--data-root", str(self.tmp), "--scenario", "sx", "--collector", "t"]), 0)
        self.assertEqual(cli_main(["verify", "--data-root", str(self.tmp), "--scenario", "sx"]), 0)
        (self.tmp / "raw" / "sx" / "a.json.gz").write_bytes(b"changed")
        self.assertEqual(cli_main(["verify", "--data-root", str(self.tmp), "--scenario", "sx"]), 1)


if __name__ == "__main__":
    unittest.main()
