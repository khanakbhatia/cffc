import random
import unittest

from cffc import metrics
from cffc.matching import MatchResult
from cffc.ground_truth import load_ground_truth
from .helpers import TmpDirMixin, ev, gt_dict, write_gt


class PairMetricTests(unittest.TestCase):
    """Hand-computed example (verified on paper):
       algo groups  A={e1,e2,e3}  B={e4,e5}  C={e6};  truth T1={e1,e2} T2={e3,e4} T3={e5,e6}
       algo pairs = 3+1 = 4, truth pairs = 3, TP = 1 (e1,e2)  ->  FP=3, FN=2
       P = 1/4, R = 1/3, F1 = 2/7, FCR = 3/4
    """
    algo = {"e1": "A", "e2": "A", "e3": "A", "e4": "B", "e5": "B", "e6": "C"}
    truth = {"e1": "T1", "e2": "T1", "e3": "T2", "e4": "T2", "e5": "T3", "e6": "T3"}

    def test_hand_computed_values(self):
        c = metrics.pair_counts(self.algo, self.truth, "labeled_only")
        self.assertEqual(c, {"tp": 1, "fp": 3, "fn": 2, "algo_pairs": 4, "true_pairs": 3})
        s = metrics.correlation_scores(c)
        self.assertAlmostEqual(s["precision"], 0.25)
        self.assertAlmostEqual(s["recall"], 1 / 3)
        self.assertAlmostEqual(s["f1"], 2 / 7)
        self.assertAlmostEqual(s["false_correlation_rate"], 0.75)
        self.assertAlmostEqual(s["false_correlation_rate"], 1 - s["precision"])

    def test_scopes_with_unlabeled_events(self):
        algo = {"e1": "A", "e2": "A", "u1": "A", "u2": "A"}
        truth = {"e1": "T1", "e2": "T1", "u1": None, "u2": None}
        # labeled_vs_unlabeled: pairs = C(2,2)+2*2 = 5, TP=1
        c = metrics.pair_counts(algo, truth, "labeled_vs_unlabeled")
        self.assertEqual((c["algo_pairs"], c["tp"], c["fp"]), (5, 1, 4))
        # all: unlabeled treated as singleton truth groups -> C(4,2)=6 pairs
        c = metrics.pair_counts(algo, truth, "all")
        self.assertEqual((c["algo_pairs"], c["tp"], c["fp"]), (6, 1, 5))
        c = metrics.pair_counts(algo, truth, "labeled_only")
        self.assertEqual((c["algo_pairs"], c["tp"], c["fp"]), (1, 1, 0))
        with self.assertRaises(ValueError):
            metrics.pair_counts(algo, truth, "nope")

    def test_closed_form_equals_brute_force(self):
        rng = random.Random(11)
        for _ in range(200):
            n = rng.randint(0, 30)
            ids = [f"e{i}" for i in range(n)]
            algo = {i: f"A{rng.randint(0, 6)}" for i in ids}
            truth = {i: rng.choice([None, None, "T1", "T2", "T3"]) for i in ids}
            for scope in metrics.PAIR_SCOPES:
                self.assertEqual(metrics.pair_counts(algo, truth, scope),
                                 metrics.brute_force_pair_counts(algo, truth, scope), (scope, algo, truth))

    def test_zero_division_guards(self):
        singletons = {"a": "G1", "b": "G2", "c": "G3"}
        truth = {"a": "T", "b": "T", "c": None}
        c = metrics.pair_counts(singletons, truth, "labeled_vs_unlabeled")
        s = metrics.correlation_scores(c)
        self.assertIsNone(s["precision"]); self.assertIsNone(s["f1"]); self.assertIsNone(s["false_correlation_rate"])
        self.assertEqual(s["recall"], 0.0)       # truth has a pair, none was linked: recall is defined = 0
        none_true = metrics.correlation_scores(metrics.pair_counts({"a": "G", "b": "G"}, {"a": "T1", "b": "T2"}))
        self.assertEqual(none_true["precision"], 0.0)
        self.assertIsNone(none_true["recall"])   # no truth pairs -> undefined
        self.assertIsNone(none_true["f1"])

    def test_f1_zero_when_p_and_r_zero(self):
        c = metrics.pair_counts({"a": "G", "b": "G", "c": "H", "d": "H"}, {"a": "T1", "c": "T1", "b": "T2", "d": "T2"}, "labeled_only")
        s = metrics.correlation_scores(c)
        self.assertEqual((s["precision"], s["recall"], s["f1"]), (0.0, 0.0, 0.0))

    def test_perfect_correlation(self):
        s = metrics.correlation_scores(metrics.pair_counts({"a": "G", "b": "G"}, {"a": "T", "b": "T"}))
        self.assertEqual((s["precision"], s["recall"], s["f1"], s["false_correlation_rate"]), (1.0, 1.0, 1.0, 0.0))


class TimelineMetricTests(TmpDirMixin, unittest.TestCase):
    def gt(self, n=4):
        steps = [{"step_id": i, "wall_clock_time_utc": f"2026-01-15T09:00:{i:02d}Z", "expected_event_name": "A",
                  "expected_correlation_group_id": "g1", "is_attack_related": True} for i in range(1, n + 1)]
        return load_ground_truth(write_gt(self.tmp / "g.json", steps=steps))

    def test_toa_hand_computed(self):
        r = metrics.timeline_ordering_accuracy(self.gt(), {1: 1, 2: 3, 3: 2, 4: 4})
        self.assertEqual((r["correct_pairs"], r["effective_denominator"], r["full_denominator"]), (2, 3, 3))
        self.assertAlmostEqual(r["value"], 2 / 3)
        self.assertEqual(r["misordered_adjacent_pairs"], [[2, 3]])

    def test_toa_reports_effective_denominator_when_events_missing(self):
        r = metrics.timeline_ordering_accuracy(self.gt(), {1: 1, 2: 2, 4: 3})
        self.assertEqual((r["effective_denominator"], r["full_denominator"], r["value"]), (1, 3, 1.0))

    def test_toa_undefined_without_adjacent_pairs(self):
        self.assertIsNone(metrics.timeline_ordering_accuracy(self.gt(), {1: 1, 3: 2})["value"])
        self.assertIsNone(metrics.timeline_ordering_accuracy(self.gt(1), {1: 1})["value"])

    def test_completeness_metrics(self):
        m = MatchResult({1: "a", 2: None, 3: "c", 4: None}, tolerance_seconds=30)
        cc = metrics.collection_completeness(m)
        self.assertEqual((cc["value"], cc["missing_steps"]), (0.5, [2, 4]))
        self.assertEqual(metrics.timeline_completeness(m)["value"], 0.5)
        self.assertIsNone(metrics.collection_completeness(MatchResult({}))["value"])

    def test_schema_coverage_hand_computed(self):
        full = ev("a", 0, ip="1.2.3.4", resource="r")                # 16/16
        sparse = ev("b", 0); sparse.source_ip = None; sparse.region = None; sparse.provider_specific = {}   # 16 - 3 -> resource None too
        r = metrics.schema_coverage([full, sparse])
        self.assertEqual((r["populated_fields"], r["possible_fields"]), (16 + 12, 32))
        self.assertAlmostEqual(r["value"], 28 / 32)
        self.assertIsNone(metrics.schema_coverage([])["value"])

    def test_tamper_rate_passthrough(self):
        r = metrics.tamper_detection_rate({"tamper_detection_rate": 1.0, "modifications_detected": 3, "modifications_attempted": 3})
        self.assertEqual((r["value"], r["detected"], r["attempted"]), (1.0, 3, 3))


if __name__ == "__main__":
    unittest.main()
