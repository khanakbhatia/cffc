import random
import unittest

from cffc.correlation import CorrelationConfig, correlate, extract_keys
from cffc.timeline import annotate_with_ground_truth, reconstruct_timeline
from cffc.ground_truth import load_ground_truth
from .helpers import TmpDirMixin, ev, gt_dict, write_gt


def groups_of(res):
    return sorted(sorted(g) for g in res.groups)


def cfg(mode="or", window=300, **kw):
    return CorrelationConfig(mode=mode, window_seconds=window, **kw)


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        # a-b share principal, b-c share IP, d is unrelated
        self.events = [ev("a", 0, principal="p1", ip="198.51.100.1"), ev("b", 10, principal="p1", ip="198.51.100.2"),
                       ev("c", 20, principal="p2", ip="198.51.100.2"), ev("d", 30, principal="p3", ip="198.51.100.9")]

    def test_or_is_transitive(self):
        self.assertEqual(groups_of(correlate(self.events, cfg("or"))), [["a", "b", "c"], ["d"]])

    def test_and_requires_all_comparable_keys(self):
        self.assertEqual(groups_of(correlate(self.events, cfg("and"))), [["a"], ["b"], ["c"], ["d"]])
        same = [ev("a", 0, principal="p1", ip="198.51.100.1"), ev("b", 5, principal="p1", ip="198.51.100.1")]
        self.assertEqual(groups_of(correlate(same, cfg("and"))), [["a", "b"]])

    def test_and_resource_conflict_blocks_link(self):
        evs = [ev("a", 0, ip="198.51.100.1", resource="r1"), ev("b", 5, ip="198.51.100.1", resource="r2")]
        self.assertEqual(groups_of(correlate(evs, cfg("and"))), [["a"], ["b"]])
        evs = [ev("a", 0, ip="198.51.100.1", resource="r1"), ev("b", 5, ip="198.51.100.1", resource=None)]
        self.assertEqual(groups_of(correlate(evs, cfg("and"))), [["a", "b"]])   # resource not comparable

    def test_and_min_comparable_keys(self):
        evs = [ev("a", 0, principal="p1"), ev("b", 5, principal="p1")]    # only principal comparable
        self.assertEqual(groups_of(correlate(evs, cfg("and"))), [["a"], ["b"]])
        self.assertEqual(groups_of(correlate(evs, cfg("and", and_min_comparable_keys=1))), [["a", "b"]])
        self.assertEqual(groups_of(correlate(evs, cfg("or"))), [["a", "b"]])

    def test_baseline_never_links(self):
        res = correlate(self.events, cfg("baseline"))
        self.assertEqual(len(res.groups), 4)
        self.assertEqual(res.edges, [])

    def test_window_boundary_is_inclusive(self):
        evs = [ev("a", 0, principal="p1"), ev("b", 300, principal="p1"), ev("c", 601, principal="p1")]
        self.assertEqual(groups_of(correlate(evs, cfg("or", 300))), [["a", "b"], ["c"]])
        self.assertEqual(groups_of(correlate(evs, cfg("or", 299))), [["a"], ["b"], ["c"]])
        self.assertEqual(groups_of(correlate(evs, cfg("or", 0))), [["a"], ["b"], ["c"]])

    def test_null_and_sentinel_values_never_link(self):
        evs = [ev("a", 0, principal="unknown"), ev("b", 1, principal="unknown"),
               ev("c", 2, principal="UNKNOWN"), ev("d", 3, principal="HIDDEN_DUE_TO_SECURITY_REASONS"),
               ev("e", 4, principal="HIDDEN_DUE_TO_SECURITY_REASONS")]
        self.assertEqual(len(correlate(evs, cfg("or")).groups), 5)

    def test_non_ip_source_ignored_but_ips_normalized(self):
        evs = [ev("a", 0, principal="x", ip="ec2.amazonaws.com"), ev("b", 1, principal="y", ip="ec2.amazonaws.com")]
        self.assertEqual(len(correlate(evs, cfg("or")).groups), 2)
        self.assertEqual(len(correlate(evs, cfg("or", ignore_non_ip_source=False)).groups), 1)
        v6 = [ev("a", 0, principal="x", ip="2001:db8::1"), ev("b", 1, principal="y", ip="2001:0db8:0:0:0:0:0:1")]
        self.assertEqual(len(correlate(v6, cfg("or")).groups), 1)

    def test_edges_explain_links(self):
        res = correlate(self.events, cfg("or"))
        by_pair = {(e.a, e.b): e.matched_keys for e in res.edges}
        self.assertEqual(by_pair[("a", "b")], ("principal_id",))
        self.assertEqual(by_pair[("b", "c")], ("source_ip",))

    def test_order_independent_and_deterministic(self):
        shuffled = list(self.events); random.Random(1).shuffle(shuffled)
        r1, r2 = correlate(self.events, cfg("or")), correlate(shuffled, cfg("or"))
        self.assertEqual((r1.group_ids, r1.groups, r1.group_of), (r2.group_ids, r2.groups, r2.group_of))

    def test_duplicate_ids_rejected_and_empty_ok(self):
        with self.assertRaises(ValueError):
            correlate([ev("a", 0), ev("a", 1)], cfg())
        self.assertEqual(correlate([], cfg()).groups, [])

    def test_bad_config_rejected(self):
        for kw in ({"mode": "xor"}, {"window_seconds": -1}, {"and_min_comparable_keys": 0}):
            with self.assertRaises(ValueError):
                CorrelationConfig(**kw)

    def test_matches_naive_connected_components_on_random_data(self):
        rng = random.Random(7)
        for trial in range(25):
            n = rng.randint(2, 40)
            evs = [ev(f"e{i}", rng.randint(0, 900), principal=rng.choice(["p1", "p2", "p3", "unknown"]),
                      ip=rng.choice([None, "198.51.100.1", "198.51.100.2", "svc.amazonaws.com"]),
                      resource=rng.choice([None, "r1", "r2"]), idx=i) for i in range(n)]
            for mode in ("or", "and"):
                c = cfg(mode, rng.choice([0, 30, 300]))
                got = groups_of(correlate(evs, c))
                keys = {e.event_id: extract_keys(e, c) for e in evs}
                parent = {e.event_id: e.event_id for e in evs}

                def find(x):
                    while parent[x] != x:
                        x = parent[x]
                    return x
                for a in evs:
                    for b in evs:
                        if a.event_id < b.event_id and abs((a.event_dt - b.event_dt).total_seconds()) <= c.window_seconds:
                            comp = [k for k in keys[a.event_id] if keys[a.event_id][k] and keys[b.event_id][k]]
                            eq = [k for k in comp if keys[a.event_id][k] == keys[b.event_id][k]]
                            ok = bool(eq) if mode == "or" else (len(comp) >= 2 and len(eq) == len(comp))
                            if ok:
                                parent[find(a.event_id)] = find(b.event_id)
                comps = {}
                for e in evs:
                    comps.setdefault(find(e.event_id), []).append(e.event_id)
                self.assertEqual(got, sorted(sorted(v) for v in comps.values()), f"trial {trial} mode {mode}")


class TimelineTests(TmpDirMixin, unittest.TestCase):
    def test_baseline_is_chronological_with_delivery_tiebreak(self):
        evs = [ev("late", 50), ev("same_b", 10, idx=5), ev("same_a", 10, idx=2), ev("early", 0)]
        tl = reconstruct_timeline(evs, correlate(evs, cfg("baseline")))
        self.assertEqual(list(tl["event_id"]), ["early", "same_a", "same_b", "late"])
        self.assertEqual(list(tl["step_number"]), [1, 2, 3, 4])

    def test_groups_are_contiguous_and_ordered_by_first_member(self):
        evs = [ev("a1", 0, principal="A"), ev("x", 5, principal="X"), ev("a2", 10, principal="A"), ev("y", 15, principal="Y")]
        tl = reconstruct_timeline(evs, correlate(evs, cfg("or")))
        self.assertEqual(list(tl["event_id"]), ["a1", "a2", "x", "y"])
        self.assertEqual(list(tl["group_id"]), ["G001", "G001", "G002", "G003"])

    def test_every_event_appears_exactly_once(self):
        evs = [ev(f"e{i}", i * 7, principal=f"p{i % 3}", idx=i) for i in range(30)]
        tl = reconstruct_timeline(evs, correlate(evs, cfg("or")))
        self.assertEqual(sorted(tl["event_id"]), sorted(e.event_id for e in evs))

    def test_missing_rows_for_unmatched_ground_truth(self):
        gt = load_ground_truth(write_gt(self.tmp / "g.json", steps=[
            {"step_id": 1, "wall_clock_time_utc": "2026-01-15T09:00:00Z", "expected_event_name": "A",
             "expected_correlation_group_id": "g1", "is_attack_related": True},
            {"step_id": 2, "wall_clock_time_utc": "2026-01-15T09:00:10Z", "expected_event_name": "B",
             "expected_correlation_group_id": "g1", "is_attack_related": True}]))
        evs = [ev("e1", 0, action="A")]
        tl = reconstruct_timeline(evs, correlate(evs, cfg("or")))
        ann, match, positions = annotate_with_ground_truth(tl, gt, 30)
        self.assertEqual(positions, {1: 1})
        self.assertEqual(match.missing_steps, [2])
        self.assertEqual(list(ann["row_type"]), ["EVENT", "MISSING"])
        self.assertEqual(ann.iloc[1]["gt_step_id"], 2)


if __name__ == "__main__":
    unittest.main()
