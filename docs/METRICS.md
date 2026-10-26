# Metric reference

Formal definitions, formulas and zero-division guards are specified in Stage 3.5 Part B and
implemented verbatim in `src/cffc/metrics.py` (pure functions, no I/O - see docstrings there for the
exact formulas). This page covers what is *not* already written down in Stage 3.5: scope choices and
worked examples. See also `docs/ASSUMPTIONS.md` A5-A7.

## Pair-counting scopes (A5)

Given an algorithm grouping and a (partial) ground-truth grouping over the same event set:

```
labeled_vs_unlabeled (default):  pairs among labeled events use ground truth;
                                  a labeled-unlabeled pair in the same algo group is a false positive;
                                  unlabeled-unlabeled pairs are excluded (no ground-truth claim either way)
labeled_only:                    only pairs where BOTH events are ground-truth-matched are counted
all:                             every unlabeled event is its own singleton "truth" group
```

`cffc.metrics.pair_counts` computes these in closed form (`comb(n, 2)` per group); `brute_force_pair_counts`
is an O(n²) reference used only by tests to cross-check the closed form (`test_closed_form_equals_brute_force`,
200 randomized trials).

## Worked example (also `PairMetricTests.test_hand_computed_values`)

Algorithm groups: `A={e1,e2,e3}`, `B={e4,e5}`, `C={e6}`. Ground truth: `T1={e1,e2}`, `T2={e3,e4}`, `T3={e5,e6}`.

- algo pairs = C(3,2) + C(2,2) = 3 + 1 = 4
- true pairs = C(2,2) × 3 = 3
- correct pairs (same algo group AND same truth group): only (e1,e2) → TP = 1
- **P = 1/4, R = 1/3, F1 = 2/7 ≈ 0.286, FCR = 3/4**

## Interpreting the experimental-matrix columns

`SC` schema coverage, `CC` collection completeness, `P/R/F1/FCR` correlation quality (undefined for the
baseline template, which performs no correlation), `TOA` timeline ordering accuracy, `TC` timeline
completeness (`TC ≤ CC` always; the runner checks this invariant and records a violation if it fails),
`TDR` tamper-detection rate (one run, not per scenario).

`undef` in a results table means the metric has no defined value for that run's configuration (e.g. P/R
for the baseline, which groups nothing). `—` means the cell was not computed for that run at all. Neither
is ever replaced by an estimated number.
