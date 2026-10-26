# Data provenance policy

Every data root passed to the pipeline (`data/synthetic`, `data/real`, or any copy) must contain a
`PROVENANCE.json` with a top-level `"kind"` of `"synthetic"` or `"real"`. `cffc.experiment.run_experiments`
reads this before touching anything else and writes results to `outputs/<kind>/`, so synthetic test runs
and real research results can never land in the same folder or be silently confused.

- **`data/synthetic/`** is produced only by `cffc.synthetic.generate_synthetic_dataset` (fixed seed
  `20260115`, defined in `synthetic.py`). It exists to exercise the pipeline end-to-end and to give the
  test suite and this Stage 4 submission something concrete to run against. Every raw file carries a
  `_synthetic_notice` key; every generated table/figure/metrics JSON in `outputs/synthetic/` is stamped
  `"SYNTHETIC TEST DATA - NOT AWS EVIDENCE - NOT RESEARCH RESULTS"`. **These numbers must never be
  quoted in the paper as results** - they demonstrate the code runs correctly on data with a known
  answer baked in (collection completeness is 1.0 by construction, since the generator writes the
  ground truth from the same script that writes the events).
- **`data/real/`** is where the team's actual AWS CloudTrail evidence goes once collected per Stage 2
  §11/§12 (multi-region CloudTrail, log file validation, S3 data events on one scenario bucket, a
  parallel ground-truth log frozen before any pipeline code runs against it). **It is currently empty**
  (`contains_data: false` in its `PROVENANCE.json`) - no real AWS evidence has been collected or is
  included in this submission. Running `cffc run --data-root data/real` on the empty folder raises
  `NoEvidenceError` and writes nothing (`test_empty_real_data_runs_nothing_and_fabricates_nothing`) -
  the tool refuses to report results it does not have, rather than producing empty or placeholder
  numbers.
- **`outputs/`** holds only generated files, is gitignored except for a placeholder, and is always safe
  to delete (`make clean-outputs`) - everything in it is reproducible from `data/` + `configs/`.

Collecting real evidence is **not part of this Stage 4 submission** (it requires an actual AWS account
and the scenario scripts to be executed by Khanak per Stage 2 §11); the pipeline that will ingest it is
implemented, tested against synthetic data of the same shape, and ready.
