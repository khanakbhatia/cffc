# Cloud Forensic Evidence Correlation Framework - Stage 4 implementation

Research software for the 5-person project described in Stages 1-3.5 (problem/lit review, research
design, integrity & evaluation specification). This is Khanak's Stage 4 deliverable: ingestion,
normalization, schema validation, correlation, timeline reconstruction, SHA-256 integrity, ground-truth
evaluation, the 16-run experiment matrix, result tables/figures, and automated tests - all real, runnable
code, not pseudocode.

**No AWS results are claimed here.** `data/real/` is empty; every number this repository currently
produces comes from `data/synthetic/`, deterministic invented test data, and every output derived from
it is stamped accordingly. See `docs/DATA_POLICY.md`.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=src                      # or: pip install -e .

python -m unittest discover -s tests -t .  # run the test suite (see "Test results" below)
python -m cffc generate-synthetic --root data/synthetic   # (re)generate the synthetic dataset
python -m cffc run --data-root data/synthetic --out-root outputs
cat outputs/synthetic/tables/results_summary.md
```

Or `make test`, `make synthetic`, `make run-synthetic`. `make run-real` runs the same matrix against
`data/real` once the team has populated it; today it will correctly refuse (`NoEvidenceError`) because
that folder is empty.

## Repository layout

```
src/cffc/            # the package (see docs/ARCHITECTURE.md for the module map)
  schema.py           canonical event schema + validation (SCHEMA.md)
  timeutil.py          UTC-safe timestamp parsing
  normalizers/          AWS CloudTrail (implemented+tested), Azure/GCP (design-level, RQ1 only)
  integrity.py           SHA-256 hashing, append-only manifests, tamper testing
  ingestion.py            integrity gate -> read -> normalize -> validate
  ground_truth.py          ground-truth file loading, freeze protocol, validation
  matching.py                ground-truth step <-> event matching
  correlation.py             OR / AND / baseline rule-based temporal correlation
  timeline.py                 timeline reconstruction + ground-truth annotation
  metrics.py                   SC, CC, P/R/F1/FCR, TOA, TC, TDR (pure functions)
  synthetic.py                  deterministic SYNTHETIC CloudTrail-format test-data generator
  experiment.py                  runs the Stage 3.5 Part D matrix, writes outputs/<provenance>/
  reporting.py                    result tables (csv/md) and figures (png)
  config.py, cli.py                config loading, `python -m cffc ...`
configs/default.toml   # the approved 5-template x 3-scenario x 1-tamper = 16-run matrix
tests/                 # 100 automated unittest cases (no network, no AWS calls)
data/
  synthetic/             committed, generator-produced TEST data (see docs/DATA_POLICY.md)
  real/                  EMPTY - real evidence goes here when collected; PROVENANCE.json says so
outputs/                GENERATED ONLY, gitignored (tables, figures, timelines, metrics JSON)
docs/
  ARCHITECTURE.md          module map
  ASSUMPTIONS.md            every concretization made beyond the approved Stage 3.5 spec, with rationale
  METRICS.md                 pair-counting scopes, worked examples
  DATA_POLICY.md              synthetic vs. real vs. generated, in detail
SCHEMA.md               # the 16-field canonical schema and AWS/Azure/GCP field mappings
```

## What is implemented vs. design-level only

| Area | Status |
|---|---|
| AWS CloudTrail ingestion, normalization, validation | Implemented, unit- and property-tested, exercised end-to-end on synthetic data |
| SHA-256 integrity (manifest, verification, 3-type tamper test) | Implemented and tested, incl. negative controls that prove the detector can fail a test |
| Rule-based correlation (OR/AND/baseline), time-window sensitivity | Implemented, tested against a brute-force reference on randomized inputs |
| Timeline reconstruction, same-second tie documentation | Implemented; the synthetic data deliberately contains one same-second collision so the documented limitation (`docs/ASSUMPTIONS.md` A6) is visible in real output, not just asserted |
| Ground-truth loading/freeze protocol, GT-to-event matching | Implemented and tested, including the ambiguous-match case |
| All 9 Stage 3.5 metrics + the 16-run experimental matrix | Implemented; see `outputs/synthetic/` for a live example run |
| Azure / GCP normalization | Design-level only (Stage 2 §14 mapping), checked against hand-written samples for RQ1 structural portability - **not validated against live Azure/GCP data**, matching Stage 2 §23's stated limit |
| Real AWS evidence | **Not collected.** `data/real/` is empty by design (see `docs/DATA_POLICY.md`) |
| Timesketch / Volatility / Wireshark / Autopsy / ML correlation | Out of scope per Stage 2 §6 - not implemented |

## Test results

See the "Test results" message in this conversation for the actual, just-executed output of
`python -m unittest discover -s tests -t .` (100 tests) and a mutation-testing sanity check showing the
suite fails when the correlation window boundary, the pair-count formula, the tamper detector, or the
null-sentinel handling are deliberately broken.

## Honesty notes for the paper (Ria/Disha)

- Every metric in `outputs/synthetic/` is a sanity check, not a finding. Collection completeness is 1.0
  there *by construction* (the generator writes ground truth and events from the same script) and must
  not be reported as evidence of real-world collection quality.
- `docs/ASSUMPTIONS.md` lists every place this implementation had to concretize something the approved
  Stage 3.5 spec left open (AND-mode semantics, pair-counting scope, same-second tie-breaking, F1's 0/0
  case, etc.). These are implementation decisions, not re-litigations of Stage 2/3 - please review them
  against Stage 3.3/Thirzah's architecture doc if either narrows them further.
