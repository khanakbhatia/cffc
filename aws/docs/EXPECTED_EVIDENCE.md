# Expected evidence per scenario

Reference for Disha's evaluation work and for sanity-checking a real collection run against what the
scenario scripts are supposed to produce. Ground truth is authoritative (it's what the pipeline is
actually scored against); this is a human-readable companion, current at the time this was written -
cross-check against the real `data/real/ground_truth/*.json` the scripts actually produce, which
record the real wall-clock times of the real run.

## Scenario A - privilege escalation (`scenario_a_privilege_escalation.sh`)

| GT step | Expected CloudTrail event | Principal | Expected result | Attack stage |
|---|---|---|---|---|
| 1 | `CreateUser` | operator (admin) | success | setup (benign) |
| 2 | `AttachUserPolicy` (AdministratorAccess) | lowpriv-user | **AccessDenied** (genuinely - ReadOnlyAccess only) | privilege_escalation |
| 3 | `AssumeRole` (admin-role) | lowpriv-user | **AccessDenied** (genuinely - trust policy excludes it) | privilege_escalation |
| 4 | `GetCallerIdentity` | lowpriv-user | success | discovery |

Groups: `group_0` = {1} (benign), `group_1` = {2,3,4} (same principal `lowpriv-user`).
Correlation signal present: shared `principal_id` across steps 2-4 within the default 300s window.
Correlation signal **absent vs. synthetic design**: no IP change (single operator IP throughout).

## Scenario B - S3 access pattern (`scenario_b_s3_access.sh`)

| GT step | Expected CloudTrail event | Resource | Expected result | Attack stage |
|---|---|---|---|---|
| 1 | `GetObject` | `reports/q3.csv` | success | baseline_access (benign) |
| 2 | `ListBuckets` | n/a | success | discovery |
| 3 | `GetObject` | `secret/a.csv` | success | collection |
| 4 | `GetObject` | `secret/b.csv` | success | collection |
| 5 | `GetObject` | `secret/c.csv` | success | exfiltration (labeled; not literally exfiltrated anywhere) |

Groups: `group_0` = {1}, `group_1` = {2,3,4,5} (same principal `svc-reader`, or a second IP if
`--alt-profile` was used). All S3 object events are **data events** - they only appear in CloudTrail
because `02_s3_data_events.sh` scoped data-event logging to this one bucket; if that setup step was
skipped, these events will not be collected at all (shows up as low `collection_completeness`, not a
pipeline bug - see `docs/ASSUMPTIONS.md` A-series in the main repo for how the metric handles this).

## Scenario C - credential misuse (`scenario_c_credential_misuse.sh`)

| GT step | Expected CloudTrail event | Expected result | Attack stage | Collected how |
|---|---|---|---|---|
| 1-3 | `ConsoleLogin` | **Failure** | credential_access | **manual** (browser) |
| 4 | `ConsoleLogin` | Success | initial_access | **manual** (browser) |
| 5 | `RunInstances` | success | execution | scripted |

Group: `group_1` = {1,2,3,4,5} (same principal `analyst-bob`). The instance from step 5 is terminated
automatically within roughly a minute by the script's own cleanup trap - do not expect it to still be
running by the time you check the EC2 console, and do not treat its absence as a collection failure.

## Cross-scenario notes

- **Benign baseline** (`baseline/benign_baseline.sh`) events are intentionally *not* in any ground
  truth file - they exist to give the correlation algorithm plausible unlabeled traffic to NOT merge
  into the labeled groups, the same role `cffc.synthetic`'s `_noise()` plays in the Stage 4 synthetic
  dataset. A high false-correlation rate against real baseline traffic would be a genuine, reportable
  finding - unlike on synthetic data, where collection completeness is 1.0 by construction
  (`docs/DATA_POLICY.md`), real collection completeness and real correlation precision/recall are
  **not known in advance** and must come from an actual run.
- **CloudTrail delivery latency** (5-15 min typical) means the exported raw files may contain events
  from slightly before/after the scenario's own window if other activity happened close in time -
  `05_export_evidence.sh` filters by `LastModified >= scenario start`, which is a coarse filter at
  file-delivery granularity, not per-event; `collection_completeness`/`timeline_ordering_accuracy`
  (Stage 3.5 metrics, already implemented and tested in Stage 4) are what actually characterize how
  well the real collected events match the frozen ground truth - this table is a prediction, not a
  result.
