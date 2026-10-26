# data/ - three kinds of files, kept apart

| Folder | What it is | Who writes it | Committed? |
|---|---|---|---|
| `data/synthetic/` | **TEST DATA** produced by `cffc.synthetic` (fixed seed). CloudTrail-format but invented. | the generator (`make synthetic`) | yes |
| `data/real/` | **REAL RESEARCH DATA**: AWS CloudTrail logs the team collects, with manifests and frozen ground truth. **Currently empty.** | the data owner | policy decision for the team |
| `outputs/` | **GENERATED** results (tables, figures, timelines, metrics JSON) | the experiment runner | no (gitignored) |

Each data root has the same layout (`raw/<scenario>/`, `manifests/`, `ground_truth/`) and a `PROVENANCE.json`
whose `kind` is `synthetic` or `real`. The runner refuses to run on a root without it, and writes results to
`outputs/<kind>/`, so synthetic and real results cannot be mixed. See `docs/DATA_POLICY.md`.
