# Module map (implements Thirzah's architecture, Stage 2 §6/§10/§15-17)

```
raw CloudTrail .json.gz  --->  integrity.py        (SHA-256 manifest, append-only, verify)
                                       |
                                       v
                                ingestion.py        (integrity gate -> read -> normalize -> validate)
                                       |                       |
                           normalizers/aws_cloudtrail.py   schema.py (CanonicalEvent, validate_event)
                           normalizers/azure_activity.py   (design-level, RQ1 only)
                           normalizers/gcp_audit.py        (design-level, RQ1 only)
                                       |
                                       v
                               correlation.py       (OR / AND / baseline, union-find over a time window)
                                       |
                                       v
                                timeline.py          (group-contiguous chronological reconstruction)
                                       |                       |
                           ground_truth.py <---- matching.py (step <-> event/timeline-row matching)
                                       |
                                       v
                                 metrics.py           (pure functions: SC, CC, P/R/F1/FCR, TOA, TC, TDR)
                                       |
                                       v
                               experiment.py           (Stage 3.5 Part D matrix; writes everything under outputs/)
                                       |
                                       v
                               reporting.py            (tables, figures - provenance-stamped)
```

`synthetic.py` sits beside `ingestion.py` as an alternative evidence *source* (writes the same
`raw/` + `manifests/` + `ground_truth/` layout that real collection would), not as a pipeline stage.

`config.py` loads `configs/default.toml` and validates it; `cli.py` exposes every stage as a
subcommand (`generate-synthetic`, `build-manifest`, `verify`, `validate-gt`, `normalize`, `run`).
