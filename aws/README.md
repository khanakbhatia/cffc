# Stage 5 - AWS execution package

Scripts + docs to collect REAL AWS CloudTrail evidence for the three approved scenarios
(Stage 2 §9) and feed it into the Stage 4 pipeline (`data/real/`). **Nothing in this package has
been run.** No AWS resources exist, no evidence has been collected, and no credentials have been
given to or handled by the assistant that wrote this - that is true both because it was never asked
for them and because this assistant has no network access to AWS at all. Every script here runs
*you* running the AWS CLI with *your own* configured profile.

## What you do vs. what the scripts do

You personally, inside AWS, with your own credentials (see `docs/MANUAL_AWS_STEPS.md` for the full,
numbered list):
1. Run `aws configure --profile cffc-research` (or SSO login) yourself, with your own account.
2. Edit `aws/config.env` (copy from `config.env.example`) with your region, profile name, and a
   unique bucket-name suffix.
3. Read `docs/COST_NOTES.md` and set `CFFC_ACK_COSTS=yes` once you accept them.
4. Actually perform the Scenario C console sign-in attempts in a browser (CloudTrail `ConsoleLogin`
   cannot be realistically scripted from the CLI - see `docs/MANUAL_AWS_STEPS.md` item 5).
5. Type the literal confirmation words every script asks for before anything that costs money or is
   destructive (`PROCEED`, `DELETE`, etc.) - this is an intentional manual gate, not a bug.
6. Run `aws/collection/08_cleanup.sh` yourself when the team is done collecting for a session, and
   visually check the Billing/EC2/CloudTrail consoles afterward.

Everything else - resource creation, the scripted parts of each scenario, export, hashing, manifest
building, sanitization - is automated, in the numbered order below. Every script supports
`--dry-run`, which prints the AWS CLI commands it would run instead of running them and requires no
configured credentials at all (verified: every setup/scenario/baseline/export script was run with
`--dry-run` and no `aws` CLI installed, and all completed successfully). Two scripts are documented
exceptions that still make a small number of read-only AWS calls even under `--dry-run`, because
that read IS their purpose: `00_preflight_checks.sh` (confirming your identity) and
`08_cleanup.sh` (listing what is currently tagged for teardown, gracefully reporting "none found"
if nothing exists or no credentials are configured yet). Use `--dry-run` first.

## Order of operations

```
aws/setup/00_preflight_checks.sh         # safety gate: confirms identity/region/cost ack, tags project
aws/setup/01_enable_cloudtrail.sh        # multi-region trail + log file validation
aws/setup/02_s3_data_events.sh           # S3 data events on the scenario-B bucket ONLY
aws/setup/03_preservation_bucket.sh      # preservation bucket (Object Lock if available, else deny-delete policy)
aws/setup/04_least_privilege_iam.sh      # lowpriv-user, svc-reader, analyst-bob, admin-role (all tagged, all least-privilege)

aws/scenarios/scenario_a_privilege_escalation.sh
aws/scenarios/scenario_b_s3_access.sh
aws/scenarios/scenario_c_credential_misuse.sh    # pauses for the manual browser steps
aws/baseline/benign_baseline.sh                  # unlabeled background activity, any time before/after/between

aws/collection/05_export_evidence.sh <scenario>  # wait for delivery, copy raw CloudTrail files, filenames untouched
aws/collection/06_hash_and_manifest.sh <scenario> # wraps `cffc build-manifest` (Stage 4)
aws/collection/07_sanitize.py <scenario>          # writes data/real/sanitized/, never touches raw/
aws/collection/08_cleanup.sh                      # tear-down, tag-scoped, confirmation-gated
```

Ground truth is written live, during each scenario script, by `aws/lib/gt_logger.sh`
(`log_step ...` calls right before/after each AWS CLI call - Stage 2 §10), then assembled, schema-
validated against the Stage 4 `cffc` package, and frozen (`chmod 444`) by `aws/lib/gt_finalize.py`
at the end of the script. **A scenario script that fails ground-truth validation does not freeze the
file** - it prints the validator's errors and leaves the scratch log for you to fix and re-run.

## Real-world limitation vs. the synthetic design (read this before running Scenario B/C)

The synthetic dataset (Stage 4) simulates attacker traffic from a *different source IP* than the
baseline. Run for real from a single operator laptop/CLI session, every CLI-originated event will
carry the **same** `sourceIPAddress` - the IP-change signal the synthetic scenarios rely on will not
be present in real data. This is flagged, not hidden: `expected_source_ip` is left unset (null, a
permitted optional field) in the real ground-truth files for CLI-originated steps, and
`docs/EXPECTED_EVIDENCE.md` names this as a threat-to-validity note the team should carry into the
paper (it only strengthens Stage 2 §23's existing "external validity" caveat). If the team has access
to a genuinely separate network path (a second machine/connection) for the "attacker" half of
Scenario B, `scenario_b_s3_access.sh --alt-profile <profile>` will use it; otherwise it runs single-IP
and says so in its ground-truth notes.
