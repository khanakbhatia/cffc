# Actions you must personally perform

Everything else in `aws/` is scripted. These are not:

1. **Configure your own AWS CLI credentials.** Run `aws configure --profile cffc-research` (or set up
   AWS SSO) yourself, with an AWS account you control. No script here asks for, reads, or stores a
   secret access key - `aws/config.env` holds only a profile *name*.
2. **Attach `aws/iam/research-collector-policy.json`** to whatever IAM identity that profile uses
   (console or `aws iam put-user-policy`/`put-role-policy`, your call) - least-privilege, scoped to
   `cff-research-*` resources and `Project`-tagged IAM actions.
3. **Confirm this is the right (non-production, budget-aware) AWS account.** `00_preflight_checks.sh`
   prints the account ID/identity and makes you type `PROCEED`; it cannot know for you whether this is
   the account you meant to use.
4. **Read `docs/COST_NOTES.md` and set `CFFC_ACK_COSTS=yes` in `aws/config.env` yourself.** Deliberately
   not auto-set by any script.
5. **Scenario C's four `ConsoleLogin` attempts** (three wrong passwords, one correct) must be done by
   you, in a browser, at `https://<account-id>.signin.aws.amazon.com/console`. `scenario_c_credential_misuse.sh`
   prints the URL and analyst-bob's generated password file path, then pauses at each attempt
   (`log_step_prompt`) for you to press Enter right after you perform it - that's how the ground-truth
   timestamp gets recorded. There is no clean way to script this: CloudTrail's `ConsoleLogin` event
   comes from the actual federated sign-in flow, and scripting repeated password submissions against
   AWS's sign-in page would be exactly the kind of automated credential-testing behavior that is
   inappropriate to script, ToS concerns aside.
6. **Every destructive or billable script step requires you to type a literal confirmation word**
   (`PROCEED`, `DELETE`, `DELETE EVIDENCE`) - this is intentional friction, not a script bug.
7. **Visually verify** in the AWS Console, at least once per session: CloudTrail shows "Logging: On"
   after `01_enable_cloudtrail.sh`; no unexpected EC2 instances remain after Scenario C or after
   cleanup; the Billing dashboard matches `docs/COST_NOTES.md`'s expectations. Anywhere a script prints
   `[VERIFY AT RUNTIME]` is a point where this implementer could not confirm current AWS behavior
   (account-tier feature availability, exact console UI) without access to AWS - confirm it yourself
   at the time you run it, the same epistemic stance Stage 1 took toward `[VERIFICATION REQUIRED]` items.
8. **Review `data/real/sanitized/<scenario>/SANITIZATION_REPORT.json` and the sanitized files by hand**
   before committing, sharing, or releasing anything - `07_sanitize.py` is a mechanical first pass
   (regex pattern matching), not a guarantee (Stage 2 §24).
9. **Run `08_cleanup.sh` yourself** when a collection session is done. No script tears resources down
   automatically except the short-lived access keys and the Scenario-C EC2 instance (both cleaned up
   by `trap ... EXIT` inside their own scenario script).
10. **Decide, as a team,** whether to keep the CloudTrail trail running across sessions (re-running
    `01_enable_cloudtrail.sh` is idempotent-ish but will error if the trail already exists - harmless,
    just re-run `start-logging` if needed) and whether sanitized real evidence gets committed to git at
    all (Stage 2 §24 raises this; it is a policy decision for the team, not something this package
    decides for you).
