# Safety checklist

Run through this before and after every collection session.

## Before
- [ ] `aws sts get-caller-identity --profile cffc-research` shows the correct account (run it yourself,
      or let `00_preflight_checks.sh` show it to you and type `PROCEED`).
- [ ] No resources already tagged `Project=cffc-research` from a stale previous run (preflight checks
      this and warns; if found, consider `08_cleanup.sh` first).
- [ ] `CFFC_ACK_COSTS=yes` set deliberately, after reading `docs/COST_NOTES.md`.
- [ ] You have read `aws/README.md`'s note on the single-source-IP real-world limitation and decided
      whether `--alt-profile` applies to your setup for Scenario B.
- [ ] Every script you are about to run has been dry-run first (`--dry-run`) and the printed commands
      reviewed.

## During
- [ ] Each scenario script's `confirm "PROCEED" ...` prompt is read, not reflexively answered.
- [ ] Scenario C: the console password file (`aws/.scratch/analyst_bob_console_password.txt`) is read
      by you, not pasted into any chat, commit, or screenshare.
- [ ] No step's output (a `create-access-key` response, in particular) is copied anywhere outside your
      local terminal/`aws/.scratch/` (gitignored).

## After each scenario
- [ ] `aws/.scratch/*_access_key*.json` files for that scenario are gone (the `trap` should have deleted
      them - confirm with `ls aws/.scratch/`).
- [ ] `data/real/ground_truth/<scenario>_ground_truth.json` exists and is read-only (`ls -l`) - if the
      script printed "GROUND TRUTH INVALID", it was NOT frozen; do not proceed to export/hash until fixed.

## After the session (before stepping away from the account)
- [ ] EC2 console: no instance tagged `Project=cffc-research` in a non-terminated state.
- [ ] IAM console: the four scenario principals exist only if you intend to keep them for a later
      session; otherwise `08_cleanup.sh` has removed them.
- [ ] Billing: matches `docs/COST_NOTES.md`'s expectations; investigate anything that does not.
- [ ] `data/real/sanitized/` reviewed by a human before anything leaves your machine (git push, email,
      upload) - see `docs/MANUAL_AWS_STEPS.md` item 8.

## If something looks wrong
Stop. Do not run further scenario/collection scripts. `08_cleanup.sh --delete-preservation-bucket` is
available but is a last resort for a compromised/misconfigured sandbox account, not a routine step -
it destroys your collected evidence along with everything else.
