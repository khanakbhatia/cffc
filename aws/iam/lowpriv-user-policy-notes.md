# Scenario principals - least-privilege design

| Principal | Created by | Attached policy | Purpose |
|---|---|---|---|
| `lowpriv-user` | `04_least_privilege_iam.sh` | AWS managed `ReadOnlyAccess` only (no IAM write permissions) | Scenario A: attempts `AttachUserPolicy`/`AssumeRole` it has no permission for - CloudTrail/IAM denies these *because* the policy is genuinely least-privilege, not because of a simulated restriction |
| `svc-reader` | `04_least_privilege_iam.sh` | Custom: `s3:GetObject`/`s3:ListBucket` on `cff-research-scenario-b-*` only | Scenario B: the principal whose access pattern shifts from one baseline object to a burst of "secret/*" objects |
| `analyst-bob` | `04_least_privilege_iam.sh` | AWS managed `ReadOnlyAccess` + `AmazonEC2FullAccess` (needed for the scripted `RunInstances` step) + console login profile | Scenario C: failed/successful console logins (manual, browser) followed by a scripted `RunInstances` |
| `admin-role` | `04_least_privilege_iam.sh` | AWS managed `AdministratorAccess`, trust policy restricted to the account's own root/IAM principals (`admin-role-trust-policy.json`) | Scenario A's `AssumeRole` target - `lowpriv-user` is never granted `sts:AssumeRole` on it, so the attempt is denied for a real, least-privilege reason |

None of these principals is granted anything beyond what its scenario script actually exercises.
Access keys created for `lowpriv-user` and `analyst-bob` are short-lived: created immediately before
use, used only for the specific CLI calls that need to run as that principal, and deleted immediately
after (`trap ... EXIT` in the scenario scripts) - never printed to stdout beyond a masked key ID.

## Notes on the two policy JSON files in this directory

- `admin-role-trust-policy.json` is consumed directly by `04_least_privilege_iam.sh` (after `sed`
  substituting `ACCOUNT_ID`) as the trust policy for `admin-role`. It intentionally contains only
  `Version`/`Statement` - AWS IAM rejects policy documents with any other top-level key
  (`MalformedPolicyDocument`), so no inline comments live inside it.
- `research-collector-policy.json` is **not called by any script**. It is what *you* should attach
  (via the IAM console, or `aws iam put-user-policy`/`put-role-policy` with your own identity) to the
  profile you configured in `aws/config.env` as `AWS_PROFILE`, so that profile has exactly what these
  scripts need and nothing more. Scoped by resource name prefix (`cff-research-*`) and, for the IAM
  bootstrap actions, by the `Project` request tag, so it cannot create or modify untagged/unrelated
  resources.
