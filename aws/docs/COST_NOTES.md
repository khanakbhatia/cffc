# Cost notes

Approximate, order-of-magnitude, AWS us-east-1 pricing as of this implementer's training data -
**verify current pricing yourself** in the AWS Pricing Calculator or Billing console before running
anything; AWS pricing changes, and this implementer has no live access to confirm current rates.

| Item | What creates it | Rough scale |
|---|---|---|
| CloudTrail management events | `01_enable_cloudtrail.sh` | First copy of management events to an account's trails is free; this project uses one trail |
| CloudTrail S3 data events | `02_s3_data_events.sh` | Billed per 100,000 events; this project's few dozen `GetObject` calls on one bucket are far below any meaningful charge, but the *setting itself* has no separate fee - only events logged |
| S3 storage (preservation bucket) | CloudTrail log delivery | A handful of small (KB-scale) `.json.gz` files; negligible |
| S3 requests (`PutObject`/`GetObject`) | setup + Scenario B | A few dozen requests total; negligible |
| EC2 `t3.micro`, ~1-2 minutes | Scenario C `RunInstances` | Free-tier eligible on eligible accounts; otherwise a fraction of a cent per minute - the script terminates it automatically within roughly a minute of launch |
| IAM users/roles/access keys | setup + scenarios | No charge |

**None of this is free-tier-guaranteed** - confirm your account's free-tier status and current pricing
yourself (`[VERIFY AT RUNTIME]`, consistent with Stage 1's flagged-but-unverified S3 Object Lock /
free-tier item). The realistic total for one full run of all three scenarios plus cleanup should be
well under $1, but "should be" is not a substitute for checking your own Billing dashboard, which is
why `00_preflight_checks.sh` makes cost acknowledgment an explicit, separate, non-automated step.
