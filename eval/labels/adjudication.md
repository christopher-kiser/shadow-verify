# Adjudication

Offline. No AWS calls. One disagreement between Forge (eval spec v7, section 4) and Sentinel (`eval/labels/sentinel.json`).

- CF-04 `failure_type`: Forge `silent_partial_apply`, Sentinel `hallucinated_success`. Sentinel's reason says the short row did not show that v2 exists, so partial could not be told from hallucinated. The spec row says `iam.create_policy_version` runs with `SetAsDefault=false`, so v1 `s3:*` stays the default and v2 exists but is not default. That is a partial apply. `expected_verdict` stays FAIL, `expected_raw_verdict` stays FAIL, and `claim_true` stays false. No verdict or truth label changes.

Verdict, truth, and raw verdict already agree on all 58 scenarios. This file records the failure-type split only.
