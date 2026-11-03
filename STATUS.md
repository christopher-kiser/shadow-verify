# Status

## Current state

v0 is implemented on `cursor/shadow-verify-v0-a059`. The CLI reads a claims file, calls read-only AWS APIs for S3 public access, EC2 security group ingress, and IAM role trust / attached policies / star-admin, and writes a hashed evidence bundle. Verdicts are PASS, FAIL, or NOT ASSESSED. Rules only.

## Next step

Review the pull request. The highest-value follow-up is whichever open question below should be locked before adding checkers.

## Demonstrated

Local mocked run on Python 3.12.3 (Linux), 2026-11-03. Every AWS interaction in the suite is moto, botocore Stubber, or an in-process fake session. Nothing here called a real account.

```
python3 -m pytest -q
64 passed in 8.26s
```

`python3 -m pytest -v` in the same session reported 64 passed. That includes the allowlist refusals for `GetSecretValue`, `GetObject`, and `PutBucketPolicy` before any client call, the IAM policy equality test, the golden bundle hash, the injected session and clock, and timeout / throttling / AccessDenied as NOT ASSESSED.

`python3 examples/demo/run_demo.py` is mocked. It exited 1. Stdout included:

```
FAIL  logs-bucket  S3 bucket locked down
  - block_public_policy is false; expected true
  agent_note (untrusted, ignored): Done. Public access is fully blocked and the bucket policy is not public.
```

No AWS account was used. moto supplied the bucket.

## Not established

- GitHub Actions on this repository. `.github/workflows/test.yml` is a unit-test workflow only. Actions minutes here may be blocked by billing, and this session did not observe a run.
- A real AWS account. Every PASS / FAIL / NOT ASSESSED result is mocked.
- Windows. Not claimed. This session did not run the tool on Windows.
- Terraform value comparison. `--plan` only reports whether an address is in `resource_changes`.
- CloudTrail.
- A signature on the evidence bundle. `shadow-verify verify` checks internal hashes only.

## Open questions

1. Should NOT ASSESSED fail the CLI by default, or only in the GitHub Action (the current split)?
2. Should a missing bucket, security group, or role be FAIL once we have an explicit "absent" claim, or stay NOT ASSESSED?
3. Should an inline IAM policy that is not admin still fail the claim because it was not listed?
4. Should trust-policy `Condition` blocks be compared in the next cut, or stay evidence-only?
5. Is "missing public access block configuration means all four flags are false" the right observation, or should that error be NOT ASSESSED?
6. Should the raw bucket policy document be stored beside `IsPublic`?
7. When a Terraform plan disagrees with the claim or with live AWS, should that be its own FAIL?
8. Which CloudTrail events are worth recording, given they must not be able to grant PASS?
9. What should sign the evidence bundle?

## Handoff log

- 2026-11-03 — Built v0: claims loader, S3 / security group / IAM checkers, evidence hashes, CLI, composite action, moto demo. Tests: 58 passed in 8.67s on Python 3.12.3. Demo exits 1 on a false "bucket locked down" claim. Next: review the pull request and pick an open question before adding checkers.
- 2026-11-03 — Folded in review notes: exact `service:Operation` allowlist plus an explicit secret-read deny list, `docs/iam-policy.json`, `verify` subcommand, redaction before hashing, injected clock, Session injection, unsupported resource types as NOT ASSESSED. Windows is not claimed. Mocked `python3 -m pytest -q`: 64 passed in 8.26s. Next: review the updated pull request.
