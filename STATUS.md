# Status

## Current state

v0 checks S3 public access, EC2 security group ingress, and IAM role trust, attached policies, and star-admin. A role ARN whose account or partition differs from `GetRole`'s `Arn` is NOT ASSESSED (`arn_mismatch`). An Allow of `*` or `*:*` on any resource pattern that matches every `arn:aws:` ARN is FAIL. `iam:*` and the other named privilege-escalation actions on all resources are NOT ASSESSED (`may_grant_admin`). Verdicts are PASS, FAIL, or NOT ASSESSED. Rules only. ADR 030.

## Next step

Review the pull request. The privilege-escalation list in ADR 030 is the named actions only; `iam:SetDefaultPolicyVersion` on `*` is still out of that list.

## Demonstrated

Local mocked run on Python 3.12.3 (Linux), 2026-11-04. Every AWS interaction in the suite is moto, botocore Stubber, or an in-process fake session. Nothing here called a real account.

```
python3 -m pytest -q
150 passed, 1 skipped in 16.58s
```

MOCKED. The skip is `tests/test_live.py` because `SV_LIVE` is not set. Two mocked demo runs both exited 1 with `bundle_sha256` `39f3a4677a9830ced8d9b7ad7d325c0758e4783955832d46686381f62b5701b4`. `python -m pip_audit` in a clean virtualenv printed `No known vulnerabilities found`.

CI for `4e8caee` is green on `ubuntu-latest` and `windows-latest`:

- https://github.com/christopher-kiser/shadow-verify/actions/runs/41836017217 (push)
- https://github.com/christopher-kiser/shadow-verify/actions/runs/41836026609 (pull request)

`python3 examples/demo/run_demo.py` is mocked. It exited 1. Stdout included:

```
FAIL  logs-bucket  S3 bucket locked down
  - block_public_policy is false; expected true
  agent_note (untrusted, ignored): Done. Public access is fully blocked and the bucket policy is not public.
```

No AWS account was used. moto supplied the bucket.

## CI

`4e8caee` is green on `ubuntu-latest` and `windows-latest`.

- `4e8caee` push: https://github.com/christopher-kiser/shadow-verify/actions/runs/41836017217
- `4e8caee` pull request: https://github.com/christopher-kiser/shadow-verify/actions/runs/41836026609

## Not established

- A real AWS account. Every PASS / FAIL / NOT ASSESSED result in the local suite is MOCKED.
- Terraform value comparison. `--plan` only reports whether an address is in `resource_changes`.
- CloudTrail.
- A signature on the evidence bundle. `shadow-verify verify` checks internal hashes only.

## Open questions

1. ADR 021 makes NOT ASSESSED exit 2. A caller that wants the old exit 0 would need a new flag.
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
- 2026-11-03 — Second review batch: pinned action SHAs, post-deploy example workflow, scoped IAM statements, OIDC trust pins, pip-audit and pytest strict settings, ubuntu/windows CI matrix. Windows: NOT ASSESSED. Mocked `python3 -m pytest -v`: 65 passed in 9.17s. Next: review PR 1.
- 2026-11-03 — Forge correctness fixes: CIDR coverage, IAM action map, account-id index, RFC 8785 hashes, exit codes 0/1/2/3, socket block, client Config, mode and tool_commit. MOCKED `python3 -m pytest -v`: 90 passed, 1 skipped in 10.18s. CI for 784eb4f later went green on ubuntu-latest and windows-latest.
- 2026-11-03 — Internet overlap instead of full cover, both address families for a world forbid, protocol numbers, unresolvable prefix lists and security-group sources, reports built from relabelled results. MOCKED `python3 -m pytest -q`: 103 passed, 1 skipped in 12.28s. Demo hash stable across two runs. CI for 6db1641 is green on ubuntu-latest and windows-latest. Next: review PR 1.
- 2026-11-04 — ICMP matches on type and ignores the code. Protocol number `1` is icmp. Raw `IpProtocol` `6`, `17`, and `1` go through a botocore Stubber. Emptying the number map made those three cases PASS instead of FAIL; the map was restored. MOCKED `python3 -m pytest -q`: 108 passed, 1 skipped in 11.05s. CI for `bb2da38` is green on ubuntu-latest and windows-latest. Next: review PR 1.
- 2026-11-04 — A forbid of `all` / `-1` covers every protocol, then ports or ICMP type. Reverting that match made the tcp/22 and icmp type 8 world cases PASS instead of FAIL. CGNAT `100.64.0.0/10` still passes a world forbid. The job summary escapes claim text. MOCKED `python3 -m pytest -q`: 113 passed, 1 skipped in 11.88s. CI for `50d5a72` is green on ubuntu-latest and windows-latest. Next: review PR 1.
- 2026-11-04 — A range entry with no CIDR is `unresolvable_source` (NOT ASSESSED). Reverting that match made tcp/22 from `0.0.0.0/0` PASS when the only range was a description. MOCKED `python3 -m pytest -q`: 114 passed, 1 skipped in 13.11s. CI for `4e8caee` is green on ubuntu-latest and windows-latest. Next: review PR 1.
- 2026-11-04 — IAM wrong-PASS: a role ARN in another account or partition is `arn_mismatch` (NOT ASSESSED), and all-resource admin patterns fail while `iam:*` on all resources is `may_grant_admin`. Breaking each check made the new tests PASS again (pytest exit 1). MOCKED `python3 -m pytest -q`: 150 passed, 1 skipped in 16.58s. Windows is not claimed from this machine. Next: review the pull request.
