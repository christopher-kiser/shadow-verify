# Status

## Current state

v0 reads S3 public access, EC2 security group ingress, and IAM role trust / policies, and writes a hashed evidence bundle. Verdicts are PASS, FAIL, or NOT ASSESSED. Rules only. An `s3_bucket` check always reads `GetBucketLocation`. The claim `region`, or `--region` when the claim omits it, must match. `null` and `""` are `us-east-1`. `EU` is `eu-west-1`. A mismatch is FAIL (`region_mismatch`). A location read error is NOT ASSESSED. `region` on any other resource type is a claims error (exit 3). A claim region must look like `us-east-1` or `us-gov-west-1`.

## Next step

Review the region pull request. The eval adapter that passes a scenario region through waits on PR #5, which adds `eval/adapter.py`. That adapter is not on main.

## Demonstrated

Local mocked run on Python 3.12.3 (Linux), 2026-11-04. Every AWS interaction in the suite is moto 5.2.5, botocore Stubber, or an in-process fake session. Nothing here called a real account.

```
python3 -m pytest -q
152 passed, 1 skipped in 14.50s
```

Exit code 0. A us-west-2 bucket checked from us-east-1 is FAIL (`region_mismatch`). A security group or IAM role claim with `region: eu-west-1` is a claims error, exit 3, and does not PASS. Removing that rejection made those tests return exit 0; pytest exit code 1. Restoring it passed; pytest exit code 0. Core `set_sha256` is still `7b4cd4f1e447f0cee054c32aeaa5eafef3a670bd2e671b38f9316f69aa4af113`.

MOCKED. The skip is `tests/test_live.py` because `SV_LIVE` is not set. Two mocked demo runs both exited 1 with `bundle_sha256` `b77dee1b3ff5e66bd9760f31439563ee20f585b4a60c3a73e094ae431805bf0f`. That hash includes `tool_commit` and the absolute claims path, so another checkout produces a different digest.

CI for `4e8caee` is green on `ubuntu-latest` and `windows-latest`:

- https://github.com/christopher-kiser/shadow-verify/actions/runs/41836017217 (push)
- https://github.com/christopher-kiser/shadow-verify/actions/runs/41836026609 (pull request)

`python3 examples/demo/run_demo.py` is mocked. It exited 1. Stdout included:

```
FAIL  logs-bucket  S3 bucket locked down
  - region is us-east-1
  - block_public_policy is false; expected true
  agent_note (untrusted, ignored): Done. Public access is fully blocked and the bucket policy is not public.
```

No AWS account was used. moto supplied the bucket.

## CI

The region change has not run in CI yet. The last green matrix for an earlier commit, `4e8caee`, was `ubuntu-latest` and `windows-latest`.

- `4e8caee` push: https://github.com/christopher-kiser/shadow-verify/actions/runs/41836017217
- `4e8caee` pull request: https://github.com/christopher-kiser/shadow-verify/actions/runs/41836026609

## Not established

- A real AWS account. Every PASS / FAIL / NOT ASSESSED result in the local suite is MOCKED.
- Windows for the region check. This session ran on Linux. CI runs `windows-latest`.
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
- 2026-11-04 — S3 checks read `GetBucketLocation`. A us-west-2 bucket no longer PASSes a us-east-1 run. `null` and `""` are `us-east-1`; `EU` is `eu-west-1`. AccessDenied on the location is NOT ASSESSED. MOCKED `python3 -m pytest -q`: 139 passed, 1 skipped in 12.13s, exit 0. Break-it of the region comparison: pytest exit 1, then exit 0 after restore. Core `set_sha256` unchanged. Windows for this change is not run here. Next: review the region pull request.
- 2026-11-04 — `region` is rejected at load time except on `s3_bucket` (exit 3). A security group in us-east-1 with `region: eu-west-1` no longer PASSes. Claim regions match `us-east-1` or `us-gov-west-1`; legacy `EU` stays a GetBucketLocation response only. MOCKED `python3 -m pytest -q`: 152 passed, 1 skipped in 14.50s, exit 0. Break-it of the type check: pytest exit 1 (CLI exit 0), then pytest exit 0 after restore. Next: wait for green ubuntu and windows CI.
