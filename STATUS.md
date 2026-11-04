# Status

## Current state

v0 is implemented on `cursor/shadow-verify-v0-a059`. The CLI reads a claims file, calls read-only AWS APIs for S3 public access, EC2 security group ingress, and IAM role trust / attached policies / star-admin, and writes a hashed evidence bundle. Verdicts are PASS, FAIL, or NOT ASSESSED. Rules only.

The legacy eval set is data under `eval/legacy/`: scenarios `LG-01` through `LG-06` and provenance. Sentinel labels are TODO. Order: label, then adjudicate, then write the manifest. This change does not commit the legacy manifest. The core `set_sha256` is still `7b4cd4f1e447f0cee054c32aeaa5eafef3a670bd2e671b38f9316f69aa4af113`. The held-out pin is unchanged. `--files` without `--out` exits 2. `--out` that resolves to `eval/`, `eval/scenarios`, `eval/labels`, or `eval/heldout` also exits 2, and every `--files` path must resolve under `--out`.

## Next step

Sentinel labels `LG-01` through `LG-06` blind from the claim, the seed, and the condition. Then adjudicate, then write a new legacy manifest that includes the label files. The runner still does not score this set.

## Demonstrated

Local mocked run on Python 3.12.3 (Linux), 2026-11-03. Every AWS interaction in the suite is moto, botocore Stubber, or an in-process fake session. Nothing here called a real account.

```
python3 -m pytest -q
114 passed, 1 skipped in 13.11s
```

Legacy set, 2026-11-04, same interpreter. MOCKED. `python3 -m pytest -q`: 141 passed, 1 skipped in 14.48s (exit 0). `python3 eval/manifest.py --check` exited 0. `python3 -m eval.manifest --check` exited 0. `python3 eval/manifest.py --check --out eval/legacy --files` for `LG-01` through `LG-06` exited 2 and named the missing `eval/legacy/manifest.json` and `eval/legacy/MANIFEST.sha256`. Those files are not committed. No AWS account was used.

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

- A scored run of `LG-01` through `LG-06`. This change does not seed or score them.
- Sentinel's labels for the legacy set, and the legacy manifest. Both come after adjudication.
- Recomputation of the source `ground_truth.json` hashes. The values recorded in `eval/legacy/PROVENANCE.md` for commit `f31dee5d6a8294c7414db4ab9eab6f30e555ecdf` are qualification005 `69f29e998852e348719ae236fecf282515fec29f81c147a61e3ea64a353c49c0`, qualification011 `9ee93e6d538547bbb4640aff178fa0a0190610d603939500aeddc9374397bab9`, and qualification013 `24f97463e23d551c3be01cca79ea0fbb46e8d3e167c870c6239aaf54eb468f5d`. This workspace could not read that commit (`raven-shadow-core` 404, `raven-shadow` 422).
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
- 2026-11-04 — Added `eval/legacy/` (`LG-01` through `LG-06`) and `--out` so `--files` cannot overwrite the core manifest. Labels are TODO. MOCKED `python3 -m pytest -q`: 137 passed, 1 skipped in 13.77s. `python3 eval/manifest.py --check` exited 0. Core set hash and held-out pin unchanged. Next: Sentinel labels the six cases blind.
- 2026-11-04 — `--files` now refuses an `--out` that resolves to `eval/`, and refuses a file that does not resolve under `--out`. Compared as paths, so `eval`, `./eval/`, a backslash, and an absolute path are the same directory. Next: Sentinel labels the six cases blind.
- 2026-11-04 — Folded the Sentinel and Forge reviews. `--files` refuses an `--out` that resolves, case-insensitively, to `eval/`, `eval/scenarios`, `eval/labels`, or `eval/heldout`. `--created` must be a date. The legacy manifest is not committed. Removing the guard made `test_out_resolving_to_a_core_directory_exits_2` fail: `--out eval` exited 0. MOCKED `python3 -m pytest -q`: 141 passed, 1 skipped in 14.48s (exit 0). `python3 eval/manifest.py --check` and `python3 -m eval.manifest --check` exited 0. Next: Sentinel labels the six cases blind.
