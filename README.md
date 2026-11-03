# Shadow Verify

Shadow Verify checks whether an AI coding agent's AWS change did what the agent claimed.

After a pull request is merged or a change is deployed, it reads a claim file, queries the live account read-only, and returns a verdict for each claim: **PASS**, **FAIL**, or **NOT ASSESSED**. Every run writes a hashed evidence bundle of the API responses that produced the verdict. Rules decide the verdict. There is no model on that path. Text the agent wrote is untrusted input and cannot grant PASS.

Pre-merge IaC review reads the plan or the templates before apply. Shadow Verify runs after deploy and reads the account. A plan can be approved while the apply fails, applies only part of the change, or is overwritten later. An agent can also report success from a tool result that never landed. This tool checks the account the agent said it changed.

v0 checks three things: S3 public access block and bucket-policy publicity, EC2 security group ingress, and IAM role trust, attached policy ARNs, and star-admin. More checkers plug into the same interface.

## 60-second quickstart

No AWS account is required. The demo is mocked with [moto](https://github.com/getmoto/moto): one public-access flag is false, and the claim says the bucket was locked down. The process exits 1 because that claim is FAIL.

```bash
git clone https://github.com/christopher-kiser/shadow-verify.git
cd shadow-verify
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python examples/demo/run_demo.py
```

Against a real account, put claims in `.shadow/claims.yaml` (see [docs/CLAIMS.md](docs/CLAIMS.md)) and use a role limited to [docs/iam-policy.json](docs/iam-policy.json):

```bash
shadow-verify run --claims .shadow/claims.yaml --region us-east-1 --evidence evidence.json
shadow-verify run --claims .shadow/claims.yaml --region us-east-1 --json
```

`python -m shadow_verify` is the same console entry point.

These commands were run on Linux. CI for `784eb4f` also passed on `windows-latest`; the links are under GitHub Action.

## Exit codes

| Code | `run` | `verify` |
| --- | --- | --- |
| 0 | Every claim is PASS. | Item and bundle hashes match. |
| 1 | Any claim is FAIL. FAIL outranks NOT ASSESSED. | |
| 2 | No FAIL, and at least one claim is NOT ASSESSED. | |
| 3 | The claims file, plan, profile, or an unexpected crash. | The bundle is unreadable or a hash does not match. |

## Verdicts

Precedence is **FAIL**, then **NOT ASSESSED**, then **PASS**.

| Verdict | Meaning |
| --- | --- |
| PASS | Every requested property was read and matched the claim. |
| FAIL | A read value contradicts the claim. One contradiction is enough, even if another call was denied. |
| NOT ASSESSED | Evidence is missing, denied, throttled, timed out, truncated, or the resource type has no checker. The tool does not guess. |

`agent_note` is printed and stored. Checkers do not read it. There is no model on the verdict path.

## Evidence

The bundle is JSON. Each AWS call is an item with the parameters, the response or the error, and a sha256 of that item. Secret-bearing fields are redacted and twelve-digit account ids are replaced with `account-N` labels before the hash is computed. `ResponseMetadata` is not hashed. `bundle_sha256` is SHA-256 of the RFC 8785 canonical JSON for the bundle with that field removed (`rfc8785==0.1.4`). `generated_at` comes from a clock the caller can replace.

```bash
shadow-verify verify evidence.json
```

The hash shows whether the file still matches a digest you copied somewhere else (the pull request comment includes it). v0 does not sign the bundle. Rewriting the file and recomputing the hash produces a new digest; it will not match the one recorded at run time.

## When it runs

The check reads the account after a change is deployed. [examples/github-workflow.yml](examples/github-workflow.yml) runs on a push to `main` or a successful GitHub deployment. A `pull_request` run reads the account before merge, so it does not show whether the merged change landed. Use a pull request run only against a preview account that the pull request already updated, and do not assume the production role from a fork.

## GitHub Action

`action.yml` is a composite action. It installs this package with `requirements-ci.txt` as a constraint, optionally assumes a read-only role with GitHub OIDC, runs the CLI, writes the job summary, and uploads the evidence bundle. Third-party actions are pinned to commit SHAs. The sample workflow does not use `@main`. This repository has no release commit for the action itself, so the example uses a placeholder SHA and says to replace it.

CI for commit `784eb4f` is green on `ubuntu-latest` and `windows-latest`:

- push: https://github.com/christopher-kiser/shadow-verify/actions/runs/41594099486
- pull request: https://github.com/christopher-kiser/shadow-verify/actions/runs/41594105984

## Security model

- AWS calls are an exact allowlist of `service:Operation` pairs. Secret and data reads are denied first. Anything else is refused before a boto3 method is called. See [docs/iam-policy.json](docs/iam-policy.json).
- `run` accepts a boto3 Session, so a harness can count calls or simulate AccessDenied without this process building its own session.
- Credentials stay in the AWS chain or in the OIDC session the action exports. The tool does not write them into the evidence bundle. Secret-like fields are redacted before hashing.
- The stored bundle replaces account ids with `account-N` labels. It can still contain role names and policy documents. Treat it as sensitive and do not commit bundles from a real account. See [THREAT_MODEL.md](THREAT_MODEL.md).
- A denied, throttled, or timed-out call is NOT ASSESSED. Missing permission is not treated as proof that a resource is safe.

## Limits

`run` defaults to `LIVE`. `--mode MOCKED` records that the calls did not hit a real account. A MOCKED bundle is not evidence about production.

A security-group source that is a prefix list or another security group is `unresolvable_source` and the claim is NOT ASSESSED, unless a CIDR on that same port and protocol already fails. v0 does not call `GetManagedPrefixListEntries`.

S3 checks are the four public-access-block flags and `GetBucketPolicyStatus.IsPublic`. They do not read object ACLs, the bucket ACL, or the account-level public access block. The IAM action for `GetPublicAccessBlock` is `s3:GetBucketPublicAccessBlock`.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

Python 3.11 or newer. Runtime dependency is boto3. pytest and moto are for tests and the demo. The test suite is mocked.

## Roadmap

- CloudTrail as corroboration of who changed a resource. It would not grant PASS by itself.
- Terraform plan values compared with the claim and with the live resource. v0 only reports whether a `terraform_address` is present in `terraform show -json`.
- More checkers: bucket encryption, public EBS snapshots, public RDS, KMS key policy, security group egress.
- Trust-policy `Condition` comparison.
- A signature on the evidence bundle.

## Docs

- [docs/CLAIMS.md](docs/CLAIMS.md) — claim file
- [docs/IAM.md](docs/IAM.md) — read-only policy
- [docs/iam-policy.json](docs/iam-policy.json) — the policy document the test locks to the allowlist
- [AGENTS.md](AGENTS.md) — how to change this repo
- [STATUS.md](STATUS.md) — what is demonstrated
- [DECISIONS.md](DECISIONS.md) — choices and when to revisit them
