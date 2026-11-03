# Shadow Verify

Shadow Verify checks whether an AI coding agent's AWS change did what the agent claimed.

After a pull request is merged or a change is deployed, it reads a claim file, queries the live account read-only, and returns a verdict for each claim: **PASS**, **FAIL**, or **NOT ASSESSED**. Every run writes a hashed evidence bundle of the API responses that produced the verdict. Rules decide the verdict. There is no model on that path. Text the agent wrote is untrusted input and cannot grant PASS.

Pre-merge IaC review reads the plan or the templates before apply. Shadow Verify runs after deploy and reads the account. A plan can be approved while the apply fails, applies only part of the change, or is overwritten later. An agent can also report success from a tool result that never landed. This tool checks the account the agent said it changed.

v0 checks three things: S3 public access block and bucket-policy publicity, EC2 security group ingress, and IAM role trust, attached policy ARNs, and star-admin. More checkers plug into the same interface.

## 60-second quickstart

No AWS account is required. The demo builds a bucket in [moto](https://github.com/getmoto/moto) where one public-access flag is false, then runs the claim an agent would write after saying the bucket was locked down. The process exits 1 because the false claim was caught.

PowerShell:

```powershell
git clone https://github.com/christopher-kiser/shadow-verify.git
cd shadow-verify
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python examples\demo\run_demo.py
```

bash:

```bash
git clone https://github.com/christopher-kiser/shadow-verify.git
cd shadow-verify
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python examples/demo/run_demo.py
```

Against a real account, put claims in `.shadow/claims.yaml` (see [docs/CLAIMS.md](docs/CLAIMS.md)) and use a role limited to the [read-only policy](docs/IAM.md):

```powershell
shadow-verify --claims .shadow\claims.yaml --region us-east-1 --evidence evidence.json
shadow-verify --claims .shadow\claims.yaml --region us-east-1 --json
```

```bash
shadow-verify --claims .shadow/claims.yaml --region us-east-1 --evidence evidence.json
```

Exit 0 when nothing failed. Exit 1 when any claim is FAIL. Exit 2 when the claims file or the invocation is invalid. NOT ASSESSED stays exit 0 unless you pass `--fail-on-not-assessed`. The GitHub Action turns that flag on so a job that cannot read AWS is not green.

`python -m shadow_verify` is the same entry point and is the reliable command on Windows if the `shadow-verify` script is not on `PATH`.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| PASS | Every requested property was read and matched the claim. |
| FAIL | A read value contradicts the claim. One contradiction is enough, even if another call was denied. |
| NOT ASSESSED | Evidence is missing, denied, throttled, or not understood. The tool does not guess. |

`agent_note` is printed and stored so a person can see what the agent said. Checkers do not read it.

## Evidence

The bundle is JSON. Each AWS call is an item with the parameters, the response or the error, and a sha256 of that item. `bundle_sha256` covers the bundle with that field removed. Canonical form is UTF-8 JSON, object keys sorted, no insignificant whitespace.

```powershell
shadow-verify --verify-evidence evidence.json
```

The hash shows whether the file still matches a digest you copied somewhere else (the pull request comment includes it). v0 does not sign the bundle. Rewriting the file and recomputing the hash produces a new digest; it will not match the one recorded at run time.

## GitHub Action

`action.yml` is a composite action. It installs this package, optionally assumes a read-only role with GitHub OIDC, runs the CLI, writes the job summary, uploads the evidence bundle, and comments on the pull request. The sample workflow is [examples/github-workflow.yml](examples/github-workflow.yml). Run it from `ubuntu-latest`. Pin the action to a commit SHA before you depend on it.

## Security model

- AWS calls go through an allowlist of `Get`, `List`, and `Describe` operations. Anything else is refused in code.
- Credentials stay in the AWS chain or in the OIDC session the action exports. The tool does not write them to disk.
- Evidence can contain account ids and policy documents. Treat the bundle as sensitive and do not commit bundles from real accounts.
- A denied call is NOT ASSESSED. Missing permission is not treated as proof that a resource is safe.

## Development

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

Python 3.11 or newer. Runtime dependency is boto3. pytest and moto are for tests and the demo.

## Roadmap

- CloudTrail as corroboration of who changed a resource. It would not grant PASS by itself.
- Terraform plan values compared with the claim and with the live resource. v0 only reports whether a `terraform_address` is present in `terraform show -json`.
- More checkers: bucket encryption, public EBS snapshots, public RDS, KMS key policy, security group egress.
- Trust-policy `Condition` comparison.
- A signature on the evidence bundle.

## Docs

- [docs/CLAIMS.md](docs/CLAIMS.md) — claim file
- [docs/IAM.md](docs/IAM.md) — read-only policy
- [AGENTS.md](AGENTS.md) — how to change this repo
- [STATUS.md](STATUS.md) — what is demonstrated
- [DECISIONS.md](DECISIONS.md) — choices and when to revisit them
