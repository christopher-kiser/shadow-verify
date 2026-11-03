# Security

Shadow Verify is a read-only checker. It is not a scanner you point at accounts you do not own.

## What it is allowed to do

The AWS client allowlist is the exact `service:Operation` set in `src/shadow_verify/aws.py`. A separate deny list blocks secret and data reads, including `secretsmanager:GetSecretValue` and `s3:GetObject`, even if they are later added to the allowlist. Both checks run before a boto3 method is resolved. The same actions are in `docs/iam-policy.json`. Prefer a role that has no write actions.

Credentials come from the AWS SDK chain or from GitHub OIDC in the composite action. The tool does not write access keys to the evidence bundle. Do not pass keys on the command line.

## Evidence bundles

Bundles contain the API responses used for the verdict. That can include account ids, role ARNs, and IAM policy documents. Treat them as sensitive. Do not commit bundles from a real account. v0 hashes the bundle after redacting secret-bearing fields. It does not sign it. `shadow-verify verify` checks that the file still matches its own digests. A digest copied to a pull request comment is what makes a later edit visible.

## GitHub Action

The action installs this repository and can assume `role-to-assume`. Pin `action.yml` and the actions it uses (`setup-python`, `configure-aws-credentials`, `upload-artifact`, `github-script`) to commit SHAs before you depend on them in production. Grant `id-token: write` and `pull-requests: write` only on the workflow that should post the verdict.

## Reporting a vulnerability

Please use a private GitHub security advisory on this repository. Do not file a public issue that includes working exploit detail, credentials, or a real evidence bundle.

A bug that lets untrusted input (a claim file, `agent_note`, a Terraform plan, or model text) produce PASS without a matching AWS read is a vulnerability.
