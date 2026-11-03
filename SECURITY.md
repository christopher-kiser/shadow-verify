# Security

Shadow Verify is a read-only checker. It is not a scanner you point at accounts you do not own.

## What it is allowed to do

The AWS client allowlist is the exact `service:Operation` set in `src/shadow_verify/aws.py`. A separate deny list blocks secret and data reads, including `secretsmanager:GetSecretValue` and `s3:GetObject`, even if they are later added to the allowlist. Both checks run before a boto3 method is resolved. The same actions are in `docs/iam-policy.json`. Prefer a role that has no write actions.

Credentials come from the AWS SDK chain or from GitHub OIDC in the composite action. The tool does not write access keys to the evidence bundle. Do not pass keys on the command line.

## Evidence bundles

The stored bundle replaces twelve-digit account ids with `account-N` labels and redacts secret-bearing fields before the RFC 8785 hash. It can still contain role names and policy documents. Treat it as sensitive. Do not commit bundles from a real account. v0 does not sign the bundle. `shadow-verify verify` checks that the file still matches its own digests. A digest copied somewhere else is what makes a later edit visible. See `THREAT_MODEL.md`.

## GitHub Action

The action installs this repository and can assume `role-to-assume`. `action.yml` already pins `setup-python`, `configure-aws-credentials`, `upload-artifact`, and `github-script` to commit SHAs. The example workflow's own `uses:` line is still a placeholder SHA because this repository has no release commit. Grant `id-token: write` only on the job that assumes the role. Do not grant it on fork pull requests. Grant `pull-requests: write` only if that workflow posts a comment. The example does not.

## Reporting a vulnerability

Please use a private GitHub security advisory on this repository. Do not file a public issue that includes working exploit detail, credentials, or a real evidence bundle.

A bug that lets untrusted input (a claim file, `agent_note`, a Terraform plan, or model text) produce PASS without a matching AWS read is a vulnerability.
