# Threat model

## What this tool is for

Shadow Verify compares a claims file to live AWS read APIs and writes a hashed evidence bundle. It does not decide that a change is safe. A person reads the verdict and the bundle.

## Untrusted inputs

The coding agent is untrusted. A claim, `agent_note`, tool output, pull request text, and any model output are untrusted text. They are recorded and are not inputs to PASS or FAIL. No model is in the verdict path. Prompt injection in a claim or a tool result cannot grant PASS.

A pull request is untrusted, including one from a fork. Fork workflows must not receive `id-token: write`. The OIDC trust policy in `docs/oidc-trust-policy.json` allows only `repo:ORG/REPO:ref:refs/heads/main` (or an environment subject you substitute for that line). It does not allow `repo:ORG/REPO:pull_request`.

The claims file and an optional Terraform plan are untrusted. A bad file is a tool error (exit 3). A claim the checkers do not understand is NOT ASSESSED (exit 2), not PASS. Plan notes do not change a verdict.

## Trusted parts

The verifier code that is reviewed and installed is the trusted part: the checkers, the allowlist, the IAM map, and the evidence hasher. A person trusts a run only after they trust that commit (`tool_commit` in the bundle).

Verifier configuration that can change what runs (the workflow, `action.yml`, and this repository's code) must be read from the protected base branch, not from the pull request head. A pull request that edits the workflow or the checker must not be the copy that runs against production credentials.

## Credentials

The IAM policy is `docs/iam-policy.json`. It allows the mapped read actions and denies secret and data reads. The client refuses those calls, and any call outside the allowlist, before it resolves a boto3 method.

The role is assumed with GitHub OIDC. `aud` is `sts.amazonaws.com`. The CLI does not write access keys into the bundle. Twelve-digit account ids in the stored bundle are replaced with `account-N` labels. That index is not stored and is not a SHA-256 of the account id.

Each AWS call uses standard retries, 3 attempts, a 3 second connect timeout, and a 10 second read timeout. One call can take about 52 seconds in the worst case.

## GitHub token

The example job's token can read contents and request an OIDC token. It does not have `checks: write` or `actions: write`. The composite action can comment on a pull request only when the caller grants `pull-requests: write` and the event is `pull_request`. The example does not. Do not grant the token write access to the production repository from a fork.

## Evidence

The bundle is hashed with SHA-256 over RFC 8785 bytes after redaction and after `ResponseMetadata` is removed. It is not signed. Anyone who can edit the file can recompute a new hash. The hash only shows a change if an earlier copy of `bundle_sha256` was stored somewhere else, such as a job log on the protected branch's workflow.

`mode` is `MOCKED` or `LIVE`. A MOCKED bundle is not evidence about a real account.

## Out of scope for v0

CloudTrail, a signature, and new checkers are not in this version. CI for `50d5a72` passed on `ubuntu-latest` and `windows-latest`.
