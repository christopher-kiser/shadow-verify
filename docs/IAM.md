# IAM policy

The policy file is [iam-policy.json](iam-policy.json). A test checks that its Allow actions are exactly `ALLOWED_OPERATIONS` and its Deny actions are exactly `DENIED_OPERATIONS` in `src/shadow_verify/aws.py`.

Allow actions are the `service:Operation` pairs the client actually calls. There is no `s3:Get*`, no `iam:Get*`, and no AWS managed `ReadOnlyAccess` policy. v0 does not call `s3:GetBucketPolicy`. Publicity comes from `GetBucketPolicyStatus`.

Deny actions are data and secret reads: `secretsmanager:GetSecretValue`, `s3:GetObject`, `ssm:GetParameter`, `ssm:GetParameters`, `kms:Decrypt`, `dynamodb:GetItem`, `dynamodb:Query`, `dynamodb:Scan`, `lambda:GetFunction`, and `ec2:GetPasswordData`. The client refuses those, and any other call that is not on the allowlist, before it looks up a boto3 method. A write such as `s3:PutBucketPolicy` is refused the same way.

`ec2:DescribeSecurityGroups` is its own statement with `Resource` `*`. EC2 Describe calls do not support resource-level permissions. S3 actions are limited to `arn:aws:s3:::*`. IAM role reads are limited to `arn:aws:iam::*:role/*`. IAM policy reads are limited to `arn:aws:iam::*:policy/*` and `arn:aws:iam::aws:policy/*`. Action strings contain no wildcards.

## OIDC trust

The GitHub Action assumes a role with `sts:AssumeRoleWithWebIdentity`. The trust policy is [oidc-trust-policy.json](oidc-trust-policy.json). Replace the account id and `ORG/REPO` before you attach it.

`token.actions.githubusercontent.com:aud` is `sts.amazonaws.com`. `token.actions.githubusercontent.com:sub` is `repo:ORG/REPO:ref:refs/heads/main`. If you deploy through a GitHub environment, replace that subject with `repo:ORG/REPO:environment:ENVIRONMENT` instead of adding a second statement. Do not add `repo:ORG/REPO:pull_request`. That subject is what fork pull requests present, and it would let an untrusted workflow assume the role.

The example workflow runs on a push to `main` or a successful deployment. It does not run on `pull_request`, and it does not grant `id-token: write` to fork runs. A `pull_request` job would read the account before the change is merged. Use that only for a preview account the pull request already updated, and still skip forks:

```yaml
if: github.event.pull_request.head.repo.full_name == github.repository
```

The CLI uses the session you pass in, or the ambient AWS credential chain. It does not assume a role itself. The example workflow is [examples/github-workflow.yml](../examples/github-workflow.yml).

Access denied, throttling, timeouts, truncated pagination, and an unsupported resource type are NOT ASSESSED. They are not a FAIL, and they are not a PASS.
