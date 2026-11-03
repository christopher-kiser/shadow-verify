# IAM policy

The policy file is [iam-policy.json](iam-policy.json). A test checks that its Allow actions are exactly `ALLOWED_OPERATIONS` and its Deny actions are exactly `DENIED_OPERATIONS` in `src/shadow_verify/aws.py`.

Allow actions are the `service:Operation` pairs the client actually calls. There is no `s3:Get*`, no `iam:Get*`, and no AWS managed `ReadOnlyAccess` policy. v0 does not call `s3:GetBucketPolicy`. Publicity comes from `GetBucketPolicyStatus`.

Deny actions are data and secret reads: `secretsmanager:GetSecretValue`, `s3:GetObject`, `ssm:GetParameter`, `ssm:GetParameters`, `kms:Decrypt`, `dynamodb:GetItem`, `dynamodb:Query`, `dynamodb:Scan`, `lambda:GetFunction`, and `ec2:GetPasswordData`. The client refuses those, and any other call that is not on the allowlist, before it looks up a boto3 method. A write such as `s3:PutBucketPolicy` is refused the same way.

`Resource` is `*` because a generic role cannot name every bucket, security group, and role until the claims file is known. Action strings themselves contain no wildcards. You can tighten `Resource` later to the ARNs named in a specific claims file.

The GitHub Action assumes a role with GitHub OIDC (`sts:AssumeRoleWithWebIdentity`). The example workflow is `examples/github-workflow.yml`. The CLI uses the session you pass in, or the ambient AWS credential chain. It does not assume a role itself.

Access denied, throttling, timeouts, truncated pagination, and an unsupported resource type are NOT ASSESSED. They are not a FAIL, and they are not a PASS.
