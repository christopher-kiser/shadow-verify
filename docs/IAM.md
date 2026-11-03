# IAM policy

Shadow Verify calls only the operations in `ALLOWED_OPERATIONS` (`src/shadow_verify/aws.py`). The client refuses any other operation before it is sent. The role you assume should allow the same set and nothing that writes.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ShadowVerifyReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:GetPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "ec2:DescribeSecurityGroups",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion"
      ],
      "Resource": "*"
    }
  ]
}
```

v0 does not call `s3:GetBucketPolicy`. Publicity comes from `GetBucketPolicyStatus`.

`Resource` is `*` because `DescribeSecurityGroups` and the IAM read actions are awkward to scope until the claim file is known. You can tighten this later:

- S3 actions to `arn:aws:s3:::bucket-name`
- `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, and `iam:GetRolePolicy` to the role ARNs under review
- `iam:GetPolicy` and `iam:GetPolicyVersion` to the policy ARNs named in the claims

Do not attach this policy to a role that also has write access if you can avoid it. The GitHub Action assumes a role with GitHub OIDC (`sts:AssumeRoleWithWebIdentity`). The example workflow is `examples/github-workflow.yml`. The CLI itself does not assume a role; it uses the ambient AWS credential chain (`AWS_ACCESS_KEY_ID`, a profile, or the OIDC credentials the action exports).

Access denied, missing credentials, and throttling become NOT ASSESSED. They are not a FAIL, and they are not a PASS.
