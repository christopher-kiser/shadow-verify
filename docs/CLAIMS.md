# Claims

A claims file is the contract Shadow Verify checks. A person or a coding agent writes it. The verifier does not trust prose in the file. It trusts `expected` only, and only after reading AWS.

JSON and a small YAML subset are both accepted. Generated claims should use JSON. The YAML subset is documented below and is intentionally small so a claim parses the same way on every machine without another dependency.

Copy `examples/claims.example.yaml` to `.shadow/claims.yaml` and edit it.

## Document

```yaml
version: 1
claims:
  - id: logs-locked
    statement: S3 bucket locked down
    resource_type: s3_bucket
    identifier: logs-prod
    agent_note: Agent says public access is blocked.
    terraform_address: aws_s3_bucket.logs
    expected:
      block_public_acls: true
```

| Field | Required | Meaning |
| --- | --- | --- |
| `version` | yes | Integer `1`. |
| `id` | yes | Stable name, unique in the file. |
| `statement` | no | Human sentence. Printed, not judged. |
| `resource_type` | yes | `s3_bucket`, `ec2_security_group`, or `iam_role`. |
| `identifier` | yes | The live resource id. See each checker. |
| `expected` | yes | The properties to compare. Unknown keys are an error. |
| `agent_note` | no | Untrusted model text. Recorded. Never an input to the verdict. |
| `terraform_address` | no | Optional address in a `terraform show -json` plan. Informational in v0. |

An unknown `resource_type` is NOT ASSESSED. It is not a pass. Register a checker before a new type can pass. See `AGENTS.md`.

## Units

Booleans are `true` or `false`. Ports are integers from 0 through 65535. Principals and policy ARNs are exact strings. A security-group forbid fails when the union of matching ingress CIDRs covers that network, including a wider prefix or several narrower ones. `0.0.0.0/0` does not imply `::/0`.

## `s3_bucket`

`identifier` is the bucket name.

| Key | API | Rule |
| --- | --- | --- |
| `block_public_acls` | `GetPublicAccessBlock` `BlockPublicAcls` | Boolean equality. |
| `ignore_public_acls` | `IgnorePublicAcls` | Boolean equality. |
| `block_public_policy` | `BlockPublicPolicy` | Boolean equality. |
| `restrict_public_buckets` | `RestrictPublicBuckets` | Boolean equality. |
| `bucket_policy_public` | `GetBucketPolicyStatus` `PolicyStatus.IsPublic` | Boolean equality. |

Check only the keys you list. At least one is required.

`NoSuchPublicAccessBlockConfiguration` means no configuration is stored. AWS treats the four flags as false in that case, so the checker compares `false`. The reason text says so.

`NoSuchBucketPolicy` means there is no bucket policy, so `bucket_policy_public` is observed as `false`.

The policy document is not parsed. Publicity is only the `IsPublic` boolean AWS returns. `NoSuchBucket` is NOT ASSESSED: the bucket is not there to read.

## `ec2_security_group`

`identifier` is the security group id (`sg-...`).

```yaml
expected:
  ingress_forbidden:
    - protocol: tcp
      from_port: 22
      to_port: 22
      cidr: 0.0.0.0/0
```

`protocol` is `tcp`, `udp`, `icmp`, `icmpv6`, `all`, or `-1`. `all` and `-1` are the same claim and cover every observed protocol. Ports are required even for `-1`, so the range is explicit. An ICMP permission is then compared by type. A permission whose protocol is `-1` matches on any overlapping port range. Observed protocol numbers `1`, `6`, `17`, and `58` are icmp, tcp, udp, and icmpv6. For ICMP, `from_port`/`to_port` in the claim are the type range. The observed `FromPort` is the type and is compared to that range; the observed code (`ToPort`) is ignored. Type `-1` matches every ICMP forbid.

Each source in one ingress permission is judged on its own. A forbid of `0.0.0.0/0` or `::/0` means open to the internet, for both address families: it fails if any matching CIDR overlaps a globally routable address. Any other forbid fails on any CIDR overlap. Protocol numbers `1`, `6`, `17`, and `58` are icmp, tcp, udp, and icmpv6. Missing ports mean every port. An ICMP type of `-1` matches every ICMP forbid; the ICMP code is ignored. A prefix list, a security-group source, or a range entry with no CIDR on that port and protocol is `unresolvable_source` (NOT ASSESSED) unless a CIDR on the same permission already fails.

This checker does not prove least privilege. It proves the listed forbids are absent.

## `iam_role`

`identifier` is the role name, or a role ARN (`arn:aws:iam::123456789012:role/team/app-deploy` uses the name after the last `/`). When the identifier is an ARN, the partition and account are compared with `Role.Arn` from `GetRole`. If either differs, or that Arn cannot be read, the claim is NOT ASSESSED (`arn_mismatch`). The same-named role in the caller's account is not the claimed role.

All three keys are required in v0:

```yaml
expected:
  trust_principals:
    - arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com
  attached_policy_arns:
    - arn:aws:iam::123456789012:policy/app-deploy
  no_admin_star: true
```

`trust_principals` is the set of principal values on Allow statements (`AWS`, `Service`, `Federated`, `CanonicalUser`, or `*`). Order does not matter. Extra or missing values FAIL. Conditions are not compared. They remain in the `GetRole` evidence for a person to read. `no_admin_star` must be `true`.

`attached_policy_arns` is the exact set of attached managed policy ARNs. Inline policy names are not part of that set.

`no_admin_star` scans the trust policy, every inline policy, and the default version of every attached policy. Action names are matched without case. It FAILs an unconditional Allow of `*` or `*:*`, and an Allow NotAction, on all resources. A resource pattern is scoped only when its partition and service are literal and the rest is not purely wildcards; anything else counts as all resources, including `*`, `arn:aws:?*:*:*:*`, `arn:aws:*:*:*:?*`, `arn:aws-us-gov:*`, and `arn:aws-cn:*:*:*:*`. An Allow of `*:Put*`, `iam:*Policy*`, `iam:Create*`, `iam:Update*`, `iam:*`, `iam:Put*Policy`, `iam:Attach*Policy`, `iam:CreatePolicyVersion`, `iam:PassRole`, `iam:SetDefaultPolicyVersion`, `iam:CreateAccessKey`, `iam:UpdateAssumeRolePolicy`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, or `iam:AddUserToGroup` on all resources is NOT ASSESSED (`may_grant_admin`). Any other Allow NotAction or NotResource is NOT ASSESSED (`not_action_unsupported`). An otherwise-admin Allow that also has a Condition is NOT ASSESSED (`condition_unsupported`); the condition is not evaluated, and the statement is not a pass. A Deny statement is ignored and does not cancel an Allow. An unreadable policy document is NOT ASSESSED. A non-admin inline policy does not, by itself, fail the ARN comparison. A PASS does not rule out every privilege-escalation path. The check covers star admin and the named escalation actions only.

## YAML subset

Supported: spaces, comments, mappings, lists, strings, booleans (`true`/`false`), integers, `null`, and quoted strings.

Rejected, with an error that points at JSON: tabs, anchors, aliases, tags, merge keys, flow collections (`[]`, `{}`), and multiline `|` / `>` strings. One space after a list dash. Nested keys under a list item align two spaces past the dash:

```yaml
claims:
  - id: logs-locked
    expected:
      block_public_acls: true
```

## Verdicts

Each present key becomes a property result.

- Any FAIL property makes the claim FAIL, even if another property could not be read.
- Otherwise any NOT ASSESSED property makes the claim NOT ASSESSED.
- Otherwise the claim is PASS.

A checker that reads nothing does not pass. Model text cannot grant PASS.

## Limits

A forbid of `all` on ports `22-22` is not "any ICMP". An ICMP permission is compared by type, and type 8 (echo) is outside `22-22`, so this forbid does not fail that rule:

```yaml
ingress_forbidden:
  - protocol: all
    from_port: 22
    to_port: 22
    cidr: 0.0.0.0/0
```

ICMP type 22 would match. Echo is covered by an `icmp` forbid whose type range includes 8, or by `all` on `0-65535`.
