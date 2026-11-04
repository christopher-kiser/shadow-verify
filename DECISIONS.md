# Decisions

## ADR 001 — 2026-11-03 — Deterministic verdicts

**Decision.** Property rules in the checkers are the only way to reach PASS or FAIL. `agent_note` is stored and printed. It is not read by a checker.

**Reason.** The product exists because model output can claim success that the account does not show. Putting a model on the verdict path would reintroduce that failure.

**Revisit when.** A later version drafts a claim file from a plan or a pull request. That draft is still untrusted input. It still cannot grant PASS.

## ADR 002 — 2026-11-03 — FAIL outranks a missing read

**Decision.** If any property contradicts the claim, the claim is FAIL even when another required call was denied. NOT ASSESSED is used only when nothing contradicted the claim and at least one required observation is missing or not understood. An empty observation list is NOT ASSESSED.

**Reason.** A false public-access flag is already a contradiction. Waiting for a second API would hide it. A denied call with no contradiction is not proof of a problem and is not proof of safety.

**Revisit when.** A checker needs a quorum rule, for example "both the policy and CloudTrail must agree".

## ADR 003 — 2026-11-03 — Exit codes

Superseded by ADR 021. The old rule exited 0 when every claim was PASS or NOT ASSESSED, and used exit 2 for a bad claims file.

## ADR 004 — 2026-11-03 — Unknown resource types are NOT ASSESSED

**Decision.** A `resource_type` with no registered checker is NOT ASSESSED. The claim file still loads. No AWS call is made for that claim.

**Reason.** An unsupported resource is missing evidence, not a contradiction and not a pass. Exit 2 is reserved for a file the tool cannot parse. The GitHub Action fails the job on NOT ASSESSED, so a typo does not look green in CI.

**Revisit when.** A generated claims file should fail the process at load time even for a local run.

## ADR 005 — 2026-11-03 — Missing S3 public access block means the flags are false

**Decision.** `NoSuchPublicAccessBlockConfiguration` is an observation that no configuration is stored. The checker compares the four flags as false, which is the AWS default, and the reason says that.

**Reason.** The error is readable evidence of absence, and the default is documented by AWS. Treating it as NOT ASSESSED would hide buckets that were never locked down.

**Revisit when.** We see an account or partition where a missing configuration does not mean the flags are false.

## ADR 006 — 2026-11-03 — Bucket policy publicity is `IsPublic` only

**Decision.** `bucket_policy_public` is `GetBucketPolicyStatus` `PolicyStatus.IsPublic`. `NoSuchBucketPolicy` is observed as false. The checker does not parse the policy document.

**Reason.** Reimplementing AWS's public-policy rules would be a second, guessy algorithm, especially once conditions are involved.

**Revisit when.** We need the policy document in the bundle for a person, or `IsPublic` disagrees with the console in a way we can cite.

## ADR 007 — 2026-11-03 — Security group coverage is exact and one-directional

**Decision.** Superseded for CIDR coverage by ADR 018. Port ranges still overlap. A permission with protocol `-1` covers any forbidden protocol and every port. A forbidden protocol of `-1` matches only an all-protocol permission. `0.0.0.0/0` does not imply `::/0`. Security-group and prefix-list sources are not CIDRs. A matching permission with no ports is NOT ASSESSED.

**Reason.** These are the rules we can apply without guessing what "open" means. The claim lists the forbids. The checker does not invent a least-privilege judgment.

**Revisit when.** A claim needs "not reachable from the internet", which would have to include both world CIDRs and maybe prefix lists.

## ADR 008 — 2026-11-03 — IAM admin is star action plus star resource

**Decision.** `no_admin_star: true` FAILs an Allow statement whose Action is `*` or `*:*` and whose Resource is `*`. Deny does not count. `NotAction` or `NotResource` is NOT ASSESSED. Inline policies are scanned for admin and are not part of the attached-ARN set. Trust comparison uses principal values and ignores conditions. The conditions stay in the `GetRole` evidence. A role that cannot be read (`GetRole` denied or missing) stops the rest of that claim as NOT ASSESSED.

**Reason.** `*:*` admin is the check v0 promised. NotAction can express admin and can express something narrower; guessing which would be a false PASS or a false FAIL. Conditions are too important to pretend we compared them, and too wide for a first cut. Stopping after a failed `GetRole` keeps the claim to one clear reason.

**Revisit when.** We compare OIDC conditions, we decide that unclaimed inline policies should fail the claim, or we want `GetRole` denial to still scan attached policies.

## ADR 009 — 2026-11-03 — Missing resources are NOT ASSESSED

**Decision.** `NoSuchBucket`, a missing security group, and `NoSuchEntity` for a role are NOT ASSESSED.

**Reason.** The claim's properties could not be read. "The resource is gone" is a different claim (`absent: true`) that v0 does not have. Treating absence as FAIL would mix "contradicted" with "not found".

**Revisit when.** We add an explicit absence claim.

## ADR 010 — 2026-11-03 — Terraform plan does not affect verdicts

**Decision.** `--plan` records whether each `terraform_address` exists in `resource_changes` and which actions the plan lists. Checkers do not read those notes. The limit is marked TODO in `src/shadow_verify/terraform.py`.

**Reason.** A correct cross-check compares planned after-values, the claim, and the live API. Doing half of that and letting it grant PASS would be worse than leaving it informational.

**Revisit when.** We have a mapping from claim keys to plan attributes and tests where a plan/live disagreement is a FAIL.

## ADR 011 — 2026-11-03 — Evidence hashes, redaction, injected clock, no signature

**Decision.** Item and bundle digests are sha256 of canonical JSON (sorted keys, compact separators, UTF-8). Secret-bearing fields are replaced with `***REDACTED***` before that JSON is hashed or stored. `generated_at` comes from a clock passed into `run`; tests pass a fixed clock. `shadow-verify verify BUNDLE` recomputes the hashes. v0 does not sign the bundle.

**Reason.** The digest is what a person copies into a pull request comment. Hashing before redaction would freeze a secret into the digest. A wall clock makes bundle hashes differ on every run, so a golden test needs an injected clock. A signature needs a key story we do not have yet.

**Revisit when.** We sign bundles (sigstore or another published key) and verify the signature rather than only the digest.

## ADR 012 — 2026-11-03 — Exact operation allowlist and an explicit deny list

**Decision.** The client allows only the `service:Operation` pairs in `ALLOWED_OPERATIONS`. It is not a `Get*` / `List*` / `Describe*` prefix. `DENIED_OPERATIONS` (secret and data reads) is refused first, before the allowlist and before any boto3 method is resolved. `docs/iam-policy.json` lists those same actions, with no action wildcards and no `ReadOnlyAccess`.

**Reason.** A verb prefix would allow `s3:GetObject` and `secretsmanager:GetSecretValue`. Checking the deny list first keeps those calls blocked even if they are later copied onto the allowlist by mistake.

**Revisit when.** A new checker needs another read. Add the pair to the allowlist, the policy, and a mocked test in the same change. Do not add a data-plane read to either list.

## ADR 013 — 2026-11-03 — Runtime dependency is boto3

**Decision.** The installed tool depends on boto3 and the standard library. Claim YAML is a subset parser. JSON is the escape hatch. pytest and moto are dev dependencies.

**Reason.** The claim schema is small. A general YAML library adds a dependency and a much larger feature surface (anchors, tags) for files that must parse predictably.

**Revisit when.** Real claim files need YAML features the subset rejects and JSON is not an acceptable output for the agents writing them.

## ADR 014 — 2026-11-03 — CloudTrail is out of v0

**Decision.** No CloudTrail calls in v0.

**Reason.** The question v0 answers is "what is true now", which the resource APIs answer. CloudTrail answers "who changed it", which is a different evidence type and a larger IAM surface.

**Revisit when.** A checker needs to corroborate that a change happened, with an explicit rule that CloudTrail cannot grant PASS by itself.

## ADR 015 — 2026-11-03 — GitHub Action is stricter than the CLI

**Decision.** NOT ASSESSED is exit 2, so the action does not need a separate flag. The action assumes a role only when `role-to-assume` is set, installs this package from `github.action_path`, and writes a job summary.

**Reason.** A deployed-account check that could not read AWS should fail the job. Exit 2 does that without a second switch.

**Revisit when.** The action is split into a report-only mode for workflows that cannot assume the role.

## ADR 016 — 2026-11-03 — Run after deploy

**Decision.** The example workflow triggers on a push to `main` or a successful `deployment_status`. It does not trigger on `pull_request`. A pull request run is documented as a preview-account option only.

**Reason.** The product checks the account after a change is deployed. A pull request workflow reads the account before merge, so a PASS there does not mean the merged change landed.

**Revisit when.** A repository deploys from pull requests into a preview account and wants a separate workflow for that account.

## ADR 017 — 2026-11-03 — Scoped IAM policy and pinned OIDC trust

**Decision.** `ec2:DescribeSecurityGroups` is the only allow statement with `Resource` `*`, because EC2 Describe calls do not support resource scoping. S3 and IAM allows use ARN patterns. The OIDC trust policy sets `aud` to `sts.amazonaws.com` and `sub` to `repo:ORG/REPO:ref:refs/heads/main` (or an environment subject, as a replacement). It does not include a `pull_request` subject. Fork pull requests must not receive `id-token: write`.

**Reason.** A broad `ReadOnlyAccess` role and an unpinned GitHub subject would let this checker, or a fork workflow, read more than the claims require.

**Revisit when.** The claims file is known ahead of time and the role can be limited to those exact ARNs, or deploys move to a GitHub environment subject.

## ADR 018 — 2026-11-03 — Security group CIDRs use coverage, not string equality

Superseded by ADR 022. The union-covers-the-whole-target rule let a partial overlap pass.

**Decision.** A forbidden CIDR fails when the union of matching ingress CIDRs of the same IP version covers that network. One wider prefix is a cover. Two halves that together contain the target are a cover. `ipaddress` does the arithmetic. Supersedes the exact-string rule in ADR 007.

**Reason.** An exact string match lets `0.0.0.0/0` pass a forbid of `10.0.0.0/8`, and lets `0.0.0.0/1` plus `128.0.0.0/1` pass a forbid of `0.0.0.0/0`.

**Revisit when.** Prefix lists or security-group sources need to count as coverage. v0 still ignores them.

## ADR 019 — 2026-11-03 — RFC 8785 canonical JSON

**Decision.** Evidence hashes use `rfc8785==0.1.4`. `ResponseMetadata` is removed before the bytes are hashed.

**Reason.** A hand-rolled `json.dumps` is close to canonical JSON but not a named standard. `ResponseMetadata` carries `RequestId` and the HTTP date, so two runs with a fixed clock still hashed differently.

**Revisit when.** The package is unmaintained or a later RFC replaces 8785.

## ADR 020 — 2026-11-03 — Account ids are indexed, not hashed

**Decision.** Twelve-digit account ids in the stored bundle are replaced with `account-1`, `account-2`, and so on, in first-seen order for that bundle. The index is not stored. Checkers still see the original response, so the verdict does not change. Account ids are not passed through SHA-256.

**Reason.** A plain SHA-256 of an account id is reversible with a 10^12 dictionary. An HMAC with an unstored salt would also make identical runs hash differently, which fights ADR 019.

**Revisit when.** A reviewer needs to recover the account id from a bundle. That requires storing a key, which this decision refuses.

## ADR 021 — 2026-11-03 — Exit codes

**Decision.** Supersedes ADR 003. `run` exits 0 when every claim is PASS, 1 when any claim is FAIL, 2 when there is no FAIL and at least one claim is NOT ASSESSED, and 3 on a bad file, a bad profile, or an unexpected crash. `verify` exits 0 when the hashes match and 3 otherwise. FAIL still outranks NOT ASSESSED.

**Reason.** Exit 0 for NOT ASSESSED hid a check that never read AWS. An uncaught crash was easy to confuse with a claim FAIL.

**Revisit when.** A caller needs the old exit-0-on-not-assessed behavior. That would be a separate flag, not the default.

## ADR 022 — 2026-11-03 — Internet exposure is overlap, not full cover

**Decision.** Supersedes ADR 018. A forbid of `0.0.0.0/0` or `::/0` means open to the internet, for both address families. It fails if any matching CIDR overlaps a globally routable address. That check uses the pinned non-global ranges in `checkers/routable.py` (RFC 1918, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `fc00::/7`, `fe80::/10`, `::1/128`). It does not call `is_global` on the whole prefix. Any other forbid fails on any overlap. Each source inside one `IpPermissions` entry is split first. A prefix list or security-group source on that port and protocol is NOT ASSESSED (`unresolvable_source`) unless a CIDR already fails. Missing ports mean every port. Protocol numbers `6`, `17`, and `58` are tcp, udp, and icmpv6. ICMP type matching is ADR 023.

**Reason.** Full-cover let `0.0.0.0/1` pass a world forbid. A world forbid that looked at only one address family let `::/0` pass a forbid of `0.0.0.0/0`. Merged sources hid a public CIDR next to a prefix list.

**Revisit when.** Prefix lists are resolved with `GetManagedPrefixListEntries`, or the non-global list needs another range.

## ADR 023 — 2026-11-04 — ICMP matches on type, and protocol 1 is icmp

**Decision.** For `icmp` and `icmpv6`, `FromPort` is the type and `ToPort` (the code) is ignored. The permission matches when `FromPort` is absent, `FromPort` is `-1`, or `FromPort` falls inside the forbid's type range. Protocol number `1` is icmp, beside `6` (tcp), `17` (udp), and `58` (icmpv6).

**Reason.** Treating type and code as a port range let echo type 8 with code 0 or code -1 pass a forbid of that type. A raw `IpProtocol` of `1` would pass an ICMP forbid if the number map omitted it.

**Revisit when.** A claim needs to forbid one ICMP code.
