# Decisions

## Deterministic verdicts

**Decision.** Property rules in the checkers are the only way to reach PASS or FAIL. `agent_note` is stored and printed. It is not read by a checker.

**Reason.** The product exists because model output can claim success that the account does not show. Putting a model on the verdict path would reintroduce that failure.

**Revisit when.** A later version drafts a claim file from a plan or a pull request. That draft is still untrusted input. It still cannot grant PASS.

## FAIL outranks a missing read

**Decision.** If any property contradicts the claim, the claim is FAIL even when another required call was denied. NOT ASSESSED is used only when nothing contradicted the claim and at least one required observation is missing or not understood. An empty observation list is NOT ASSESSED.

**Reason.** A false public-access flag is already a contradiction. Waiting for a second API would hide it. A denied call with no contradiction is not proof of a problem and is not proof of safety.

**Revisit when.** A checker needs a quorum rule, for example "both the policy and CloudTrail must agree".

## Exit codes

**Decision.** Exit 1 on any FAIL. Exit 2 on a bad claims file, a bad plan file, or a bad profile. Exit 0 when every claim is PASS or NOT ASSESSED. `--fail-on-not-assessed` also exits 1 on NOT ASSESSED. The GitHub Action defaults that flag to true.

**Reason.** The CLI spec is "non-zero on any FAIL". A local run that cannot read one optional property should still show the passes. A CI job that never reached AWS should not look green, so the action is stricter.

**Revisit when.** Users want NOT ASSESSED to fail the CLI by default.

## Unknown resource types are claims errors

**Decision.** A `resource_type` with no registered checker fails at load time with exit 2. The engine still returns NOT ASSESSED if a checker disappears between load and run.

**Reason.** A typo such as `s3_bukcet` would otherwise exit 0 and look like a successful check.

**Revisit when.** Claims are generated for checkers this process does not have installed, and a soft skip is more useful than a hard error.

## Missing S3 public access block means the flags are false

**Decision.** `NoSuchPublicAccessBlockConfiguration` is an observation that no configuration is stored. The checker compares the four flags as false, which is the AWS default, and the reason says that.

**Reason.** The error is readable evidence of absence, and the default is documented by AWS. Treating it as NOT ASSESSED would hide buckets that were never locked down.

**Revisit when.** We see an account or partition where a missing configuration does not mean the flags are false.

## Bucket policy publicity is `IsPublic` only

**Decision.** `bucket_policy_public` is `GetBucketPolicyStatus` `PolicyStatus.IsPublic`. `NoSuchBucketPolicy` is observed as false. The checker does not parse the policy document.

**Reason.** Reimplementing AWS's public-policy rules would be a second, guessy algorithm, especially once conditions are involved.

**Revisit when.** We need the policy document in the bundle for a person, or `IsPublic` disagrees with the console in a way we can cite.

## Security group coverage is exact and one-directional

**Decision.** CIDR match is an exact string. Port ranges overlap. A permission with protocol `-1` covers any forbidden protocol and every port. A forbidden protocol of `-1` matches only an all-protocol permission. `0.0.0.0/0` does not imply `::/0`. Security-group and prefix-list sources do not satisfy a CIDR forbid. A matching permission with no ports is NOT ASSESSED.

**Reason.** These are the rules we can apply without guessing what "open" means. The claim lists the forbids. The checker does not invent a least-privilege judgment.

**Revisit when.** A claim needs "not reachable from the internet", which would have to include both world CIDRs and maybe prefix lists.

## IAM admin is star action plus star resource

**Decision.** `no_admin_star: true` FAILs an Allow statement whose Action is `*` or `*:*` and whose Resource is `*`. Deny does not count. `NotAction` or `NotResource` is NOT ASSESSED. Inline policies are scanned for admin and are not part of the attached-ARN set. Trust comparison uses principal values and ignores conditions. The conditions stay in the `GetRole` evidence. A role that cannot be read (`GetRole` denied or missing) stops the rest of that claim as NOT ASSESSED.

**Reason.** `*:*` admin is the check v0 promised. NotAction can express admin and can express something narrower; guessing which would be a false PASS or a false FAIL. Conditions are too important to pretend we compared them, and too wide for a first cut. Stopping after a failed `GetRole` keeps the claim to one clear reason.

**Revisit when.** We compare OIDC conditions, we decide that unclaimed inline policies should fail the claim, or we want `GetRole` denial to still scan attached policies.

## Missing resources are NOT ASSESSED

**Decision.** `NoSuchBucket`, a missing security group, and `NoSuchEntity` for a role are NOT ASSESSED.

**Reason.** The claim's properties could not be read. "The resource is gone" is a different claim (`absent: true`) that v0 does not have. Treating absence as FAIL would mix "contradicted" with "not found".

**Revisit when.** We add an explicit absence claim.

## Terraform plan does not affect verdicts

**Decision.** `--plan` records whether each `terraform_address` exists in `resource_changes` and which actions the plan lists. Checkers do not read those notes. The limit is marked TODO in `src/shadow_verify/terraform.py`.

**Reason.** A correct cross-check compares planned after-values, the claim, and the live API. Doing half of that and letting it grant PASS would be worse than leaving it informational.

**Revisit when.** We have a mapping from claim keys to plan attributes and tests where a plan/live disagreement is a FAIL.

## Evidence hashes, no signature

**Decision.** Item and bundle digests are sha256 of canonical JSON (sorted keys, no insignificant whitespace, UTF-8). `--verify-evidence` checks internal consistency. v0 does not sign the bundle.

**Reason.** The digest is what a person copies into a pull request comment or a ticket. A signature needs a key story we do not have yet. Internal consistency alone does not stop someone who can rewrite the file and rehash it.

**Revisit when.** We sign bundles (sigstore or another published key) and verify the signature rather than only the digest.

## Runtime dependency is boto3

**Decision.** The installed tool depends on boto3 and the standard library. Claim YAML is a subset parser. JSON is the escape hatch. pytest and moto are dev dependencies.

**Reason.** The claim schema is small. A general YAML library adds a dependency and a much larger feature surface (anchors, tags) for files that must parse predictably.

**Revisit when.** Real claim files need YAML features the subset rejects and JSON is not an acceptable output for the agents writing them.

## CloudTrail is out of v0

**Decision.** No CloudTrail calls in v0.

**Reason.** The question v0 answers is "what is true now", which the resource APIs answer. CloudTrail answers "who changed it", which is a different evidence type and a larger IAM surface.

**Revisit when.** A checker needs to corroborate that a change happened, with an explicit rule that CloudTrail cannot grant PASS by itself.

## GitHub Action is stricter than the CLI

**Decision.** `fail-on-not-assessed` defaults to true in `action.yml` and false in the CLI. The action assumes a role only when `role-to-assume` is set, installs this package from `github.action_path`, and posts a comment plus a job summary.

**Reason.** Local exploration should show NOT ASSESSED without failing the process. A pull request check that could not read the account should fail.

**Revisit when.** The action is split into a "report only" mode for forks that cannot assume the role.
