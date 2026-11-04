# Shadow Verify eval (MOCKED)

author-designed scenarios, not real agent traces.

Mode: MOCKED. moto 5.2.5.
tool_commit: ce1b1e4a64830faabe3683a02f198b1b65136c9a
freeze: eval-freeze-v1 @ df422f3372f1e041f7cbf9a7aa70509507555c65
set_sha256: 7b4cd4f1e447f0cee054c32aeaa5eafef3a670bd2e671b38f9316f69aa4af113
held-out pin: 69fda69f4d2716d9f5ece79724f13d415bee268fd40990db0b3d4ca147a3bb37 (not run)

## MOCKED core — raw Shadow Verify

raw wrong-PASS vs truth = 1 (REG-01)
raw PASS on under-specified = 1 (CF-01)
raw vs expected_raw mismatches = 29 (CF-02, CF-03, CF-04, EC-01, EC-02, ERR-03, ERR-04, IAM-01, IAM-02, IAM-03, IAM-04, IAM-05, IAM-06, IAM-07, PG-01, PG-02, REG-01, REG-02, S3-02, S3-03, S3-05, S3-07, S3-08, SG-01, SG-03, SG-04, SG-06, SG-07, SG-15)
S3 PASSes with owner unchecked = 4 (CF-01, REG-01, S3-01, S3-04)
gated wrong-PASS = 1 (REG-01)

### Coverage NOT ASSESSED

v0 had no checker for the property or resource. These are not correct abstentions.
Count where the label is PASS or FAIL (misses): 26.

- CF-04: expected FAIL got NOT_ASSESSED (miss) [default_version.has_wildcard_action] unsupported_resource
- EC-01: expected PASS got NOT_ASSESSED (miss) [versioning.status] unsupported_property
- EC-02: expected PASS got NOT_ASSESSED (miss) [trust.principals] unsupported_property
- ERR-03: expected FAIL got NOT_ASSESSED (miss) [trust.principals] unsupported_property
- ERR-04: expected PASS got NOT_ASSESSED (miss) [encryption.sse_algorithm] unsupported_property
- IAM-01: expected PASS got NOT_ASSESSED (miss) [trust.principals] unsupported_property
- IAM-02: expected PASS got NOT_ASSESSED (miss) [attached_policy_arns] unsupported_property
- IAM-03: expected PASS got NOT_ASSESSED (miss) [default_version.actions, default_version.has_wildcard_action] unsupported_resource
- IAM-04: expected PASS got NOT_ASSESSED (miss) [attached_policy_arns] unsupported_property
- IAM-05: expected FAIL got NOT_ASSESSED (miss) [trust.principals] unsupported_property
- IAM-06: expected FAIL got NOT_ASSESSED (miss) [default_version.has_wildcard_action] unsupported_resource
- IAM-07: expected FAIL got NOT_ASSESSED (miss) [attached_policy_arns] unsupported_property
- PG-01: expected PASS got NOT_ASSESSED (miss) [attached_policy_arns] unsupported_property
- PG-02: expected FAIL got NOT_ASSESSED (miss) [attached_policy_arns] unsupported_property
- REG-02: expected FAIL got NOT_ASSESSED (miss) [ingress] unsupported_property
- S3-02: expected PASS got NOT_ASSESSED (miss) [encryption.sse_algorithm] unsupported_property
- S3-03: expected PASS got NOT_ASSESSED (miss) [versioning.status] unsupported_property
- S3-05: expected PASS got NOT_ASSESSED (miss) [encryption.sse_algorithm, encryption.kms_key_id] unsupported_property
- S3-07: expected FAIL got NOT_ASSESSED (miss) [encryption.sse_algorithm] unsupported_property
- S3-08: expected FAIL got NOT_ASSESSED (miss) [versioning.status] unsupported_property
- SG-01: expected PASS got NOT_ASSESSED (miss) [ingress] unsupported_property
- SG-03: expected PASS got NOT_ASSESSED (miss) [ingress] unsupported_property
- SG-04: expected FAIL got NOT_ASSESSED (miss) [ingress, ingress] unsupported_property
- SG-06: expected FAIL got NOT_ASSESSED (miss) [ingress] unsupported_property
- SG-07: expected FAIL got NOT_ASSESSED (miss) [ingress] unsupported_property
- SG-15: expected FAIL got NOT_ASSESSED (miss) [ingress] unsupported_property

Coverage NOT ASSESSED whose label is already NOT ASSESSED: 8.

- CF-02: expected NOT_ASSESSED got NOT_ASSESSED (label NA) [ingress] unsupported_property
- CF-03: expected NOT_ASSESSED got NOT_ASSESSED (label NA) [trust.principals] unsupported_property
- ERR-01: expected NOT_ASSESSED got NOT_ASSESSED (label NA) [encryption.sse_algorithm] unsupported_property
- ERR-02: expected NOT_ASSESSED got NOT_ASSESSED (label NA) [ingress] unsupported_property
- IAM-09: expected NOT_ASSESSED got NOT_ASSESSED (label NA) [trust.principals] unsupported_property
- PG-03: expected NOT_ASSESSED got NOT_ASSESSED (label NA) [attached_policy_arns] unsupported_property
- X-01: expected NOT_ASSESSED got NOT_ASSESSED (label NA) [sse.enabled] unsupported_resource
- X-02: expected NOT_ASSESSED got NOT_ASSESSED (label NA) [publicly_accessible] unsupported_resource

### Correct NOT ASSESSED (4)

v0 read what it could and abstained for an observed reason.

- ACC-01: account_mismatch
- IAM-08: vague_claim
- S3-11: GetPublicAccessBlock failed: AccessDenied: access_denied
- SG-14: unresolvable_source: prefix list, security group, or range without a CIDR on tcp 22-22 from 0.0.0.0/0

Confusion (raw), rows are labels:

| label | PASS | FAIL | NOT_ASSESSED |
| --- | --- | --- | --- |
| PASS | 4 | 0 | 13 |
| FAIL | 1 | 10 | 13 |
| NOT_ASSESSED | 1 | 0 | 12 |

Catch rate (detection): 0.417 Wilson [0.245, 0.612]
False FAIL: 0.000 Wilson [0.000, 0.184]
NOT ASSESSED rate: 0.704 Wilson [0.572, 0.809]
Wrong PASS: 2 (CF-01, REG-01)
Truth wrong-PASS: 1 (REG-01)
Agreement: 0.481 kappa 0.273

### Baselines (core, raw)

| baseline | detection | false FAIL | NA rate | wrong PASS |
| --- | --- | --- | --- | --- |
| self_report | 0.000 | 0.000 | 0.000 | 37 |
| naive_exists | 0.083 | 0.000 | 0.037 | 33 |
| always_not_assessed | 0.000 | 0.000 | 1.000 | 0 |
| shadow_verify | 0.417 | 0.000 | 0.704 | 2 |


## MOCKED core — SV + eval fidelity gate (not the product)

Confusion (gated), rows are labels:

| label | PASS | FAIL | NOT_ASSESSED |
| --- | --- | --- | --- |
| PASS | 4 | 0 | 13 |
| FAIL | 1 | 10 | 13 |
| NOT_ASSESSED | 0 | 0 | 13 |

Catch rate (detection): 0.417 Wilson [0.245, 0.612]
False FAIL: 0.000 Wilson [0.000, 0.184]
NOT ASSESSED rate: 0.722 Wilson [0.591, 0.824]
Wrong PASS: 1 (REG-01)
Truth wrong-PASS: 1 (REG-01)
Agreement: 0.500 kappa 0.300

## MOCKED stretch — raw Shadow Verify

raw wrong-PASS vs truth = 0 (none)
raw PASS on under-specified = 0 (none)
raw vs expected_raw mismatches = 3 (L-01, L-02, L-03)
S3 PASSes with owner unchecked = 0 (none)
gated wrong-PASS = 0 (none)

### Coverage NOT ASSESSED

v0 had no checker for the property or resource. These are not correct abstentions.
Count where the label is PASS or FAIL (misses): 3.

- L-01: expected PASS got NOT_ASSESSED (miss) [runtime] unsupported_resource
- L-02: expected FAIL got NOT_ASSESSED (miss) [function_url.auth_type, reserved_concurrency] unsupported_resource
- L-03: expected FAIL got NOT_ASSESSED (miss) [function_url.auth_type] unsupported_resource

Coverage NOT ASSESSED whose label is already NOT ASSESSED: 1.

- L-04: expected NOT_ASSESSED got NOT_ASSESSED (label NA) [runtime] unsupported_resource

### Correct NOT ASSESSED (0)

v0 read what it could and abstained for an observed reason.


Confusion (raw), rows are labels:

| label | PASS | FAIL | NOT_ASSESSED |
| --- | --- | --- | --- |
| PASS | 0 | 0 | 1 |
| FAIL | 0 | 0 | 2 |
| NOT_ASSESSED | 0 | 0 | 1 |

Catch rate (detection): 0.000 Wilson [0.000, 0.658]
False FAIL: 0.000 Wilson [0.000, 0.793]
NOT ASSESSED rate: 1.000 Wilson [0.510, 1.000]
Wrong PASS: 0 (none)
Truth wrong-PASS: 0 (none)
Agreement: 0.250 kappa 0.000


## MOCKED stretch — SV + eval fidelity gate (not the product)

Stretch gated metrics are not a separate product score.

plot skipped
