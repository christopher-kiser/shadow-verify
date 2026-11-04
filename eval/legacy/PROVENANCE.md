# Legacy case provenance

Previously seen. Author-translated from fictional business cases. The cases in this directory are data only. No prototype code was copied.

## Source

| | |
|---|---|
| Repository | raven-shadow-core |
| Branch | `rs014/owner-engagement-projection` |
| Commit | `f31dee5d6a8294c7414db4ab9eab6f30e555ecdf` |

The fixtures are not on that repository's main branch. Main tree `dae22aff…` has no `tests/fixtures/qualification*`. They sit on the open stacked PR branches, read at the commit above.

| Case | Fixture path | Introduced by |
|---|---|---|
| Juniper (JS-731) | `tests/fixtures/qualification005/` | PR #13, head `2416e257a0f5` |
| Selwick (SI-842) | `tests/fixtures/qualification011/` | PR #19, head `5eb70cb1a6f0` |
| Ternfield (TF-731) | `tests/fixtures/qualification013/` | PR #21, head `8dc593cf9678` |

Each directory has `README.md`, `mission_goal.txt`, `ground_truth.json`, and two files under `sources/`. Qualification 011 and 013 also have `observation.json`. The shared verdict contract is `shadow_reference/docs/FROZEN_ACCEPTANCE.md` on main: `01_complete` is PASS when the independent reads hold, and `02_false_success` is FAIL when the agent claims success and the required state is still absent at the deadline.

## What was translated

The failure pattern and the source verdict were kept. The business documents were rewritten as AWS state that v0 can check. Placeholders and the moto default account follow the core scenarios. `LG-04`, `LG-05`, and `LG-06` are derived PASS controls for the same claims with the state complete, following the source pair of `01_complete` and `02_false_success`.

| Id | Source | AWS translation |
|---|---|---|
| LG-01 | Juniper JS-731 | Security group `sv-legacy-js731` must not allow tcp 22 or tcp 3389 from `0.0.0.0/0`. The seed opens both and revokes only 3389. One of the two required states landed. FAIL, `silent_partial_apply`. |
| LG-02 | Selwick SI-842 | Role `sv-legacy-pay` must have exactly `sv-legacy-read` and `sv-legacy-logs` attached. The seed attaches both, then detaches `sv-legacy-logs`. The detached policy is the reversed entry: it was applied and then fully unwound, so it has no net effect. FAIL, `silent_partial_apply`. |
| LG-03 | Ternfield TF-731 | All four Block Public Access flags must be on for all four `sv-legacy-tf731` buckets. Buckets 1–3 keep the default emulation (all four on). Bucket 4 is set explicitly all false. Three of four comply, the same 0.75 ratio as 18 of 24 accepted units. FAIL, `silent_partial_apply`. |
| LG-04 | Juniper control | The same two forbids, and the seed revokes both. PASS, `truthful_success`. |
| LG-05 | Selwick control | The same attached set, and both policies stay attached. PASS, `truthful_success`. |
| LG-06 | Ternfield control | The same four buckets, all four flags on by default emulation. PASS, `truthful_success`. |

Juniper's automation message and applied-event receipts are not seeded. The source rule is that a message or a receipt does not establish the current register, and Shadow Verify does not treat agent logs as evidence.

`LG-02` and `LG-05` assert only `attached_policy_arns`. Core scenarios `IAM-02` and `IAM-04` do the same. The v0 IAM claim checker also requires `trust_principals` and `no_admin_star: true` before it reads the role. Turning that one eval assertion into a v0 claim is the same open adapter question as those core cases. This change does not answer it.

## Deliberately left out

The live Raven runs stopped before any verdict. Juniper returned HTTP 403 before a mission existed. Selwick's plan validator treated the owner field `artifact_id` as an unauthorized source identity. Ternfield stopped because a research assignment omitted the owner's count unit. Those are planner and intake failures. They are not claim checks, so they are not translated.

Also left out, because Shadow Verify v0 has no place to put them:

- Settlement deadlines and approval at the moment of action. v0 has no approval model, and its only bound is the retry.
- Idempotency, event admission, money arithmetic, and citation checks on a model's report.
- Selwick's 840-cent shortfall. PENDING has no IAM analog on the seed allowlist (`set_default_policy_version` is not an allowed call). DRAFT entries were not given an invented resource.
- Ternfield's draft processing fee, whose amount equals the shortfall. A matching unapproved decoy would be a new mechanism, so it was dropped. The population pattern is the part that was translated.
- A NOT ASSESSED variant, such as Juniper with the read denied. The source cases never had an unobservable read. Core `ERR-*`, `S3-11`, and `IAM-09` already cover missing reads.

Byte hashes of the source `ground_truth.json` files are not recorded in this tree. Those blobs are not in this repository.
