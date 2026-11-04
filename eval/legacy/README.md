# Legacy evaluation set

Mode: OFFLINE. MOCKED when a later runner scores it. These files are declarative data. Nothing here calls AWS or the network.

`LG-01` through `LG-06` are previously seen cases translated from the raven-shadow-core qualification fixtures for Juniper, Selwick, and Ternfield. They are author-translated from fictional business cases. They are previously seen. They are scored and reported in their own table, and they are never part of the core set or the held-out set.

Ids match `^LG-\d{2}$`. That prefix belongs to this directory. A legacy id never appears under `eval/scenarios/` or in the core manifest.

The core command `python -m eval.manifest --check` does not read this directory. Check this set with `--out eval/legacy` and `--files` naming each file. `--files` without `--out` exits 2. `--out` that resolves, case-insensitively, to `eval/`, `eval/scenarios`, `eval/labels`, or `eval/heldout` also exits 2. That includes `eval`, `./eval/`, `EVAL`, a backslash separator, and an absolute path. Every `--files` path must resolve under that directory. Those rules keep this set from writing `eval/manifest.json` or `eval/MANIFEST.sha256`.

## Labels

Order: label, then adjudicate, then write the manifest.

Sentinel labels `LG-01` through `LG-06` blind, from the claim, the seed, and the condition. The label file is `eval/legacy/labels/sentinel.json`. A disagreement is recorded in `eval/legacy/labels/adjudication.md`. Both are still TODO. This change does not commit `manifest.json` or `MANIFEST.sha256`. Those files are written after the labels, with `--out eval/legacy` and `--files`.

## What is here

- `scenarios/LG-01.json` through `scenarios/LG-06.json` hold the claim, the seed, and the author labels.
- `PROVENANCE.md` records the source repo, branch, commit, fixture paths, source hashes, the mapping, and what was left out.

`LG-01` and `LG-04` use security-group ingress forbids. `LG-03` and `LG-06` use the four S3 Block Public Access flags. `LG-02` and `LG-05` assert only `attached_policy_arns`. v0's IAM checker requires `trust_principals`, `attached_policy_arns`, and `no_admin_star` together, so those two cases cannot be run as written. Every seed call is on the core seed allowlist.
