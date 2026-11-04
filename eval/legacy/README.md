# Legacy evaluation set

Mode: OFFLINE. MOCKED when a later runner scores it. These files are declarative data. Nothing here calls AWS or the network.

`LG-01` through `LG-06` are previously seen cases translated from the raven-shadow-core qualification fixtures for Juniper, Selwick, and Ternfield. They are author-translated from fictional business cases. They are previously seen. They are scored and reported in their own table, and they are never part of the core set or the held-out set.

Ids match `^LG-\d{2}$`. That prefix belongs to this directory. A legacy id never appears under `eval/scenarios/` or in the core manifest.

The core command `python -m eval.manifest --check` does not read this directory. Check this set with `--out eval/legacy` and `--files` naming each file. `--files` without `--out` exits 2, so this set cannot overwrite `eval/manifest.json` or `eval/MANIFEST.sha256`.

## Labels

Freeze order: author, then label, then adjudicate, then freeze.

Sentinel labels `LG-01` through `LG-06` blind, from the claim, the seed, and the condition. The label file is `eval/legacy/labels/sentinel.json`. A disagreement is recorded in `eval/legacy/labels/adjudication.md`. Both are still TODO. This manifest names the six scenario files only. Adding the label files means a new manifest.

## What is here

- `scenarios/LG-01.json` through `scenarios/LG-06.json` hold the claim, the seed, and the author labels.
- `PROVENANCE.md` records the source repo, branch, commit, fixture paths, the mapping, and what was left out.
- `manifest.json` is the record from `python -m eval.manifest --out eval/legacy --files …`: `version`, `created`, `author`, a sha256 for each named file, and `set_sha256`.
- `MANIFEST.sha256` is that same `set_sha256`, on one line.

`created` is `2026-11-04` and `author` is `Forge`. Paths are POSIX, sorted by UTF-8 bytes. The cases use only properties v0 checks today: security-group ingress forbids, the four S3 Block Public Access flags, and an IAM role's attached policy ARN set. Every seed call is on the core seed allowlist.
