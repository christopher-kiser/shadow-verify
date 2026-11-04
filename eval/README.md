# Evaluation set

Mode: OFFLINE. These files are declarative data. Nothing here calls AWS or the network, and nothing here is a scored run.

This change freezes the evaluation set only. The runner, the seeder, and the scoring code are not in this change. They come later, after the v0 pull request merges, so the first scored run happens after the freeze.

Freeze order: label, adjudicate, freeze, then first run.

## What is frozen

- `SPEC.md` is eval spec v7, copied verbatim.
- `scenarios/` holds 54 core cases and 4 stretch cases (`L-01` through `L-04`). Each file has the claim, the seed steps, and the labels.
- `labels/forge.json` is the spec's expected labels.
- `labels/sentinel.json` is the second labeler's file, copied verbatim.
- `labels/adjudication.md` records the one failure-type disagreement (`CF-04`).
- `labels/known_gaps.json` is `["CF-02"]`.
- `manifest.json` is the core freeze record from `python -m eval.manifest`: `version`, `created`, `author`, a sha256 for each named file, and `set_sha256`.
- `MANIFEST.sha256` is that same `set_sha256`, on one line.
- `heldout.manifest.json` and `heldout/MANIFEST.sha256` pin the held-out set. The case files are not in this repo. The pinned `set_sha256` is `69fda69f4d2716d9f5ece79724f13d415bee268fd40990db0b3d4ca147a3bb37`.

The core manifest names exactly the scenario files, `labels/sentinel.json`, `labels/adjudication.md`, and `labels/known_gaps.json`. Paths are POSIX, sorted by UTF-8 bytes. Check it with:

```
python -m eval.manifest --check
```

A mismatch exits 2 and names the file whose bytes no longer match. The held-out pin is checked there too, and a wrong `set_sha256` fails the check.

Scenarios are author-designed, not real agent traces. Labeled OFFLINE.
