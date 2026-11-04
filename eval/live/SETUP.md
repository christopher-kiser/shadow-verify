# LIVE evaluation

This path is manual. The mocked harness does not take it. `python -m eval.run --live` exits 2 and does not seed, write, or call AWS.

A live run, when someone adds it later, must:

- Use only scenarios Christopher listed in `eval/live/manifest.json`.
- Use the read-only actions in `docs/iam-policy.json`.
- Never seed and never write to the account.
- HMAC or drop the account id before anything is stored.
- Keep its table separate from every MOCKED result.

MOCKED numbers are not evidence about a live account.
