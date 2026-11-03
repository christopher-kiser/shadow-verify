# Contributing

Issues and pull requests are welcome.

Run the tests before you open a pull request. They are mocked; they do not call AWS.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
python examples/demo/run_demo.py
```

The demo exits 1. That is the tool catching the false claim. Windows: NOT ASSESSED until a green `windows-latest` job exists. The latest matrix run failed at the audit step on both operating systems: https://github.com/christopher-kiser/shadow-verify/actions/runs/41592185575

Read `AGENTS.md` before adding a checker. Verdicts stay deterministic: a change that lets model text or a missing API call produce PASS will not be accepted. Update `docs/CLAIMS.md` and `docs/IAM.md` when the claim schema or the AWS calls change. Update `STATUS.md` and, when you make a durable choice, `DECISIONS.md`.

Please keep pull requests focused. v0 would rather have one well-tested checker than several sketched ones.
