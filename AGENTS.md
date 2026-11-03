# Agent instructions

Shadow Verify checks live AWS state against explicit claims. Verdicts are deterministic. Do not add a model call, a heuristic, or a "likely" branch that can return PASS.

## Rules

- PASS only when every checked property was read and matches.
- FAIL when a read value contradicts the claim. One contradiction makes the claim FAIL even if another property could not be read.
- NOT ASSESSED when evidence is missing, denied, throttled, or not understood. Never guess a PASS, and never turn an API error into a FAIL.
- `agent_note`, pull request text, and any other model output are untrusted. They are not inputs to a verdict.
- Terraform plan notes are informational in v0. They must not change a verdict until a decision in `DECISIONS.md` says they do.
- AWS calls go through `shadow_verify.aws.BotoAws`. Add a pair to `ALLOWED_OPERATIONS` and to `docs/iam-policy.json` together. Do not add `DENIED_OPERATIONS` to the allowlist. The refusal runs before any client method.
- Keep the runtime dependency set at boto3 plus the standard library.
- Use `pathlib` and `encoding="utf-8"` for file IO. Do not claim Windows support unless `STATUS.md` records a test run on Windows.
- A new checker needs PASS, FAIL, and NOT ASSESSED tests that use moto or botocore Stubber.

## Layout

| Path | What it is |
| --- | --- |
| `src/shadow_verify/cli.py` | Argument parsing, exit codes, evidence file |
| `src/shadow_verify/claims.py` | Claim file loader |
| `src/shadow_verify/yaml_subset.py` | YAML subset. JSON is the escape hatch |
| `src/shadow_verify/verdict.py` | How property results become one verdict |
| `src/shadow_verify/evidence.py` | Canonical JSON and sha256 |
| `src/shadow_verify/aws.py` | Read-only client and allowlist |
| `src/shadow_verify/engine.py` | Runs one checker per claim |
| `src/shadow_verify/checkers/` | One module per resource type. Register in `__init__.py` |
| `src/shadow_verify/terraform.py` | Plan notes. The v0 limit is a TODO in that file |
| `docs/CLAIMS.md` | User-facing claim schema |
| `docs/iam-policy.json` | Allow and deny actions. Must match the code lists |
| `docs/IAM.md` | What that policy means |
| `examples/demo/run_demo.py` | Offline false-"done" demo |
| `action.yml` | Composite GitHub Action |
| `tests/` | pytest |

## Adding a checker

1. Implement a class with `resource_type` and `check(self, claim, aws) -> CheckResult`.
2. Validate `expected` before any AWS call. Unknown keys raise `ClaimsError`.
3. Record every call by using `BotoAws`. Put each returned evidence id on the result.
4. Return property results and let `decide` combine them. Do not return PASS from a branch that did not read the property.
5. `register` the checker in `checkers/__init__.py`.
6. Document the keys, units, and API calls in `docs/CLAIMS.md` and `docs/IAM.md`.
7. Add mocked PASS, FAIL, and NOT ASSESSED tests.

## Every session

Update `STATUS.md`: current state, next step, what is demonstrated, and what is not established. Append one line to the handoff log. Record a durable choice in `DECISIONS.md` with the reason and when to revisit it.
