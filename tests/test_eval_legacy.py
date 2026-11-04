"""Offline checks for the legacy eval set. No AWS and no network.

The legacy cases are scored apart from the core freeze and the held-out pin.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from tests.helpers import CONDITIONS, SEED_ALLOWLIST
from eval.manifest import (
    CORE_FILES,
    check,
    heldout_problems,
    main,
    set_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / "eval" / "legacy"
SCENARIOS = LEGACY / "scenarios"
CORE_SET = "7b4cd4f1e447f0cee054c32aeaa5eafef3a670bd2e671b38f9316f69aa4af113"
LEGACY_ID = re.compile(r"^LG-\d{2}$")

# Assertion shapes in the legacy files.
# Security-group forbids map to ingress_forbidden. The four PAB flags are what
# the S3 checker reads. LG-02 and LG-05 assert only attached_policy_arns.
# v0's IAM checker requires trust_principals, attached_policy_arns, and
# no_admin_star together, so those two cases cannot be run as written.
SCENARIO_OPS = {
    "security_group": {"ingress": {"not_contains"}},
    "s3_bucket": {
        "pab.block_public_acls": {"eq"},
        "pab.ignore_public_acls": {"eq"},
        "pab.block_public_policy": {"eq"},
        "pab.restrict_public_buckets": {"eq"},
    },
    "iam_role": {"attached_policy_arns": {"equals_set"}},
}

FAILURE_TYPES = {
    "truthful_success",
    "silent_partial_apply",
    "hallucinated_success",
    "out_of_scope_mutation",
    "drift_after_apply",
    "stale_after_retry",
    "unverifiable",
}
VERDICTS = {"PASS", "FAIL", "NOT_ASSESSED"}
_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _legacy_files() -> tuple[str, ...]:
    names = sorted(path.name for path in SCENARIOS.glob("*.json"))
    return tuple(f"eval/legacy/scenarios/{name}" for name in names)


def _encoding_problems(name: str, raw: bytes) -> list[str]:
    problems: list[str] = []
    if b"\r" in raw:
        problems.append(f"{name} has CR")
    if not raw.endswith(b"\n"):
        problems.append(f"{name} missing trailing newline")
    return problems


def _identity_problems(path: Path, scenario: dict) -> tuple[str, list[str]]:
    example = json.loads(
        (ROOT / "eval" / "scenarios" / "SG-05.json").read_text(encoding="utf-8")
    )
    problems: list[str] = []
    if set(scenario) != set(example):
        problems.append(f"{path.name} keys {sorted(set(scenario) ^ set(example))}")
    sid = scenario.get("id")
    if sid != path.stem or LEGACY_ID.fullmatch(str(sid)) is None:
        problems.append(f"{path.name} id {sid}")
    resource_type = scenario.get("resource_type")
    if not isinstance(resource_type, str) or re.fullmatch(r"[a-z0-9_]+", resource_type) is None:
        problems.append(f"{sid} resource_type")
    if resource_type not in SCENARIO_OPS:
        problems.append(f"{sid} resource_type {resource_type} is not one of the legacy shapes")
    return str(sid), problems


def _claim_problems(sid: str, scenario: dict) -> list[str]:
    resource_type = scenario.get("resource_type")
    claim = scenario.get("agent_claim")
    if not isinstance(claim, dict) or set(claim) != {"text", "structured", "prose_assertions"}:
        return [f"{sid} agent_claim"]
    problems: list[str] = []
    if not isinstance(claim.get("text"), str) or not claim["text"].strip():
        problems.append(f"{sid} empty text")
    if claim.get("prose_assertions") != "same":
        problems.append(f"{sid} prose_assertions")
    structured = claim.get("structured")
    resources = structured.get("resources") if isinstance(structured, dict) else None
    if set(structured or {}) != {"resources"} or not isinstance(resources, list) or not resources:
        return [*problems, f"{sid} structured"]
    for index, resource in enumerate(resources):
        problems.extend(_resource_problems(sid, resource_type, index, resource))
    return problems


def _resource_problems(sid: str, resource_type, index: int, resource: dict) -> list[str]:
    if set(resource) != {
        "resource_type",
        "resource_id",
        "region",
        "account_id",
        "assertions",
    }:
        return [f"{sid} resource {index} keys"]
    problems: list[str] = []
    if resource["resource_type"] != resource_type:
        problems.append(f"{sid} resource {index} type")
    if not isinstance(resource["resource_id"], str) or not resource["resource_id"]:
        problems.append(f"{sid} resource {index} id")
    region = resource["region"]
    if resource_type == "iam_role":
        if region is not None:
            problems.append(f"{sid} iam region")
    elif not isinstance(region, str) or not region:
        problems.append(f"{sid} region")
    if resource["account_id"] is not None:
        problems.append(f"{sid} account_id")
    assertions = resource["assertions"]
    if not isinstance(assertions, list) or not assertions:
        return [*problems, f"{sid} resource {index} assertions"]
    allowed = SCENARIO_OPS.get(resource_type, {})
    for assertion in assertions:
        if set(assertion) != {"property", "op", "value"}:
            problems.append(f"{sid} assertion keys")
            continue
        prop = assertion["property"]
        op = assertion["op"]
        if prop not in allowed or op not in allowed[prop]:
            problems.append(f"{sid} property {prop} op {op}")
    return problems


def _seed_problems(sid: str, scenario: dict, claim: dict) -> list[str]:
    seed = scenario.get("seed")
    if not isinstance(seed, dict) or set(seed) != {
        "region",
        "steps",
        "post_claim",
        "fault",
        "page_size",
    }:
        return [f"{sid} seed"]
    problems: list[str] = []
    if not isinstance(seed["region"], str) or not seed["region"]:
        problems.append(f"{sid} seed.region")
    if seed["page_size"] is not None:
        problems.append(f"{sid} page_size")
    if seed["post_claim"] != [] or seed["fault"] != []:
        problems.append(f"{sid} post_claim or fault")
    saves: set[str] = set()
    if not isinstance(seed["steps"], list) or not seed["steps"]:
        problems.append(f"{sid} steps")
    else:
        for step in seed["steps"]:
            problems.extend(_step_problems(sid, step, saves))
    problems.extend(_placeholder_problems(sid, claim, saves))
    return problems


def _step_problems(sid: str, step, saves: set[str]) -> list[str]:
    if not isinstance(step, dict) or "call" not in step or "params" not in step:
        return [f"{sid} step"]
    problems: list[str] = []
    extra = set(step) - {"call", "params", "save", "region", "account"}
    if extra:
        problems.append(f"{sid} step keys {sorted(extra)}")
    if step["call"] not in SEED_ALLOWLIST:
        problems.append(f"{sid} call {step['call']}")
    if not isinstance(step["params"], dict):
        problems.append(f"{sid} params")
    else:
        problems.extend(_placeholder_problems(sid, step["params"], saves))
    save = step.get("save")
    if save is not None:
        if not isinstance(save, dict) or not save:
            problems.append(f"{sid} save")
        else:
            saves.update(str(key) for key in save)
    return problems


def _label_problems(sid: str, scenario: dict) -> list[str]:
    problems: list[str] = []
    if scenario.get("condition") not in CONDITIONS:
        problems.append(f"{sid} condition")
    if scenario.get("failure_type") not in FAILURE_TYPES:
        problems.append(f"{sid} failure_type")
    if scenario.get("failure_type") == "unverifiable":
        problems.append(f"{sid} unverifiable")
    elif scenario.get("na_cause") is not None:
        problems.append(f"{sid} na_cause")
    if scenario.get("expected_verdict") not in VERDICTS:
        problems.append(f"{sid} verdict")
    if scenario.get("expected_raw_verdict") != scenario.get("expected_verdict"):
        problems.append(f"{sid} raw verdict")
    if not isinstance(scenario.get("claim_true"), bool):
        problems.append(f"{sid} claim_true")
    if scenario.get("stretch") is not False:
        problems.append(f"{sid} stretch")
    if not isinstance(scenario.get("rationale"), str) or not scenario["rationale"].strip():
        problems.append(f"{sid} rationale")
    return problems


def _schema_problems(path: Path) -> list[str]:
    raw = path.read_bytes()
    problems = _encoding_problems(path.name, raw)
    try:
        scenario = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"{path.name} is not utf-8 JSON: {exc}"]
    sid, identity = _identity_problems(path, scenario)
    problems.extend(identity)
    claim = scenario.get("agent_claim")
    if not isinstance(claim, dict):
        return [*problems, f"{sid} agent_claim"]
    problems.extend(_claim_problems(sid, scenario))
    problems.extend(_seed_problems(sid, scenario, claim))
    problems.extend(_label_problems(sid, scenario))
    return problems


def _placeholder_problems(sid: str, value, saves: set[str]) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        for name in _PLACEHOLDER.findall(value):
            if name not in saves:
                found.append(f"{sid} unknown placeholder {name}")
    elif isinstance(value, dict):
        for item in value.values():
            found.extend(_placeholder_problems(sid, item, saves))
    elif isinstance(value, list):
        for item in value:
            found.extend(_placeholder_problems(sid, item, saves))
    return found


def test_core_set_hash_and_check_ignore_legacy():
    assert set_sha256(ROOT) == CORE_SET
    assert check(ROOT) == []
    assert main(["--check"]) == 0
    document = json.loads((ROOT / "eval" / "manifest.json").read_text(encoding="utf-8"))
    assert document["set_sha256"] == CORE_SET
    assert all("LG-" not in rel for rel in document["files"])
    assert all("LG-" not in rel for rel in CORE_FILES)
    assert heldout_problems(ROOT) == []
    pin = json.loads((ROOT / "eval" / "heldout.manifest.json").read_text(encoding="utf-8"))
    assert pin["set_sha256"] == (
        "69fda69f4d2716d9f5ece79724f13d415bee268fd40990db0b3d4ca147a3bb37"
    )


def test_legacy_ids_labels_and_counts():
    files = _legacy_files()
    assert files == tuple(f"eval/legacy/scenarios/LG-{number:02d}.json" for number in range(1, 7))
    verdicts = {"PASS": 0, "FAIL": 0}
    truth = {True: 0, False: 0}
    for rel in files:
        scenario = json.loads((ROOT / rel).read_text(encoding="utf-8"))
        assert LEGACY_ID.fullmatch(scenario["id"])
        assert scenario["id"] == Path(rel).stem
        for key in ("expected_verdict", "expected_raw_verdict", "claim_true"):
            assert key in scenario
        verdicts[scenario["expected_verdict"]] += 1
        truth[scenario["claim_true"]] += 1
    assert verdicts == {"PASS": 3, "FAIL": 3}
    assert truth == {True: 3, False: 3}


def test_legacy_manifest_is_written_after_labels():
    assert not (LEGACY / "manifest.json").exists()
    assert not (LEGACY / "MANIFEST.sha256").exists()


def test_legacy_scenarios_match_the_core_schema_and_v0_properties():
    problems: list[str] = []
    for path in sorted(SCENARIOS.glob("*.json")):
        problems.extend(_schema_problems(path))
    assert problems == []
