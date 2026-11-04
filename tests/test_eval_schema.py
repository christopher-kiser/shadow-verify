"""Schema checks. The frozen files are not modified."""

from __future__ import annotations

import json
from pathlib import Path

from eval.adapter import retry_bound
from eval.schema import ATTEMPT_LIMIT, lint_public_policy, validate_file, validate_scenario

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "eval" / "scenarios"


def _base(**overrides):
    data = {
        "id": "S3-01",
        "resource_type": "widget",
        "agent_claim": {
            "text": "Done.",
            "structured": {
                "resources": [
                    {
                        "resource_type": "widget",
                        "resource_id": "w",
                        "region": "us-east-1",
                        "account_id": None,
                        "assertions": [{"property": "color", "op": "eq", "value": "blue"}],
                    }
                ]
            },
            "prose_assertions": "same",
        },
        "seed": {
            "region": "us-east-1",
            "steps": [],
            "post_claim": [],
            "fault": [],
            "page_size": None,
        },
        "condition": "none",
        "failure_type": "unverifiable",
        "na_cause": "unsupported_resource",
        "expected_verdict": "NOT_ASSESSED",
        "expected_raw_verdict": "NOT_ASSESSED",
        "claim_true": False,
        "stretch": False,
        "rationale": "No checker.",
    }
    data.update(overrides)
    return data


def test_frozen_files_validate_and_attempt_bound_matches_v0():
    assert ATTEMPT_LIMIT == retry_bound()
    for path in SCENARIOS.glob("*.json"):
        assert validate_file(path) == []


def test_unknown_resource_type_validates():
    assert validate_scenario(_base(), filename="S3-01.json") == []


def test_attempts_at_the_bound_are_rejected():
    data = _base()
    data["seed"]["fault"] = [
        {"operation": "s3.GetPublicAccessBlock", "kind": "throttling", "attempts": ATTEMPT_LIMIT}
    ]
    problems = validate_scenario(data, filename="S3-01.json")
    assert any("attempts" in item for item in problems)


def test_unknown_placeholder_is_a_schema_error():
    data = _base()
    data["agent_claim"]["structured"]["resources"][0]["resource_id"] = "${missing}"
    problems = validate_scenario(data, filename="S3-01.json")
    assert any("missing" in item for item in problems)


def test_public_policy_lint_rejects_a_star_principal_without_the_override():
    data = _base()
    data["seed"]["steps"] = [
        {
            "call": "s3.put_bucket_policy",
            "params": {"Bucket": "b", "Policy": {"Statement": [{"Principal": "*"}]}},
        }
    ]
    assert lint_public_policy(data)
    data["seed"]["steps"].insert(
        0,
        {
            "call": "s3.put_public_access_block",
            "params": {
                "Bucket": "b",
                "PublicAccessBlockConfiguration": {"BlockPublicPolicy": False},
            },
        },
    )
    assert lint_public_policy(data) == []


def test_frozen_public_policies_pass_the_lint():
    for path in SCENARIOS.glob("*.json"):
        scenario = json.loads(path.read_text(encoding="utf-8"))
        assert lint_public_policy(scenario, path.name) == []


def test_null_truth_only_with_vague_claim():
    data = _base(claim_true=None, na_cause="vague_claim")
    assert validate_scenario(data, filename="S3-01.json") == []
    data["na_cause"] = "unsupported_resource"
    assert validate_scenario(data, filename="S3-01.json")
