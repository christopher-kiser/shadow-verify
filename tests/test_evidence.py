import hashlib
import json
from datetime import datetime, timezone

import pytest

from shadow_verify.evidence import (
    EvidenceLog,
    bundle_problems,
    canonical_dumps,
    sha256_text,
    to_jsonable,
)


def test_canonical_json_sorts_keys_and_matches_sha256():
    text = canonical_dumps({"b": 1, "a": {"d": True, "c": "x"}})
    assert text == '{"a":{"c":"x","d":true},"b":1}'
    assert sha256_text('{"a":1}') == "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"


def test_datetime_is_frozen_as_iso():
    frozen = to_jsonable({"when": datetime(2026, 11, 3, 6, 0, tzinfo=timezone.utc)})
    assert frozen == {"when": "2026-11-03T06:00:00+00:00"}


def test_item_hash_changes_when_the_response_changes():
    first = EvidenceLog()
    second = EvidenceLog()
    left = first.record("s3", "GetPublicAccessBlock", {"Bucket": "logs"}, response={"ok": True})
    right = second.record("s3", "GetPublicAccessBlock", {"Bucket": "logs"}, response={"ok": False})
    assert left.sha256 != right.sha256
    assert left.id == "s3.GetPublicAccessBlock#1"


def test_bundle_hash_detects_tampering():
    log = EvidenceLog()
    log.record("s3", "GetPublicAccessBlock", {"Bucket": "logs"}, response={"BlockPublicPolicy": False})
    bundle = log.bundle(
        generated_at="2026-11-03T06:00:00+00:00",
        claims_file="claims.yaml",
        claims_sha256="abc",
        region="us-east-1",
        results=[],
        plan_notes=[],
        mode="MOCKED",
        tool_commit="test-commit",
    )
    assert bundle_problems(bundle) == []
    bundle["items"][0]["body"]["response"]["BlockPublicPolicy"] = True
    problems = bundle_problems(bundle)
    assert any("hash mismatch" in problem for problem in problems)


def test_reloaded_bundle_still_verifies(tmp_path):
    log = EvidenceLog()
    log.record(
        "iam",
        "GetRole",
        {"RoleName": "app"},
        error_code="AccessDenied",
        error_message="no",
    )
    bundle = log.bundle(
        generated_at="2026-11-03T06:00:00+00:00",
        claims_file="claims.json",
        claims_sha256="def",
        region="us-east-1",
        results=[{"id": "role", "verdict": "NOT_ASSESSED"}],
        plan_notes=[],
        mode="MOCKED",
        tool_commit="test-commit",
    )
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert bundle_problems(loaded) == []
    assert loaded["bundle_sha256"] == bundle["bundle_sha256"]


def test_non_finite_float_is_rejected():
    with pytest.raises(TypeError):
        to_jsonable(float("nan"))


def test_sha256_text_is_hashlib():
    assert sha256_text("shadow") == hashlib.sha256(b"shadow").hexdigest()


def test_account_ids_are_indexed_and_the_verdict_is_unchanged():
    log = EvidenceLog()
    item = log.record(
        "iam",
        "GetRole",
        {"RoleName": "app"},
        response={
            "Role": {
                "Arn": "arn:aws:iam::123456789012:role/app",
                "ResponseMetadata": {"RequestId": "req", "HTTPHeaders": {"date": "Tue"}},
            }
        },
    )
    assert item.response["Role"]["Arn"] == "arn:aws:iam::123456789012:role/app"
    assert "ResponseMetadata" not in item.response["Role"]
    bundle = log.bundle(
        generated_at="2026-11-03T06:00:00+00:00",
        claims_file="claims.json",
        claims_sha256="abc",
        region="us-east-1",
        results=[{"verdict": "PASS", "reason": "arn:aws:iam::123456789012:role/app"}],
        plan_notes=[],
        mode="MOCKED",
        tool_commit="test-commit",
    )
    encoded = json.dumps(bundle)
    assert "123456789012" not in encoded
    assert "account-1" in encoded
    assert bundle["results"][0]["verdict"] == "PASS"
    assert "sha256" not in bundle["results"][0]["reason"]


def test_golden_bundle_hash_redacts_before_hashing():
    """MOCKED fixture. Clock and response are fixed; the digest is golden."""

    log = EvidenceLog()
    log.record(
        "s3",
        "GetPublicAccessBlock",
        {"Bucket": "logs-prod"},
        response={
            "PublicAccessBlockConfiguration": {"BlockPublicPolicy": False},
            "SecretString": "super-secret",
        },
    )
    bundle = log.bundle(
        generated_at="2026-11-03T06:00:00+00:00",
        claims_file="claims.json",
        claims_sha256="abc",
        region="us-east-1",
        results=[],
        plan_notes=[],
        mode="MOCKED",
        tool_commit="test-commit",
    )
    encoded = json.dumps(bundle)
    assert "super-secret" not in encoded
    assert bundle["items"][0]["body"]["response"]["SecretString"] == "***REDACTED***"
    assert bundle["items"][0]["sha256"] == "142a208972e8972dcd61c7384b02d26c4cd54afc3bf6a700c13f9444955e15ec"
    assert bundle["bundle_sha256"] == "deac44aedd6225e01bb6b15dbc54f111b6edabac87be7d504657a03dc362f638"
    assert bundle_problems(bundle) == []
    assert sha256_text(canonical_dumps({"a": 1}).encode("utf-8").decode("utf-8")) == (
        "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
    )
