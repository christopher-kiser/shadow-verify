"""MOCKED. Allowlist refusals happen before a client method is touched."""

import json
from pathlib import Path

import pytest

from shadow_verify.aws import (
    ALLOWED_OPERATIONS,
    DENIED_OPERATIONS,
    BotoAws,
    refusal,
)
from shadow_verify.errors import ShadowVerifyError
from shadow_verify.evidence import EvidenceLog

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "docs" / "iam-policy.json"


class BoomClient:
    def __getattr__(self, name):
        raise AssertionError(f"client method was called: {name}")


def test_secret_and_write_calls_are_refused_before_any_client_call():
    aws = BotoAws(
        s3=BoomClient(),
        ec2=BoomClient(),
        iam=BoomClient(),
        evidence=EvidenceLog(),
    )
    cases = (
        ("secretsmanager", "GetSecretValue", {"SecretId": "prod"}),
        ("s3", "GetObject", {"Bucket": "logs-prod", "Key": "a"}),
        ("s3", "PutBucketPolicy", {"Bucket": "logs-prod", "Policy": "{}"}),
    )
    for service, operation, params in cases:
        with pytest.raises(ShadowVerifyError, match="refusing"):
            aws._invoke(service, operation, BoomClient(), **params)


def test_denied_pair_wins_over_an_allowlist_prefix():
    assert refusal("secretsmanager", "GetSecretValue") == "refusing denied AWS call secretsmanager:GetSecretValue"
    assert refusal("s3", "GetObject") == "refusing denied AWS call s3:GetObject"
    assert refusal("s3", "PutBucketPolicy") == "refusing non-allowlisted AWS call s3:PutBucketPolicy"
    assert refusal("s3", "GetPublicAccessBlock") is None
    assert DENIED_OPERATIONS.isdisjoint(ALLOWED_OPERATIONS)
    assert "s3:Get*" not in ALLOWED_OPERATIONS
    assert "iam:Get*" not in ALLOWED_OPERATIONS


def test_iam_policy_actions_equal_the_allowlist():
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    text = POLICY.read_text(encoding="utf-8")
    assert "ReadOnlyAccess" not in text
    allow: list[str] = []
    deny: list[str] = []
    for statement in policy["Statement"]:
        actions = statement["Action"]
        assert isinstance(actions, list)
        for action in actions:
            assert isinstance(action, str)
            assert "*" not in action
        if statement["Effect"] == "Allow":
            allow.extend(actions)
        elif statement["Effect"] == "Deny":
            deny.extend(actions)
        else:
            raise AssertionError(statement["Effect"])
    assert set(allow) == set(ALLOWED_OPERATIONS)
    assert set(deny) == set(DENIED_OPERATIONS)
    assert len(allow) == len(set(allow))
    assert len(deny) == len(set(deny))
