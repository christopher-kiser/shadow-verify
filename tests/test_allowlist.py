"""MOCKED. Allowlist refusals happen before a client method is touched."""

import json
from pathlib import Path

import pytest

from shadow_verify.aws import (
    ALLOWED_OPERATIONS,
    CLIENT_CONFIG,
    DENIED_OPERATIONS,
    OPERATION_IAM_ACTIONS,
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


# Hard-coded. Removing kms:Decrypt from DENIED_OPERATIONS fails this set equality.
REQUIRED_DENIALS = {
    "secretsmanager:GetSecretValue",
    "s3:GetObject",
    "s3:GetObjectVersion",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "ssm:GetParameterHistory",
    "kms:Decrypt",
    "dynamodb:GetItem",
    "dynamodb:BatchGetItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "dynamodb:ExecuteStatement",
    "lambda:GetFunction",
    "ec2:GetPasswordData",
}


def test_deny_list_matches_the_hard_coded_set():
    assert DENIED_OPERATIONS == REQUIRED_DENIALS


@pytest.mark.parametrize("pair", sorted(REQUIRED_DENIALS))
def test_denied_call_is_refused_before_any_client_call(pair: str):
    service, operation = pair.split(":", 1)
    aws = BotoAws(
        s3=BoomClient(),
        ec2=BoomClient(),
        iam=BoomClient(),
        evidence=EvidenceLog(),
        region="us-east-1",
    )
    with pytest.raises(ShadowVerifyError, match="refusing denied"):
        aws._invoke(service, operation, BoomClient())


def test_write_call_is_refused_before_any_client_call():
    aws = BotoAws(
        s3=BoomClient(),
        ec2=BoomClient(),
        iam=BoomClient(),
        evidence=EvidenceLog(),
        region="us-east-1",
    )
    with pytest.raises(ShadowVerifyError, match="refusing"):
        aws._invoke("s3", "PutBucketPolicy", BoomClient(), Bucket="logs-prod", Policy="{}")


def test_client_region_argument_is_required():
    with pytest.raises(TypeError):
        BotoAws(s3=BoomClient(), ec2=BoomClient(), iam=BoomClient(), evidence=EvidenceLog())


def test_bucket_location_is_allowed_and_secret_reads_stay_refused():
    assert refusal("s3", "GetBucketLocation") is None
    assert "s3:GetBucketLocation" in ALLOWED_OPERATIONS
    assert refusal("s3", "GetObject") == "refusing denied AWS call s3:GetObject"
    assert refusal("secretsmanager", "GetSecretValue") == (
        "refusing denied AWS call secretsmanager:GetSecretValue"
    )
    assert "s3:GetObject" in DENIED_OPERATIONS
    assert "secretsmanager:GetSecretValue" in DENIED_OPERATIONS


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
    assert set(allow) == set(OPERATION_IAM_ACTIONS.values())
    assert "s3:GetPublicAccessBlock" not in allow
    assert "s3:GetBucketPublicAccessBlock" in allow
    assert set(OPERATION_IAM_ACTIONS) == set(ALLOWED_OPERATIONS)
    assert set(deny) == set(DENIED_OPERATIONS)
    assert len(allow) == len(set(allow))
    assert len(deny) == len(set(deny))
    by_sid = {statement["Sid"]: statement for statement in policy["Statement"]}
    ec2 = by_sid["Ec2DescribeSecurityGroups"]
    assert ec2["Action"] == ["ec2:DescribeSecurityGroups"]
    assert ec2["Resource"] == "*"
    assert by_sid["S3BucketReads"]["Action"] == [
        "s3:GetBucketLocation",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
    ]
    assert by_sid["S3BucketReads"]["Resource"] == "arn:aws:s3:::*"
    assert by_sid["IamRoleReads"]["Resource"] == "arn:aws:iam::*:role/*"
    assert "arn:aws:iam::*:policy/*" in by_sid["IamPolicyReads"]["Resource"]
    for statement in policy["Statement"]:
        if statement["Sid"] == "Ec2DescribeSecurityGroups":
            continue
        if statement["Effect"] != "Allow":
            continue
        assert statement["Resource"] != "*"


def test_client_config_is_applied_by_from_session():
    seen = []

    class Session:
        def client(self, name, **kwargs):
            seen.append(kwargs.get("config"))
            return object()

    BotoAws.from_session(Session(), "us-east-1", EvidenceLog())
    assert len(seen) == 3
    for config in seen:
        assert config is CLIENT_CONFIG
        assert config.retries["mode"] == "standard"
        assert config.retries["max_attempts"] == 3
        assert config.connect_timeout == 3
        assert config.read_timeout == 10


def test_oidc_trust_policy_pins_audience_and_subject():
    document = json.loads((ROOT / "docs" / "oidc-trust-policy.json").read_text(encoding="utf-8"))
    condition = document["Statement"][0]["Condition"]["StringEquals"]
    assert condition["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    subject = condition["token.actions.githubusercontent.com:sub"]
    assert subject == "repo:ORG/REPO:ref:refs/heads/main"
    assert "pull_request" not in json.dumps(document)
