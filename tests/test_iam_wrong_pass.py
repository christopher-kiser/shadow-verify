"""Wrong-PASS regressions for IAM role ARNs and admin-equivalent policies.

These tests describe the verdict. They do not grant it.
"""

import json

import boto3
import pytest
from moto import mock_aws

from shadow_verify.checkers.iam_documents import admin_finding
from shadow_verify.checkers.iam_role import IamRoleChecker
from shadow_verify.models import Verdict
from tests.helpers import REGION, aws_stack, claim

CHECKER = IamRoleChecker()
OIDC = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
ACCOUNT = "123456789012"
OTHER = "111122223333"


def _trust() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": OIDC},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _policy(action, resource="*") -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}],
        }
    )


def _expected() -> dict:
    return {
        "trust_principals": [OIDC],
        "attached_policy_arns": [],
        "no_admin_star": True,
    }


def _role(name: str = "app-deploy") -> None:
    boto3.client("iam", region_name=REGION).create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_trust()),
    )


def _put_inline(action, resource, name: str = "extra") -> None:
    boto3.client("iam", region_name=REGION).put_role_policy(
        RoleName="app-deploy",
        PolicyName=name,
        PolicyDocument=_policy(action, resource),
    )


def _statement(action, resource, effect="Allow") -> dict:
    return {"Statement": [{"Effect": effect, "Action": action, "Resource": resource}]}


def test_other_account_role_arn_is_not_assessed():
    with mock_aws():
        _role()
        aws, evidence = aws_stack()
        result = CHECKER.check(
            claim("iam_role", f"arn:aws:iam::{OTHER}:role/app-deploy", _expected()),
            aws,
        )
    assert result.verdict == Verdict.NOT_ASSESSED
    assert any("arn_mismatch" in reason for reason in result.reasons)
    assert [item.operation for item in evidence.items] == ["GetRole"]


def test_same_account_role_arn_passes_when_compliant():
    with mock_aws():
        _role()
        aws, _evidence = aws_stack()
        result = CHECKER.check(
            claim("iam_role", f"arn:aws:iam::{ACCOUNT}:role/app-deploy", _expected()),
            aws,
        )
    assert result.verdict == Verdict.PASS, result.reasons


def test_other_partition_role_arn_is_not_assessed():
    with mock_aws():
        _role()
        aws, _evidence = aws_stack()
        result = CHECKER.check(
            claim(
                "iam_role",
                f"arn:aws-us-gov:iam::{ACCOUNT}:role/app-deploy",
                _expected(),
            ),
            aws,
        )
    assert result.verdict == Verdict.NOT_ASSESSED
    assert any("arn_mismatch" in reason for reason in result.reasons)


def test_star_action_on_partition_wildcard_resource_fails():
    with mock_aws():
        _role()
        _put_inline("*", "arn:aws:*:*:*:*")
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("iam_role", "app-deploy", _expected()), aws)
    assert result.verdict == Verdict.FAIL
    assert any("Action * or *:* on Resource *" in reason for reason in result.reasons)


def test_iam_star_on_all_resources_is_not_pass():
    with mock_aws():
        _role()
        _put_inline("iam:*", "*")
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("iam_role", "app-deploy", _expected()), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert result.verdict != Verdict.PASS
    assert any("may_grant_admin" in reason for reason in result.reasons)


@pytest.mark.parametrize(
    ("action", "resource", "kind", "token"),
    [
        ("*", "arn:*:*:*:*:*", "admin", "Resource *"),
        ("*:*", "arn:aws:*", "admin", "Resource *"),
        ("*", "arn:aws:s3:::*", "clear", ""),
        ("*", "arn:aws:s3:::logs/*", "clear", ""),
        ("*", "arn:aws:iam::*:role/*", "clear", ""),
        ("iam:*", "*", "not_assessed", "may_grant_admin"),
        ("iam:Put*Policy", "*", "not_assessed", "may_grant_admin"),
        ("iam:Attach*Policy", "*", "not_assessed", "may_grant_admin"),
        ("iam:CreatePolicyVersion", "*", "not_assessed", "may_grant_admin"),
        ("iam:PassRole", "*", "not_assessed", "may_grant_admin"),
        ("iam:Pass*", "*", "not_assessed", "may_grant_admin"),
        ("iam:PutRolePolicy", "*", "not_assessed", "may_grant_admin"),
        ("iam:*", "arn:aws:*:*:*:*", "not_assessed", "may_grant_admin"),
        ("s3:*", "*", "clear", ""),
        ("iam:GetUser", "*", "clear", ""),
        ("*", ["arn:aws:s3:::logs/*", "*"], "admin", "Resource *"),
    ],
)
def test_admin_finding_resource_and_privesc(action, resource, kind, token):
    found, detail = admin_finding(_statement(action, resource))
    assert found == kind
    if token:
        assert token in detail


def test_deny_of_iam_star_on_all_resources_is_clear():
    found, _detail = admin_finding(_statement("iam:*", "*", effect="Deny"))
    assert found == "clear"


def test_admin_statement_outranks_privesc_statement():
    document = {
        "Statement": [
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
            {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:*:*:*:*"},
        ]
    }
    assert admin_finding(document)[0] == "admin"


def test_not_action_on_all_resources_fails():
    document = {
        "Statement": [
            {"Effect": "Allow", "NotAction": ["iam:DeleteUser"], "Resource": "*"}
        ]
    }
    assert admin_finding(document)[0] == "admin"


def test_not_resource_is_not_assessed_never_pass():
    document = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "NotResource": "arn:aws:s3:::logs/one",
            }
        ]
    }
    kind, detail = admin_finding(document)
    assert kind == "not_assessed"
    assert kind != "clear"
    assert "not_action_unsupported" in detail


@pytest.mark.parametrize(
    "action",
    ["*:PUT*", "iam:*POLICY*", "IAM:Create*", "iam:Update*", "IAM:PassRole", "IAM:*"],
)
def test_iam_write_wildcards_and_mixed_case_are_not_pass(action):
    kind, detail = admin_finding(_statement(action, "*"))
    assert kind == "not_assessed"
    assert kind != "clear"
    assert "may_grant_admin" in detail


@pytest.mark.parametrize(
    "resource",
    ["arn:aws-us-gov:*", "arn:aws-cn:*:*:*:*"],
)
def test_other_partition_all_resources_fail(resource):
    assert admin_finding(_statement("*", resource))[0] == "admin"


def test_condition_on_admin_statement_is_not_pass():
    document = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            }
        ]
    }
    kind, detail = admin_finding(document)
    assert kind == "not_assessed"
    assert kind != "clear"
    assert "condition_unsupported" in detail


def test_deny_does_not_cancel_an_admin_allow():
    document = {
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "arn:aws-us-gov:*"},
            {"Effect": "Deny", "Action": "*", "Resource": "*"},
        ]
    }
    assert admin_finding(document)[0] == "admin"
