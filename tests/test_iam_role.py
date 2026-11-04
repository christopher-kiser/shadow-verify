import json
from datetime import datetime, timezone

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from shadow_verify.checkers.iam_role import (
    IamRoleChecker,
    admin_finding,
    allow_principals,
    decode_policy_document,
    role_name_from_identifier,
)
from shadow_verify.errors import ClaimsError
from shadow_verify.models import Verdict
from tests.helpers import REGION, aws_stack, claim

CHECKER = IamRoleChecker()
OIDC = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"


def _trust(principal: dict | str = None, *, condition: bool = True) -> dict:
    statement = {
        "Effect": "Allow",
        "Principal": principal or {"Federated": OIDC},
        "Action": "sts:AssumeRole",
    }
    if condition:
        statement["Condition"] = {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}
    return {"Version": "2012-10-17", "Statement": [statement]}


def _policy(action, resource="*") -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}],
        }
    )


def _expected(arn: str, principal: str = OIDC) -> dict:
    return {
        "trust_principals": [principal],
        "attached_policy_arns": [arn] if arn else [],
        "no_admin_star": True,
    }


def _role(name: str = "app-deploy", trust: dict | None = None) -> None:
    iam = boto3.client("iam", region_name=REGION)
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust or _trust()),
    )


def test_pass_when_trust_arns_and_admin_match():
    with mock_aws():
        _role()
        iam = boto3.client("iam", region_name=REGION)
        arn = iam.create_policy(PolicyName="app-deploy", PolicyDocument=_policy("s3:GetObject", "arn:aws:s3:::logs/*"))[
            "Policy"
        ]["Arn"]
        iam.attach_role_policy(RoleName="app-deploy", PolicyArn=arn)
        aws, evidence = aws_stack()
        result = CHECKER.check(claim("iam_role", "app-deploy", _expected(arn)), aws)
    assert result.verdict == Verdict.PASS, result.reasons
    assert any("conditions are not compared in v0" in reason for reason in result.reasons)
    assert any(item.operation == "GetPolicyVersion" for item in evidence.items)


def test_pass_for_role_arn_identifier():
    with mock_aws():
        _role()
        iam = boto3.client("iam", region_name=REGION)
        arn = iam.create_policy(PolicyName="app-deploy", PolicyDocument=_policy("s3:ListBucket", "arn:aws:s3:::logs"))[
            "Policy"
        ]["Arn"]
        iam.attach_role_policy(RoleName="app-deploy", PolicyArn=arn)
        aws, _evidence = aws_stack()
        result = CHECKER.check(
            claim("iam_role", "arn:aws:iam::123456789012:role/team/app-deploy", _expected(arn)),
            aws,
        )
    assert result.verdict == Verdict.PASS, result.reasons


def test_fail_when_trust_principal_does_not_match():
    with mock_aws():
        _role(trust=_trust({"Service": "ec2.amazonaws.com"}, condition=False))
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("iam_role", "app-deploy", _expected("")), aws)
    assert result.verdict == Verdict.FAIL
    assert any("trust_principals do not match" in reason for reason in result.reasons)
    assert any("ec2.amazonaws.com" in reason for reason in result.reasons)


def test_fail_when_an_extra_policy_is_attached():
    with mock_aws():
        _role()
        iam = boto3.client("iam", region_name=REGION)
        wanted = iam.create_policy(PolicyName="wanted", PolicyDocument=_policy("s3:GetObject", "arn:aws:s3:::logs/*"))[
            "Policy"
        ]["Arn"]
        extra = iam.create_policy(PolicyName="extra", PolicyDocument=_policy("s3:ListBucket", "arn:aws:s3:::logs"))[
            "Policy"
        ]["Arn"]
        iam.attach_role_policy(RoleName="app-deploy", PolicyArn=wanted)
        iam.attach_role_policy(RoleName="app-deploy", PolicyArn=extra)
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("iam_role", "app-deploy", _expected(wanted)), aws)
    assert result.verdict == Verdict.FAIL
    assert any(extra in reason for reason in result.reasons)


def test_fail_when_inline_policy_is_admin():
    with mock_aws():
        _role()
        iam = boto3.client("iam", region_name=REGION)
        iam.put_role_policy(RoleName="app-deploy", PolicyName="admin", PolicyDocument=_policy("*", "*"))
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("iam_role", "app-deploy", _expected("")), aws)
    assert result.verdict == Verdict.FAIL
    assert any("inline policy admin" in reason for reason in result.reasons)


def test_fail_when_attached_policy_is_admin():
    with mock_aws():
        _role()
        iam = boto3.client("iam", region_name=REGION)
        arn = iam.create_policy(PolicyName="admin", PolicyDocument=_policy("*:*", "*"))["Policy"]["Arn"]
        iam.attach_role_policy(RoleName="app-deploy", PolicyArn=arn)
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("iam_role", "app-deploy", _expected(arn)), aws)
    assert result.verdict == Verdict.FAIL
    assert any("Action * or *:* on all resources" in reason for reason in result.reasons)


def test_deny_star_is_not_admin():
    with mock_aws():
        _role()
        iam = boto3.client("iam", region_name=REGION)
        iam.put_role_policy(
            RoleName="app-deploy",
            PolicyName="deny-admin",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
                }
            ),
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("iam_role", "app-deploy", _expected("")), aws)
    assert result.verdict == Verdict.PASS, result.reasons


def test_not_action_is_not_assessed():
    with mock_aws():
        _role()
        iam = boto3.client("iam", region_name=REGION)
        iam.put_role_policy(
            RoleName="app-deploy",
            PolicyName="not-action",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "NotAction": "iam:CreateUser",
                            "Resource": "arn:aws:s3:::logs/*",
                        }
                    ],
                }
            ),
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("iam_role", "app-deploy", _expected("")), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert any("NotAction" in reason for reason in result.reasons)


def test_not_assessed_when_get_role_is_denied():
    iam = boto3.client("iam", region_name=REGION)
    stubber = Stubber(iam)
    stubber.add_client_error(
        "get_role",
        service_error_code="AccessDenied",
        service_message="denied",
        expected_params={"RoleName": "app-deploy"},
    )
    stubber.activate()
    aws, _evidence = aws_stack()
    aws._iam = iam
    result = CHECKER.check(claim("iam_role", "app-deploy", _expected("")), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert any("AccessDenied" in reason for reason in result.reasons)
    stubber.assert_no_pending_responses()


def test_not_assessed_when_role_does_not_exist():
    with mock_aws():
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("iam_role", "missing-role", _expected("")), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert any("NoSuchEntity" in reason for reason in result.reasons)


def test_truncated_policy_list_is_not_assessed():
    iam = boto3.client("iam", region_name=REGION)
    stubber = Stubber(iam)
    stubber.add_response(
        "get_role",
        {
            "Role": {
                "Path": "/",
                "RoleName": "app-deploy",
                "RoleId": "AROAEXAMPLE123456",
                "Arn": "arn:aws:iam::123456789012:role/app-deploy",
                "CreateDate": datetime(2026, 11, 3, tzinfo=timezone.utc),
                "AssumeRolePolicyDocument": json.dumps(_trust(condition=False)),
            }
        },
        {"RoleName": "app-deploy"},
    )
    stubber.add_response(
        "list_attached_role_policies",
        {"AttachedPolicies": [], "IsTruncated": True},
        {"RoleName": "app-deploy"},
    )
    stubber.add_response(
        "list_role_policies",
        {"PolicyNames": [], "IsTruncated": False},
        {"RoleName": "app-deploy"},
    )
    stubber.activate()
    aws, _evidence = aws_stack()
    aws._iam = iam
    result = CHECKER.check(claim("iam_role", "app-deploy", _expected("")), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert any("truncated" in reason or "IsTruncated" in reason or "incomplete" in reason for reason in result.reasons)
    stubber.assert_no_pending_responses()


def test_role_name_parser_and_policy_helpers():
    assert role_name_from_identifier("app-deploy") == "app-deploy"
    assert role_name_from_identifier("arn:aws:iam::123456789012:role/team/app-deploy") == "app-deploy"
    with pytest.raises(ClaimsError):
        role_name_from_identifier("team/app-deploy")
    principals, error = allow_principals(_trust())
    assert error is None
    assert principals == {OIDC}
    encoded = (
        "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C"
        "%22Action%22%3A%22*%22%2C%22Resource%22%3A%22*%22%7D%5D%7D"
    )
    document = decode_policy_document(encoded)
    assert admin_finding(document)[0] == "admin"
    assert admin_finding({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})[0] == "clear"
