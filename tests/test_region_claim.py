"""region is an s3_bucket field. MOCKED. Other types must not PASS with it set."""

import json

import boto3
import pytest
from moto import mock_aws

from shadow_verify.cli import run
from shadow_verify.errors import ClaimsError
from shadow_verify.claims import load_claims

_SSH = {
    "ingress_forbidden": [
        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}
    ]
}
_OIDC = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"


def _document(resource_type: str, identifier: str, expected: dict, region: str = "eu-west-1") -> str:
    return json.dumps(
        {
            "version": 1,
            "claims": [
                {
                    "id": "placed",
                    "statement": "in eu-west-1",
                    "resource_type": resource_type,
                    "identifier": identifier,
                    "region": region,
                    "expected": expected,
                }
            ],
        }
    )


def _run(tmp_path, document: str) -> int:
    claims = tmp_path / "claims.json"
    claims.write_text(document, encoding="utf-8")
    code = run(
        [
            "run",
            "--claims",
            str(claims),
            "--evidence",
            str(tmp_path / "evidence.json"),
            "--region",
            "us-east-1",
            "--json",
            "--mode",
            "MOCKED",
        ]
    )
    return code


@pytest.mark.parametrize("resource_type", ["ec2_security_group", "iam_role"])
def test_region_on_non_s3_is_rejected_at_load(resource_type: str):
    expected = _SSH if resource_type == "ec2_security_group" else {
        "trust_principals": [_OIDC],
        "attached_policy_arns": ["arn:aws:iam::123456789012:policy/app"],
        "no_admin_star": True,
    }
    with pytest.raises(ClaimsError, match="s3_bucket"):
        load_claims(_document(resource_type, "resource", expected), ".json")


def test_security_group_region_does_not_pass(tmp_path, capsys):
    """The group is in us-east-1 and the forbid holds. region eu-west-1 must not PASS."""

    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        group_id = ec2.create_security_group(
            GroupName="app",
            Description="app",
            VpcId=vpc_id,
        )["GroupId"]
        code = _run(tmp_path, _document("ec2_security_group", group_id, _SSH))
    captured = capsys.readouterr()
    assert code == 3
    assert code != 0
    assert "PASS" not in captured.out
    assert "placed" in captured.err
    assert "s3_bucket" in captured.err


def test_iam_role_region_does_not_pass(tmp_path, capsys):
    """The role matches the claim. region eu-west-1 must not PASS."""

    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="app-deploy",
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Federated": _OIDC},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        )
        arn = iam.create_policy(
            PolicyName="app-deploy",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::logs/*",
                        }
                    ],
                }
            ),
        )["Policy"]["Arn"]
        iam.attach_role_policy(RoleName="app-deploy", PolicyArn=arn)
        code = _run(
            tmp_path,
            _document(
                "iam_role",
                "app-deploy",
                {
                    "trust_principals": [_OIDC],
                    "attached_policy_arns": [arn],
                    "no_admin_star": True,
                },
            ),
        )
    captured = capsys.readouterr()
    assert code == 3
    assert code != 0
    assert "PASS" not in captured.out
    assert "placed" in captured.err


@pytest.mark.parametrize("region", ["us-east-1", "eu-west-1", "us-gov-west-1", "ap-southeast-2"])
def test_s3_region_format_is_accepted(region: str):
    claims = load_claims(_document("s3_bucket", "logs-prod", {"block_public_acls": True}, region), ".json")
    assert claims[0].region == region


@pytest.mark.parametrize("region", ["EU", "US-EAST-1", "us-east", "not-a-region"])
def test_s3_region_format_is_rejected(region: str):
    with pytest.raises(ClaimsError, match="region"):
        load_claims(_document("s3_bucket", "logs-prod", {"block_public_acls": True}, region), ".json")
