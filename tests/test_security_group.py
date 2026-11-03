import boto3
from botocore.stub import Stubber
from moto import mock_aws

from shadow_verify.checkers.security_group import SecurityGroupChecker
from shadow_verify.models import Verdict
from tests.helpers import REGION, aws_stack, claim

CHECKER = SecurityGroupChecker()

FORBID_SSH = {
    "ingress_forbidden": [
        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}
    ]
}


def _group(permissions: list[dict]) -> str:
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    group_id = ec2.create_security_group(
        GroupName="app",
        Description="app",
        VpcId=vpc_id,
    )["GroupId"]
    if permissions:
        ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=permissions)
    return group_id


def test_pass_when_port_22_is_not_open_to_the_world():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.1.2.3/32"}],
                }
            ]
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.PASS, result.reasons
    assert any("no ingress covers tcp 22-22 from 0.0.0.0/0" in reason for reason in result.reasons)


def test_fail_when_port_22_is_open_to_the_world():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(
            claim(
                "ec2_security_group",
                group_id,
                FORBID_SSH,
                statement="port 22 not open to 0.0.0.0/0",
            ),
            aws,
        )
    assert result.verdict == Verdict.FAIL
    assert any("ingress allows tcp 22-22 from 0.0.0.0/0" in reason for reason in result.reasons)


def test_fail_when_a_wide_port_range_covers_22():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 0,
                    "ToPort": 100,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.FAIL


def test_pass_when_only_port_80_is_open_to_the_world():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.PASS, result.reasons


def test_security_group_source_is_not_treated_as_world_cidr():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        other = ec2.create_security_group(GroupName="other", Description="other", VpcId=vpc_id)["GroupId"]
        group_id = ec2.create_security_group(GroupName="app", Description="app", VpcId=vpc_id)["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "UserIdGroupPairs": [{"GroupId": other}],
                }
            ],
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.PASS, result.reasons


def test_all_protocol_rule_covers_port_22():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.FAIL, result.reasons


def test_ipv4_world_does_not_imply_ipv6():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(
            claim(
                "ec2_security_group",
                group_id,
                {
                    "ingress_forbidden": [
                        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "::/0"}
                    ]
                },
            ),
            aws,
        )
    assert result.verdict == Verdict.PASS, result.reasons


def test_not_assessed_when_access_is_denied():
    ec2 = boto3.client("ec2", region_name=REGION)
    stubber = Stubber(ec2)
    stubber.add_client_error(
        "describe_security_groups",
        service_error_code="UnauthorizedOperation",
        service_message="denied",
        expected_params={"GroupIds": ["sg-0123456789abcdef0"]},
    )
    stubber.activate()
    aws, _evidence = aws_stack()
    aws._ec2 = ec2
    result = CHECKER.check(claim("ec2_security_group", "sg-0123456789abcdef0", FORBID_SSH), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert any("UnauthorizedOperation" in reason for reason in result.reasons)
    stubber.assert_no_pending_responses()


def test_not_assessed_when_group_does_not_exist():
    with mock_aws():
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", "sg-0123456789abcdef0", FORBID_SSH), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert any("InvalidGroup.NotFound" in reason or "not found" in reason.lower() for reason in result.reasons)
