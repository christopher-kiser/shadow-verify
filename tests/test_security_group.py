import boto3
import pytest
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
    assert result.verdict == Verdict.NOT_ASSESSED, result.reasons
    assert any("unresolvable_source" in reason for reason in result.reasons)


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


def test_ipv4_world_fails_an_ipv6_world_forbid():
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
    assert result.verdict == Verdict.FAIL, result.reasons


def test_ipv6_world_fails_an_ipv4_world_forbid():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }
            ]
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.FAIL, result.reasons


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


def test_superset_cidr_fails_a_narrower_forbid():
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
                        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "10.0.0.0/8"}
                    ]
                },
            ),
            aws,
        )
    assert result.verdict == Verdict.FAIL, result.reasons


def test_two_halves_fail_a_world_forbid():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/1"}, {"CidrIp": "128.0.0.0/1"}],
                }
            ]
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.FAIL, result.reasons


def test_narrow_cidr_does_not_cover_the_world():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.1.0.0/16"}],
                }
            ]
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.PASS, result.reasons


def test_half_internet_fails_a_world_forbid():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/1"}],
                }
            ]
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.FAIL, result.reasons


def test_public_host_fails_a_world_forbid():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "8.8.8.8/32"}],
                }
            ]
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.FAIL, result.reasons


def test_rfc1918_passes_a_world_forbid():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }
            ]
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.PASS, result.reasons


def test_overlap_fails_a_private_forbid():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.1.0.0/16"}],
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
                        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "10.0.0.0/8"}
                    ]
                },
            ),
            aws,
        )
    assert result.verdict == Verdict.FAIL, result.reasons


def test_disjoint_private_ranges_pass():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "192.168.0.0/16"}],
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
                        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "10.0.0.0/8"}
                    ]
                },
            ),
            aws,
        )
    assert result.verdict == Verdict.PASS, result.reasons


_STUB_GROUP = "sg-0123456789abcdef0"


def _check_raw_permission(permission: dict, forbid: dict):
    """DescribeSecurityGroups via Stubber, so moto cannot rewrite IpProtocol."""

    ec2 = boto3.client("ec2", region_name=REGION)
    stubber = Stubber(ec2)
    stubber.add_response(
        "describe_security_groups",
        {"SecurityGroups": [{"GroupId": _STUB_GROUP, "IpPermissions": [permission]}]},
        expected_params={"GroupIds": [_STUB_GROUP]},
    )
    stubber.activate()
    try:
        aws, _evidence = aws_stack()
        aws._ec2 = ec2
        result = CHECKER.check(
            claim(
                "ec2_security_group",
                _STUB_GROUP,
                {"ingress_forbidden": [forbid]},
            ),
            aws,
        )
        stubber.assert_no_pending_responses()
        return result
    finally:
        stubber.deactivate()


def _world_permission(protocol: str, from_port: int, to_port: int) -> dict:
    return {
        "IpProtocol": protocol,
        "FromPort": from_port,
        "ToPort": to_port,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }


@pytest.mark.parametrize(
    ("from_port", "to_port", "forbid_from", "forbid_to", "expected"),
    [
        (8, -1, 0, 255, Verdict.FAIL),
        (8, 0, 8, 8, Verdict.FAIL),
        (3, 4, 8, 8, Verdict.PASS),
    ],
)
def test_icmp_type_matches_and_code_is_ignored(
    from_port, to_port, forbid_from, forbid_to, expected
):
    result = _check_raw_permission(
        _world_permission("icmp", from_port, to_port),
        {
            "protocol": "icmp",
            "from_port": forbid_from,
            "to_port": forbid_to,
            "cidr": "0.0.0.0/0",
        },
    )
    assert result.verdict == expected, result.reasons


@pytest.mark.parametrize(
    ("number", "protocol", "from_port", "to_port"),
    [
        ("6", "tcp", 22, 22),
        ("17", "udp", 53, 53),
        ("1", "icmp", 0, 255),
    ],
)
def test_raw_ip_protocol_numbers(number, protocol, from_port, to_port):
    permission = _world_permission(number, from_port, to_port)
    if number == "1":
        permission["FromPort"] = -1
        permission["ToPort"] = -1
    result = _check_raw_permission(
        permission,
        {
            "protocol": protocol,
            "from_port": from_port,
            "to_port": to_port,
            "cidr": "0.0.0.0/0",
        },
    )
    assert result.verdict == Verdict.FAIL, result.reasons


def test_icmp_all_types_matches_an_icmp_forbid():
    with mock_aws():
        group_id = _group(
            [
                {
                    "IpProtocol": "icmp",
                    "FromPort": -1,
                    "ToPort": -1,
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
                        {"protocol": "icmp", "from_port": 0, "to_port": 255, "cidr": "0.0.0.0/0"}
                    ]
                },
            ),
            aws,
        )
    assert result.verdict == Verdict.FAIL, result.reasons


def _prefix_list(ec2, cidr: str) -> str:
    created = ec2.create_managed_prefix_list(
        PrefixListName=f"pl-{cidr.replace('/', '-')}",
        AddressFamily="IPv4",
        MaxEntries=1,
        Entries=[{"Cidr": cidr, "Description": "test"}],
    )
    return created["PrefixList"]["PrefixListId"]


def test_prefix_list_alone_is_not_assessed_even_if_it_holds_the_world():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        group_id = ec2.create_security_group(GroupName="app", Description="app", VpcId=vpc_id)["GroupId"]
        prefix_id = _prefix_list(ec2, "0.0.0.0/0")
        ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "PrefixListIds": [{"PrefixListId": prefix_id}],
                }
            ],
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.NOT_ASSESSED, result.reasons
    assert any("unresolvable_source" in reason for reason in result.reasons)


def test_public_half_plus_prefix_list_in_one_entry_fails():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        group_id = ec2.create_security_group(GroupName="app", Description="app", VpcId=vpc_id)["GroupId"]
        prefix_id = _prefix_list(ec2, "0.0.0.0/0")
        ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/1"}],
                    "PrefixListIds": [{"PrefixListId": prefix_id}],
                }
            ],
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.FAIL, result.reasons


def test_private_cidr_plus_prefix_list_is_not_assessed():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        group_id = ec2.create_security_group(GroupName="app", Description="app", VpcId=vpc_id)["GroupId"]
        prefix_id = _prefix_list(ec2, "0.0.0.0/0")
        ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    "PrefixListIds": [{"PrefixListId": prefix_id}],
                }
            ],
        )
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", group_id, FORBID_SSH), aws)
    assert result.verdict == Verdict.NOT_ASSESSED, result.reasons
    assert any("unresolvable_source" in reason for reason in result.reasons)


def test_not_assessed_when_group_does_not_exist():
    with mock_aws():
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("ec2_security_group", "sg-0123456789abcdef0", FORBID_SSH), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert any("InvalidGroup.NotFound" in reason or "not found" in reason.lower() for reason in result.reasons)
