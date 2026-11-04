"""EC2 security group ingress checks.

``expected.ingress_forbidden`` is a list of rules that must not be covered
by any ingress permission. A permission covers a forbidden rule when:

* its protocol is all (``-1``), the forbid is all, or the two are equal
  after ``1``, ``6``, ``17``, and ``58`` are read as icmp, tcp, udp,
  and icmpv6
* its ports overlap the forbid; missing ports mean every port.
  For an ICMP permission, FromPort is the type and ToPort (the code)
  is ignored. Type ``-1``, or a type inside the forbid's range, matches.
  A permission with protocol ``-1`` matches on any port overlap.
* a forbid of ``0.0.0.0/0`` or ``::/0`` means open to the internet,
  for both address families: any CIDR that overlaps a globally routable
  address fails it
* any other forbid fails on any CIDR overlap

A prefix list or security-group source on that port and protocol is
``unresolvable_source`` (NOT ASSESSED) unless a CIDR on the same
permission already fails. Sources in one ``IpPermissions`` entry are
split before that judgment.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from shadow_verify.aws import BotoAws
from shadow_verify.checkers.base import blocked, call_failure, finish
from shadow_verify.checkers.sg_rules import assess_forbid
from shadow_verify.errors import ClaimsError
from shadow_verify.models import CheckResult, Claim, PropertyResult, Verdict

_PROTOCOLS = {"tcp", "udp", "icmp", "icmpv6", "-1"}


class SecurityGroupChecker:
    resource_type = "ec2_security_group"

    def check(self, claim: Claim, aws: BotoAws) -> CheckResult:
        rules = _validate(claim)
        item = aws.describe_security_group(claim.identifier)
        evidence_ids = [item.id]
        if not item.ok:
            return blocked(claim, call_failure("DescribeSecurityGroups", item), evidence_ids)
        groups = item.response.get("SecurityGroups")
        if not isinstance(groups, list) or len(groups) != 1 or not isinstance(groups[0], dict):
            return blocked(
                claim,
                "DescribeSecurityGroups did not return exactly one security group",
                evidence_ids,
            )
        permissions = groups[0].get("IpPermissions", [])
        if permissions is None:
            permissions = []
        if not isinstance(permissions, list):
            return blocked(claim, "IpPermissions is not a list", evidence_ids)
        properties: list[PropertyResult] = []
        for index, rule in enumerate(rules):
            properties.append(assess_forbid(index, rule, permissions))
        return finish(claim, properties, evidence_ids)


def _validate(claim: Claim) -> list[dict[str, Any]]:
    expected = claim.expected
    unknown = sorted(set(expected) - {"ingress_forbidden"})
    if unknown:
        raise ClaimsError(
            f"ec2_security_group claim {claim.id!r} has unknown expected keys: {unknown}"
        )
    rules = expected.get("ingress_forbidden")
    if not isinstance(rules, list) or not rules:
        raise ClaimsError(
            f"ec2_security_group claim {claim.id!r} expected.ingress_forbidden must be a non-empty list"
        )
    if not isinstance(claim.identifier, str) or not claim.identifier.startswith("sg-"):
        raise ClaimsError(
            f"ec2_security_group claim {claim.id!r} identifier must be a security group id (sg-...)"
        )
    normalized: list[dict[str, Any]] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ClaimsError(f"ingress_forbidden[{index}] must be a mapping")
        extra = sorted(set(rule) - {"protocol", "from_port", "to_port", "cidr"})
        if extra:
            raise ClaimsError(f"ingress_forbidden[{index}] has unknown keys: {extra}")
        protocol = _protocol(rule.get("protocol"), index)
        from_port = _port(rule.get("from_port"), index, "from_port")
        to_port = _port(rule.get("to_port"), index, "to_port")
        if from_port > to_port:
            raise ClaimsError(f"ingress_forbidden[{index}] from_port is greater than to_port")
        cidr = rule.get("cidr")
        if not isinstance(cidr, str) or not cidr.strip():
            raise ClaimsError(f"ingress_forbidden[{index}].cidr must be a CIDR string")
        try:
            ipaddress.ip_network(cidr, strict=True)
        except ValueError as exc:
            raise ClaimsError(f"ingress_forbidden[{index}].cidr is not a network: {cidr}") from exc
        normalized.append(
            {
                "protocol": protocol,
                "from_port": from_port,
                "to_port": to_port,
                "cidr": cidr,
            }
        )
    return normalized


def _protocol(value: object, index: int) -> str:
    if value == -1 or value == "-1":
        return "-1"
    if isinstance(value, str):
        lowered = value.lower()
        if lowered == "all":
            return "-1"
        if lowered in _PROTOCOLS:
            return lowered
    raise ClaimsError(
        f"ingress_forbidden[{index}].protocol must be tcp, udp, icmp, all, or -1"
    )


def _port(value: object, index: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ClaimsError(f"ingress_forbidden[{index}].{name} must be an integer port")
    if value < 0 or value > 65535:
        raise ClaimsError(f"ingress_forbidden[{index}].{name} must be between 0 and 65535")
    return value

