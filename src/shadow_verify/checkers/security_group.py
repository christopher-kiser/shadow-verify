"""EC2 security group ingress checks.

``expected.ingress_forbidden`` is a list of rules that must not be covered
by any ingress permission. A permission covers a forbidden rule when:

* the permission protocol is ``-1`` (all), or it equals the forbidden
  protocol; a forbidden protocol of ``-1`` matches only an all-protocol
  permission
* the permission's port range overlaps the forbidden range; an
  all-protocol permission covers every port
* the permission lists the forbidden CIDR with an exact string match on
  ``CidrIp`` or ``CidrIpv6``

``0.0.0.0/0`` does not imply ``::/0``. Security-group and prefix-list
sources are not CIDRs and do not satisfy a CIDR forbid. A permission that
matches the protocol and CIDR but has no ports is NOT ASSESSED, not a
pass.
"""

from __future__ import annotations

from typing import Any

from shadow_verify.aws import BotoAws
from shadow_verify.checkers.base import blocked, call_failure, finish
from shadow_verify.errors import ClaimsError
from shadow_verify.models import CheckResult, Claim, PropertyResult, Verdict

_PROTOCOLS = {"tcp", "udp", "icmp", "-1"}


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
            properties.append(_assess(index, rule, permissions))
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


def _assess(index: int, rule: dict[str, Any], permissions: list) -> PropertyResult:
    name = f"ingress_forbidden[{index}]"
    label = (
        f"{rule['protocol']} {rule['from_port']}-{rule['to_port']} from {rule['cidr']}"
    )
    unknown = False
    for permission in permissions:
        if not isinstance(permission, dict):
            unknown = True
            continue
        kind = _permission_covers(permission, rule)
        if kind == "yes":
            return PropertyResult(
                name=name,
                verdict=Verdict.FAIL,
                reason=f"ingress allows {label}",
            )
        if kind == "unknown":
            unknown = True
    if unknown:
        return PropertyResult(
            name=name,
            verdict=Verdict.NOT_ASSESSED,
            reason=f"ingress permissions could not be fully read for {label}",
        )
    return PropertyResult(
        name=name,
        verdict=Verdict.PASS,
        reason=f"no ingress covers {label}",
    )


def _permission_covers(permission: dict, rule: dict[str, Any]) -> str:
    protocol = permission.get("IpProtocol")
    if not isinstance(protocol, str):
        return "unknown"
    if not _protocol_covers(protocol, rule["protocol"]):
        return "no"
    cidr_state = _cidr_present(permission, rule["cidr"])
    if cidr_state != "yes":
        return cidr_state
    if _norm_protocol(protocol) == "-1":
        return "yes"
    if "FromPort" not in permission or "ToPort" not in permission:
        return "unknown"
    try:
        start = int(permission["FromPort"])
        end = int(permission["ToPort"])
    except (TypeError, ValueError):
        return "unknown"
    if start <= rule["to_port"] and end >= rule["from_port"]:
        return "yes"
    return "no"


def _norm_protocol(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"-1", "all"}:
        return "-1"
    return lowered


def _protocol_covers(actual: str, expected: str) -> bool:
    actual_norm = _norm_protocol(actual)
    if actual_norm == "-1":
        return True
    if expected == "-1":
        return False
    return actual_norm == expected


def _cidr_present(permission: dict, cidr: str) -> str:
    found = False
    for key, field in (("IpRanges", "CidrIp"), ("Ipv6Ranges", "CidrIpv6")):
        ranges = permission.get(key, [])
        if ranges is None:
            continue
        if not isinstance(ranges, list):
            return "unknown"
        for entry in ranges:
            if not isinstance(entry, dict):
                return "unknown"
            if entry.get(field) == cidr:
                found = True
    return "yes" if found else "no"
