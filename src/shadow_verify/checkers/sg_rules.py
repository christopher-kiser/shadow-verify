"""Match one security-group permission against one forbid.

AWS puts every source of one permission in a single ``IpPermissions`` entry.
Each CIDR, prefix list, and security-group reference is judged on its own.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from shadow_verify.checkers.routable import is_world, overlaps_globally_routable
from shadow_verify.models import PropertyResult, Verdict

_NUMBERS = {"6": "tcp", "17": "udp", "58": "icmpv6"}


def assess_forbid(index: int, rule: dict[str, Any], permissions: list) -> PropertyResult:
    label = f"{rule['protocol']} {rule['from_port']}-{rule['to_port']} from {rule['cidr']}"
    name = f"ingress_forbidden[{index}]"
    target = ipaddress.ip_network(rule["cidr"], strict=True)
    failed = False
    unresolvable = False
    unknown = False
    for permission in permissions:
        if not isinstance(permission, dict):
            unknown = True
            continue
        outcome = _one_permission(permission, rule, target)
        failed = failed or outcome == "fail"
        unresolvable = unresolvable or outcome == "unresolvable"
        unknown = unknown or outcome == "unknown"
    if failed:
        return PropertyResult(name=name, verdict=Verdict.FAIL, reason=f"ingress allows {label}")
    if unresolvable:
        return PropertyResult(
            name=name,
            verdict=Verdict.NOT_ASSESSED,
            reason=f"unresolvable_source: prefix list or security group on {label}",
        )
    if unknown:
        return PropertyResult(
            name=name,
            verdict=Verdict.NOT_ASSESSED,
            reason=f"ingress permissions could not be fully read for {label}",
        )
    return PropertyResult(name=name, verdict=Verdict.PASS, reason=f"no ingress covers {label}")


def _one_permission(
    permission: dict,
    rule: dict[str, Any],
    target: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> str:
    normalized = _norm_protocol(permission.get("IpProtocol"))
    if normalized is None:
        return "unknown"
    if not _covers(normalized, rule["protocol"]):
        return "clear"
    ports = _ports_overlap(permission, rule)
    if ports == "no":
        return "clear"
    if ports == "unknown":
        return "unknown"
    saw_unresolvable = False
    saw_fail = False
    saw_unknown = False
    for kind, value in _sources(permission):
        if kind == "unresolvable":
            saw_unresolvable = True
            continue
        if kind == "unknown":
            saw_unknown = True
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            saw_unknown = True
            continue
        if _cidr_fails(network, target):
            saw_fail = True
    if saw_fail:
        return "fail"
    if saw_unresolvable:
        return "unresolvable"
    if saw_unknown:
        return "unknown"
    return "clear"


def _sources(permission: dict) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for key, field, kind in (
        ("IpRanges", "CidrIp", "cidr"),
        ("Ipv6Ranges", "CidrIpv6", "cidr"),
        ("PrefixListIds", "", "unresolvable"),
        ("UserIdGroupPairs", "", "unresolvable"),
    ):
        values = permission.get(key, [])
        if values is None:
            continue
        if not isinstance(values, list):
            return [("unknown", key)]
        for entry in values:
            if not isinstance(entry, dict) or not entry:
                found.append(("unknown", key))
                continue
            if kind == "unresolvable":
                found.append(("unresolvable", key))
                continue
            cidr = entry.get(field)
            if isinstance(cidr, str) and cidr:
                found.append(("cidr", cidr))
            elif cidr is not None:
                found.append(("unknown", key))
    return found


def _cidr_fails(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    target: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> bool:
    if is_world(target):
        return overlaps_globally_routable(network)
    if network.version != target.version:
        return False
    return network.overlaps(target)


def _covers(actual: str, expected: str) -> bool:
    if actual == "-1":
        return True
    if expected == "-1":
        return False
    return actual == expected


def _norm_protocol(value: object) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, str):
        return None
    lowered = value.strip().lower()
    if lowered in {"-1", "all"}:
        return "-1"
    return _NUMBERS.get(lowered, lowered)


def _ports_overlap(permission: dict, rule: dict[str, Any]) -> str:
    if "FromPort" not in permission and "ToPort" not in permission:
        return "yes"
    try:
        start = int(permission["FromPort"])
        end = int(permission["ToPort"])
    except (KeyError, TypeError, ValueError):
        return "unknown"
    if start == -1 and end == -1:
        return "yes"
    if start <= rule["to_port"] and end >= rule["from_port"]:
        return "yes"
    return "no"
