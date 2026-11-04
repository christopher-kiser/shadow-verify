"""CIDR rules v0 actually implements, plus the cases it does not."""

from __future__ import annotations

import ipaddress

from shadow_verify.checkers.routable import NON_GLOBAL_CIDRS
from shadow_verify.checkers.sg_rules import _sources, assess_forbid
from shadow_verify.models import Verdict


def _forbid(cidr, protocol="tcp", start=22, end=22):
    return {"protocol": protocol, "from_port": start, "to_port": end, "cidr": cidr}


def _perm(protocol, cidrs, start=22, end=22, extra=None):
    entry = {
        "IpProtocol": protocol,
        "IpRanges": [{"CidrIp": cidr} for cidr in cidrs],
    }
    if start is not None:
        entry["FromPort"] = start
        entry["ToPort"] = end
    if extra:
        entry.update(extra)
    return entry


def _verdict(rule, permissions):
    return assess_forbid(0, rule, permissions).verdict


def test_non_global_entries_are_not_global():
    for cidr in NON_GLOBAL_CIDRS:
        assert ipaddress.ip_network(cidr).is_global is False


def test_normalization_and_world_cover():
    assert ipaddress.ip_network("10.0.0.1/8", strict=False) == ipaddress.ip_network("10.0.0.0/8")
    halves = [ipaddress.ip_network("0.0.0.0/1"), ipaddress.ip_network("128.0.0.0/1")]
    collapsed = list(ipaddress.collapse_addresses(halves))
    assert collapsed == [ipaddress.ip_network("0.0.0.0/0")]
    assert ipaddress.ip_network("::0/0") == ipaddress.ip_network("::/0")


def test_forbids_fail_closed():
    world = _forbid("0.0.0.0/0")
    assert _verdict(world, [_perm("tcp", ["0.0.0.0/1"])]) is Verdict.FAIL
    v6 = _forbid("::/0")
    assert _verdict(v6, [_perm("tcp", [], extra={"Ipv6Ranges": [{"CidrIpv6": "::/1"}]})]) is Verdict.FAIL
    assert _verdict(world, [_perm("tcp", [], extra={"Ipv6Ranges": [{"CidrIpv6": "::/0"}]})]) is Verdict.FAIL
    wide = _perm("tcp", ["0.0.0.0/0"], 0, 65535)
    assert _verdict(world, [wide]) is Verdict.FAIL
    assert _verdict(world, [_perm("-1", ["0.0.0.0/0"], None, None)]) is Verdict.FAIL
    assert _verdict(_forbid("0.0.0.0/0", "-1", 0, 65535), [_perm("tcp", ["0.0.0.0/0"])]) is Verdict.FAIL
    assert _verdict(_forbid("0.0.0.0/0"), [_perm("6", ["0.0.0.0/0"])]) is Verdict.FAIL
    assert _verdict(_forbid("10.0.0.0/8"), [_perm("tcp", ["10.1.0.0/16"])]) is Verdict.FAIL
    private = [
        _perm("tcp", ["10.0.0.0/8"]),
        _perm("tcp", ["100.64.0.0/10"]),
    ]
    assert _verdict(world, private) is Verdict.PASS
    assert _verdict(_forbid("10.0.0.0/8"), [_perm("tcp", ["192.168.0.0/16"])]) is Verdict.PASS


def test_unresolvable_sources_and_equals_extra_is_not_a_pass_path():
    world = _forbid("0.0.0.0/0")
    prefix = _perm("tcp", [], extra={"PrefixListIds": [{"PrefixListId": "pl-1"}]})
    group = _perm("tcp", [], extra={"UserIdGroupPairs": [{"GroupId": "sg-1"}]})
    assert _verdict(world, [prefix]).value == "NOT_ASSESSED"
    assert _verdict(world, [group]).value == "NOT_ASSESSED"
    both = _perm(
        "tcp",
        ["0.0.0.0/0"],
        extra={"PrefixListIds": [{"PrefixListId": "pl-1"}]},
    )
    assert _verdict(world, [both]) is Verdict.FAIL


def test_explode_and_missing_ports():
    entry = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        "PrefixListIds": [{"PrefixListId": "pl-1"}],
        "UserIdGroupPairs": [{"GroupId": "sg-1"}],
    }
    assert len(_sources(entry)) >= 4
    open_all = {"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    assert _verdict(_forbid("0.0.0.0/0"), [open_all]) is Verdict.FAIL


def test_partial_port_cover_still_overlaps_a_forbid():
    # 10.1.0.0/17 on port 22 and the other half on every port both overlap 10.1.0.0/16.
    rules = [
        _perm("tcp", ["10.1.0.0/17"], 22, 22),
        _perm("tcp", ["10.1.128.0/17"], 0, 65535),
    ]
    assert _verdict(_forbid("10.1.0.0/16"), rules) is Verdict.FAIL
