"""MOCKED. The pinned non-global list matches this interpreter's is_global."""

import ipaddress

from shadow_verify.checkers.routable import NON_GLOBAL_CIDRS


def test_pinned_non_global_ranges_are_not_global():
    for cidr in NON_GLOBAL_CIDRS:
        assert not ipaddress.ip_network(cidr).is_global, cidr
