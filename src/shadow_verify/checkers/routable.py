"""Which addresses count as on the internet.

The decision does not call ``ipaddress`` ``is_global`` on a whole prefix.
``0.0.0.0/0`` and ``0.0.0.0/1`` overlap the public internet even when
``is_global`` is the wrong question for a wide block. A prefix overlaps a
globally routable address when it is not entirely inside the pinned
non-global ranges below.
"""

from __future__ import annotations

import ipaddress

# Pinned. A unit test checks each entry with ``not network.is_global``.
NON_GLOBAL_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
)

_NON_GLOBAL = tuple(ipaddress.ip_network(cidr) for cidr in NON_GLOBAL_CIDRS)
_WORLD_V4 = ipaddress.ip_network("0.0.0.0/0")
_WORLD_V6 = ipaddress.ip_network("::/0")


def is_world(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    return network == _WORLD_V4 or network == _WORLD_V6


def overlaps_globally_routable(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """True when some address in ``network`` is outside the non-global list."""

    pieces: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [network]
    for blocked in _NON_GLOBAL:
        if blocked.version != network.version:
            continue
        pieces = _remove_blocked(pieces, blocked)
        if not pieces:
            return False
    return True


def _remove_blocked(
    pieces: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    blocked: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    kept: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for piece in pieces:
        if piece.subnet_of(blocked):
            continue
        if not piece.overlaps(blocked):
            kept.append(piece)
            continue
        kept.extend(piece.address_exclude(blocked))
    return kept
