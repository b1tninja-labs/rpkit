"""route origin authorisation payloads: prefix, ASN, max length.

`Vrp` is the Validated ROA Payload of RFC 6811 section 2: the (prefix, maximum length, origin AS)
triple a relying party hands to a router once a ROA has validated. It is the one record the rest of
the portfolio shares by shape, not by import: routevalid keeps its own `Vrp` with the same three
fields so neither project depends on the other, and a conversion is `Vrp(v.prefix, v.max_length,
v.asn)`.

Parsing the ROA eContent of RFC 9582 (RFC 6482 is obsolete) is a row of its own in ROADMAP.md; this
module holds only the payload type that the SLURM layer and a future ROA decoder both need.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

__all__ = ["MAX_ASN", "Vrp", "vrp_sort_key"]

MAX_ASN = 2**32 - 1

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class Vrp:
    """One Validated ROA Payload (RFC 6811 section 2).

    ``max_length`` is never absent here: a ROA without a maxLength authorises exactly the prefix
    (RFC 9582 section 4.3.2.2), which is ``max_length == prefix.prefixlen``. An ASN of 0 is a legal
    VRP and can never match a route (RFC 6811 section 2). ``prefix`` is an ``ip_network`` built with
    ``strict=True``, so host bits cannot exist.
    """

    prefix: Network
    max_length: int
    asn: int

    def __post_init__(self) -> None:
        if not isinstance(self.prefix, ipaddress.IPv4Network | ipaddress.IPv6Network):
            raise TypeError("Vrp.prefix must be an ipaddress network")
        if isinstance(self.max_length, bool) or not isinstance(self.max_length, int):
            raise TypeError("Vrp.max_length must be an int")
        if isinstance(self.asn, bool) or not isinstance(self.asn, int):
            raise TypeError("Vrp.asn must be an int")
        if not self.prefix.prefixlen <= self.max_length <= self.prefix.max_prefixlen:
            raise ValueError(
                f"max length {self.max_length} is outside {self.prefix.prefixlen}.."
                f"{self.prefix.max_prefixlen} for {self.prefix}"
            )
        if not 0 <= self.asn <= MAX_ASN:
            raise ValueError(f"ASN {self.asn} is outside 0..{MAX_ASN}")


def vrp_sort_key(vrp: Vrp) -> tuple[int, int, int, int, int]:
    """A total order over VRPs of both families: IPv4 first, then address, length, max, ASN.

    ``ipaddress`` networks of different families do not compare, so a plain ``sorted`` raises on a
    mixed set; this key is what makes output deterministic.
    """
    return (
        vrp.prefix.version,
        int(vrp.prefix.network_address),
        vrp.prefix.prefixlen,
        vrp.max_length,
        vrp.asn,
    )
