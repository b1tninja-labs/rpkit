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

from asn1core import Asn1Error, Tag, TagClass, check_bit_string, check_integer, decode

from .findings import Finding, Severity

__all__ = [
    "MAX_ASN",
    "ROA_CONTENT_TYPE",
    "Roa",
    "RoaAddress",
    "RoaError",
    "Vrp",
    "parse_roa_content",
    "vrp_sort_key",
]

MAX_ASN = 2**32 - 1
ROA_CONTENT_TYPE = "1.2.840.113549.1.9.16.1.24"  # id-ct-routeOriginAuthz, RFC 9582 section 4

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


class RoaError(ValueError):
    """A ROA eContent that RFC 9582 section 4 does not allow; ``findings`` lists every error found."""

    def __init__(self, findings: tuple[Finding, ...]) -> None:
        super().__init__("; ".join(str(f) for f in findings))
        self.findings = findings


@dataclass(frozen=True, slots=True)
class RoaAddress:
    """One ROAIPAddress: the prefix and the maxLength as encoded (``None`` when absent)."""

    prefix: Network
    max_length: int | None

    @property
    def effective_max(self) -> int:
        """The maximum length that applies: the encoded one, or the prefix length (section 4.3.2.2)."""
        return self.prefix.prefixlen if self.max_length is None else self.max_length


@dataclass(frozen=True, slots=True)
class Roa:
    """A parsed RouteOriginAttestation (RFC 9582 section 4).

    ``addresses`` are in the encoded order, both families. ``findings`` holds only warnings:
    anything that makes the content invalid raises :class:`RoaError` instead.
    """

    asn: int
    addresses: tuple[RoaAddress, ...]
    findings: tuple[Finding, ...] = ()

    @property
    def canonical(self) -> bool:
        """True when ipAddrBlocks is in the canonical form of section 4.3.3."""
        return not any(f.rule == "roa.not-canonical" for f in self.findings)

    def vrps(self) -> tuple[Vrp, ...]:
        """The distinct VRPs this ROA states, in :func:`vrp_sort_key` order."""
        found = {Vrp(a.prefix, a.effective_max, self.asn) for a in self.addresses}
        return tuple(sorted(found, key=vrp_sort_key))


_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_UNIVERSAL_SEQ = Tag(16, True, TagClass.universal)


def _bad(rule: str, message: str, spec: str) -> Finding:
    return Finding(Severity.ERROR, rule, message, spec)


def parse_roa_content(econtent: bytes) -> Roa:
    """Parse the DER eContent of a ROA (RFC 9582 section 4; RFC 6482 is obsolete).

    Refused with :class:`RoaError`: anything that is not DER; a ``version`` that is present
    (the only value allowed is 0, which is the DEFAULT and so must be omitted, X.690 section
    11.5); an asID outside 0..4294967295; ipAddrBlocks that is not one or two ROAIPAddressFamily;
    an address family other than 0001 or 0002, or one repeated; an empty address list; a
    prefix longer than its family; a maxLength below the prefix length or above 32 or 128; an
    IPv6 prefix inside ::ffff:0:0/96 (an IPv4 prefix as an IPv4-mapped address, section 4.3.1);
    octets after the SEQUENCE. Reported as warnings: a maxLength equal to the prefix length
    (section 4.3.2.2 SHOULD NOT), an identical prefix twice with different maxLength (4.3.2.3 NOT
    RECOMMENDED), and an ipAddrBlocks that is not in the canonical order and free of duplicates
    of section 4.3.3.
    """
    spec = "RFC 9582 section 4"
    try:
        top, end = decode(econtent, der=True)
    except Asn1Error as error:
        raise RoaError((_bad("roa.der", str(error), "RFC 6488 section 2"),)) from error
    if end != len(econtent):
        raise RoaError(
            (_bad("roa.trailing", f"{len(econtent) - end} octets follow the ROA", spec),)
        )
    if top.tag != _UNIVERSAL_SEQ:
        raise RoaError((_bad("roa.structure", "RouteOriginAttestation is not a SEQUENCE", spec),))
    items = list(top.children)
    if items and items[0].tag.is_context(0):
        raise RoaError(
            (
                _bad(
                    "roa.version",
                    "version is encoded; it must be 0, the DEFAULT, which DER omits",
                    "RFC 9582 section 4.1, X.690 section 11.5",
                ),
            )
        )
    if len(items) != 2 or items[0].tag != Tag(2) or items[1].tag != _UNIVERSAL_SEQ:
        raise RoaError(
            (_bad("roa.structure", "expected asID INTEGER and ipAddrBlocks SEQUENCE", spec),)
        )
    try:
        asn = check_integer(items[0].payload or b"")
    except Asn1Error as error:
        raise RoaError((_bad("roa.der", str(error), spec),)) from error
    problems: list[Finding] = []
    if not 0 <= asn <= MAX_ASN:
        problems.append(
            _bad("roa.asid", f"asID {asn} is outside 0..4294967295", "RFC 9582 section 4")
        )
    families = items[1].children
    if not 1 <= len(families) <= 2:
        problems.append(
            _bad(
                "roa.families",
                f"{len(families)} ROAIPAddressFamily, SIZE(1..2)",
                "RFC 9582 section 4.3.1",
            )
        )
    addresses: list[RoaAddress] = []
    seen_afi: list[int] = []
    for family in families:
        if family.tag != _UNIVERSAL_SEQ or len(family.children) != 2:
            problems.append(
                _bad("roa.structure", "ROAIPAddressFamily is not a SEQUENCE of two", spec)
            )
            continue
        afi_node, list_node = family.children
        afi_bytes = afi_node.payload if afi_node.tag == Tag(4) else None
        if (
            afi_bytes is None
            or len(afi_bytes) != 2
            or int.from_bytes(afi_bytes, "big") not in (1, 2)
        ):
            problems.append(
                _bad("roa.afi", "addressFamily is not 0001 or 0002", "RFC 9582 section 4.3.1")
            )
            continue
        afi = int.from_bytes(afi_bytes, "big")
        if afi in seen_afi:
            problems.append(
                _bad("roa.afi-repeated", f"AFI {afi} appears twice", "RFC 9582 section 4.3.1")
            )
        seen_afi.append(afi)
        width = 32 if afi == 1 else 128
        if list_node.tag != _UNIVERSAL_SEQ or not list_node.children:
            problems.append(_bad("roa.addresses", "addresses is not a non-empty SEQUENCE", spec))
            continue
        for entry in list_node.children:
            parts = entry.children
            if entry.tag != _UNIVERSAL_SEQ or not 1 <= len(parts) <= 2 or parts[0].tag != Tag(3):
                problems.append(
                    _bad(
                        "roa.structure",
                        "ROAIPAddress is not { BIT STRING, INTEGER OPTIONAL }",
                        spec,
                    )
                )
                continue
            try:
                unused, data = check_bit_string(parts[0].payload or b"")
                max_length = check_integer(parts[1].payload or b"") if len(parts) == 2 else None
                if len(parts) == 2 and parts[1].tag != Tag(2):
                    raise Asn1Error("maxLength is not an INTEGER")
            except Asn1Error as error:
                problems.append(_bad("roa.der", str(error), spec))
                continue
            plen = len(data) * 8 - unused
            if plen > width:
                problems.append(
                    _bad(
                        "roa.prefix",
                        f"prefix of {plen} bits in a {width}-bit family",
                        "RFC 9582 section 4.3.2.1",
                    )
                )
                continue
            packed = data.ljust(width // 8, b"\x00")
            network: Network = (
                ipaddress.IPv4Network((packed, plen))
                if afi == 1
                else ipaddress.IPv6Network((packed, plen))
            )
            if afi == 2 and network.subnet_of(_MAPPED):  # type: ignore[arg-type]
                problems.append(
                    _bad(
                        "roa.mapped",
                        f"{network} is an IPv4 prefix as an IPv4-mapped address",
                        "RFC 9582 section 4.3.1",
                    )
                )
                continue
            if max_length is not None and not plen <= max_length <= width:
                problems.append(
                    _bad(
                        "roa.maxlength",
                        f"maxLength {max_length} outside {plen}..{width} for {network}",
                        "RFC 9582 section 4.3.2.2",
                    )
                )
                continue
            addresses.append(RoaAddress(network, max_length))
    if problems:
        raise RoaError(tuple(problems))
    return Roa(asn, tuple(addresses), _warnings(addresses))


def _warnings(addresses: list[RoaAddress]) -> tuple[Finding, ...]:
    found: list[Finding] = []
    for a in addresses:
        if a.max_length is not None and a.max_length == a.prefix.prefixlen:
            found.append(
                Finding(
                    Severity.WARNING,
                    "roa.maxlength-superfluous",
                    f"maxLength of {a.prefix} equals its prefix length",
                    "RFC 9582 section 4.3.2.2",
                )
            )
    prefixes = [a.prefix for a in addresses]
    for prefix in sorted(
        set(prefixes), key=lambda p: (p.version, int(p.network_address), p.prefixlen)
    ):
        if (
            prefixes.count(prefix) > 1
            and len({a.effective_max for a in addresses if a.prefix == prefix}) > 1
        ):
            found.append(
                Finding(
                    Severity.WARNING,
                    "roa.duplicate-prefix",
                    f"{prefix} appears with different maxLength",
                    "RFC 9582 section 4.3.2.3",
                )
            )
    keys = [
        (
            1 if a.prefix.version == 4 else 2,
            int(a.prefix.network_address),
            a.prefix.prefixlen,
            a.effective_max,
        )
        for a in addresses
    ]
    if keys != sorted(set(keys)):
        found.append(
            Finding(
                Severity.WARNING,
                "roa.not-canonical",
                "ipAddrBlocks is not sorted by (afi, address, prefix length, maxLength) or holds duplicates",
                "RFC 9582 section 4.3.3",
            )
        )
    return tuple(found)
