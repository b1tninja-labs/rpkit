"""Resource certificates: reading RFC 3779 resources, the RFC 6487 profile, and path validation.

Decoding the IP address and AS number extensions is asn1core's (``asn1core.resources``, with its own
vectors and the RFC 3779 errata 2537 and 6792); this module consumes it, and does what a relying
party does with the result:

* :func:`read_resources` reads a certificate's resources through asn1core, strictly or, with
  ``lenient=True``, through asn1core's lenient reader, which keeps a non-canonical set and reports
  each canonical-form break as a defect. A lenient read never makes a certificate valid: every
  defect becomes an ERROR finding in :func:`profile_check`;
* :func:`profile_check` applies RFC 6487 sections 4.8.9 to 4.8.11 (and RFC 8360 sections 4.2.4.1 to
  4.2.4.3 for certificates of the validation-reconsidered profile): the extensions are critical,
  at least one is present, a family has no SAFI, a set is non-empty or ``inherit``, no RDI, one
  certificate policy of the right version;
* :func:`validate_path` is the resource half of path validation. The default procedure is RFC 6487
  section 7 (read through rfclib on 2026-11-13): the resources of each certificate must be
  encompassed by those of the one above it, or the certificate is rejected. RFC 8360 is selectable
  (:class:`Procedure`): a certificate that carries the validation-reconsidered policy and
  overclaims is accepted for the intersection with the Verified Resource Set (RFC 8360 section
  4.2.4.4, steps 7 and 8), with a warning; a certificate under the original policy is still
  rejected. The decision is recorded in ``docs/strategy.md`` and every result names the procedure.

The arithmetic is exact integer ranges. ``inherit`` resolves to the issuer's set (RFC 3779
sections 2.3 and 3.3; in RFC 8360 to its Verified Resource Set), and a trust anchor that inherits is
refused: it has no issuer.
"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from asn1core.extensions import parse_certificate_policies
from asn1core.resources import (
    ASResources,
    IPResources,
    ResourceError,
    parse_as_resources,
    parse_ip_resources,
    ranges_cover,
)

from .findings import Finding, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from asn1core.cert import Certificate

__all__ = [
    "ID_CP_IPADDR_ASNUMBER",
    "ID_CP_IPADDR_ASNUMBER_V2",
    "ID_PE_AUTONOMOUS_SYS_IDS",
    "ID_PE_AUTONOMOUS_SYS_IDS_V2",
    "ID_PE_IP_ADDR_BLOCKS",
    "ID_PE_IP_ADDR_BLOCKS_V2",
    "CertResources",
    "PathResult",
    "PathStep",
    "Procedure",
    "ResourceReadError",
    "ResourceSet",
    "outside",
    "profile_check",
    "read_resources",
    "resolve",
    "validate_path",
]

# RFC 3779 sections 2.2.1 and 3.2.1 (id-pe 7 and 8); RFC 8360 sections 4.2.2.1 and 4.2.2.3 (id-pe 28 and 29).
ID_PE_IP_ADDR_BLOCKS = "1.3.6.1.5.5.7.1.7"
ID_PE_AUTONOMOUS_SYS_IDS = "1.3.6.1.5.5.7.1.8"
ID_PE_IP_ADDR_BLOCKS_V2 = "1.3.6.1.5.5.7.1.28"
ID_PE_AUTONOMOUS_SYS_IDS_V2 = "1.3.6.1.5.5.7.1.29"
# RFC 6484 section 1.2 (id-cp 2) and RFC 8360 section 4.2.1 (id-cp 3).
ID_CP_IPADDR_ASNUMBER = "1.3.6.1.5.5.7.14.2"
ID_CP_IPADDR_ASNUMBER_V2 = "1.3.6.1.5.5.7.14.3"
_ID_CE_CERTIFICATE_POLICIES = "2.5.29.32"

Range = tuple[int, int]
Family = tuple[int, int | None]  # (AFI, SAFI or None)
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class Procedure(enum.StrEnum):
    """The certification path validation procedure: RFC 6487 section 7 (the default) or RFC 8360."""

    RFC6487 = "rfc6487"
    RFC8360 = "rfc8360"


class ResourceReadError(ValueError):
    """A certificate whose resource extensions cannot be read as one coherent set."""


def _norm(ranges: Iterable[Range]) -> tuple[Range, ...]:
    out: list[Range] = []
    for low, high in sorted(ranges):
        if out and low <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], high))
        else:
            out.append((low, high))
    return tuple(out)


def _intersect(a: tuple[Range, ...], b: tuple[Range, ...]) -> tuple[Range, ...]:
    out: list[Range] = []
    i = j = 0
    while i < len(a) and j < len(b):
        low, high = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if low <= high:
            out.append((low, high))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return tuple(out)


def _subtract(a: tuple[Range, ...], b: tuple[Range, ...]) -> tuple[Range, ...]:
    out: list[Range] = []
    for low, high in a:
        cursor = low
        for b_low, b_high in b:
            if b_high < cursor or b_low > high:
                continue
            if b_low > cursor:
                out.append((cursor, b_low - 1))
            cursor = max(cursor, b_high + 1)
            if cursor > high:
                break
        if cursor <= high:
            out.append((cursor, high))
    return tuple(out)


@dataclass(frozen=True, slots=True)
class ResourceSet:
    """A resolved set of number resources: integer ranges per address family, and AS ranges.

    ``ip`` is a tuple of ``((afi, safi), ranges)`` sorted by family, each ``ranges`` sorted,
    non-overlapping and coalesced; families with no ranges are omitted. ``asn`` likewise.
    """

    ip: tuple[tuple[Family, tuple[Range, ...]], ...] = ()
    asn: tuple[Range, ...] = ()

    @classmethod
    def of(
        cls, ip: Mapping[Family, Iterable[Range]] | None = None, asn: Iterable[Range] = ()
    ) -> ResourceSet:
        """Build a normalised set from unsorted, possibly overlapping ranges."""
        families = tuple(
            sorted(
                (family, merged)
                for family, ranges in (ip or {}).items()
                if (merged := _norm(ranges))
            )
        )
        return cls(families, _norm(asn))

    def ip_ranges(self, afi: int, safi: int | None = None) -> tuple[Range, ...]:
        for family, ranges in self.ip:
            if family == (afi, safi):
                return ranges
        return ()

    @property
    def is_empty(self) -> bool:
        return not self.ip and not self.asn

    def covers(self, other: ResourceSet) -> bool:
        """True when every resource of ``other`` is in this set (RFC 6487 section 7.1 "encompass")."""
        families = {family for family, _ in self.ip}
        for family, ranges in other.ip:
            if family not in families and ranges:
                return False
            if not ranges_cover(self.ip_ranges(*family), ranges):
                return False
        return ranges_cover(self.asn, other.asn)

    def intersection(self, other: ResourceSet) -> ResourceSet:
        ip = {f: _intersect(r, other.ip_ranges(*f)) for f, r in self.ip}
        return ResourceSet.of(ip, _intersect(self.asn, other.asn))

    def difference(self, other: ResourceSet) -> ResourceSet:
        """What this set holds that ``other`` does not: the overclaim of this set over ``other``."""
        ip = {f: _subtract(r, other.ip_ranges(*f)) for f, r in self.ip}
        return ResourceSet.of(ip, _subtract(self.asn, other.asn))


@dataclass(frozen=True, slots=True)
class CertResources:
    """The resource extensions of one certificate, as read.

    ``v2`` is true when the extensions present are the RFC 8360 id-pe 28 and 29 ones;
    ``mixed`` when one is v1 and the other v2. ``ip_critical`` and ``as_critical`` are ``None``
    for an absent extension. ``policies`` are the dotted certificate policy OIDs.
    """

    ip: IPResources | None
    asn: ASResources | None
    v2: bool
    mixed: bool
    ip_critical: bool | None
    as_critical: bool | None
    policies: tuple[str, ...]
    defects: tuple[tuple[str, str], ...] = ()

    @property
    def uses_v2_policy(self) -> bool:
        return ID_CP_IPADDR_ASNUMBER_V2 in self.policies


def _extension(cert: Certificate, v1: str, v2: str):
    first, second = cert.extension(v1), cert.extension(v2)
    if first is not None and second is not None:
        raise ResourceReadError(f"the certificate carries both extension {v1} and extension {v2}")
    return (first, False) if first is not None else (second, second is not None)


def read_resources(cert: Certificate, *, lenient: bool = False) -> CertResources:
    """Read a certificate's resource extensions and certificate policies through asn1core.

    Both the RFC 3779 OIDs (id-pe 7 and 8) and the RFC 8360 ones (id-pe 28 and 29) are looked
    for. ``ResourceReadError`` for a certificate carrying both OIDs of one extension, and for a
    resource extension that is not a resource set at all (structure, DER, AFI), whatever
    ``lenient`` says. With ``lenient=True`` a set that breaks a canonical-form rule is returned
    with its defects in ``defects`` as ``(rule, message)``; without it that is an error too.
    """
    try:
        ip_ext, ip_v2 = _extension(cert, ID_PE_IP_ADDR_BLOCKS, ID_PE_IP_ADDR_BLOCKS_V2)
        as_ext, as_v2 = _extension(cert, ID_PE_AUTONOMOUS_SYS_IDS, ID_PE_AUTONOMOUS_SYS_IDS_V2)
        ip = None if ip_ext is None else parse_ip_resources(ip_ext.value, lenient=lenient)
        asn = None if as_ext is None else parse_as_resources(as_ext.value, lenient=lenient)
        policy_ext = cert.extension(_ID_CE_CERTIFICATE_POLICIES)
        policies = (
            ()
            if policy_ext is None
            else tuple(
                ".".join(map(str, p.policy)) for p in parse_certificate_policies(policy_ext.value)
            )
        )
    except ResourceError as error:
        raise ResourceReadError(str(error)) from error
    except Exception as error:
        if isinstance(error, ResourceReadError):
            raise
        raise ResourceReadError(f"{type(error).__name__}: {error}") from error
    present_v2 = [flag for ext, flag in ((ip_ext, ip_v2), (as_ext, as_v2)) if ext is not None]
    defects = tuple(
        (d.rule, d.message) for part in (ip, asn) if part is not None for d in part.defects
    )
    return CertResources(
        ip=ip,
        asn=asn,
        v2=bool(present_v2) and all(present_v2),
        mixed=len(set(present_v2)) > 1,
        ip_critical=None if ip_ext is None else ip_ext.critical,
        as_critical=None if as_ext is None else as_ext.critical,
        policies=policies,
        defects=defects,
    )


def _err(rule: str, message: str, spec: str) -> Finding:
    return Finding(Severity.ERROR, rule, message, spec)


def profile_check(
    res: CertResources, *, procedure: Procedure = Procedure.RFC6487
) -> tuple[Finding, ...]:
    """Check the resource extensions and policy of a certificate against the profile.

    RFC 6487 sections 4.8.9, 4.8.10 and 4.8.11, or for ``Procedure.RFC8360`` also sections
    4.2.4.1 to 4.2.4.3 of RFC 8360. Every canonical-form defect of a lenient read is an ERROR
    finding here. Returns the findings in the order of the checks; an empty tuple means the
    resources and policy conform.
    """
    found: list[Finding] = []
    for rule, message in res.defects:
        found.append(
            _err(f"resources.non-canonical.{rule}", message, "RFC 3779 sections 2.2.3 and 3.2.3")
        )
    if res.ip is None and res.asn is None:
        found.append(
            _err(
                "resources.missing",
                "neither the IP resources nor the AS resources extension is present",
                "RFC 6487 sections 4.8.10 and 4.8.11",
            )
        )
    if res.ip is not None and res.ip_critical is not True:
        found.append(
            _err(
                "resources.ip-not-critical",
                "the IP resources extension is not critical",
                "RFC 6487 section 4.8.10",
            )
        )
    if res.asn is not None and res.as_critical is not True:
        found.append(
            _err(
                "resources.as-not-critical",
                "the AS resources extension is not critical",
                "RFC 6487 section 4.8.11",
            )
        )
    if res.ip is not None:
        for family in res.ip.families:
            if family.safi is not None:
                found.append(
                    _err(
                        "resources.safi",
                        f"address family {family.afi} carries SAFI {family.safi}",
                        "RFC 6487 section 4.8.10",
                    )
                )
            if not family.inherit and not family.ranges:
                found.append(
                    _err(
                        "resources.empty",
                        f"address family {family.afi} is neither inherit nor a non-empty set",
                        "RFC 6487 section 4.8.10",
                    )
                )
    if res.asn is not None:
        if res.asn.rdi is not None:
            found.append(
                _err(
                    "resources.rdi",
                    "the AS resources extension carries an RDI",
                    "RFC 6487 section 4.8.11",
                )
            )
        if res.asn.asnum is None:
            found.append(
                _err(
                    "resources.as-empty",
                    "the AS resources extension holds no asnum",
                    "RFC 6487 section 4.8.11",
                )
            )
        elif not res.asn.asnum.inherit and not res.asn.asnum.ranges:
            found.append(
                _err(
                    "resources.as-empty",
                    "asnum is neither inherit nor a non-empty set",
                    "RFC 6487 section 4.8.11",
                )
            )
    found.extend(_policy_findings(res, procedure))
    return tuple(found)


def _policy_findings(res: CertResources, procedure: Procedure) -> list[Finding]:
    if len(res.policies) != 1:
        return [
            _err(
                "policy.count",
                f"the certificate carries {len(res.policies)} policies, exactly one is required",
                "RFC 6487 section 4.8.9",
            )
        ]
    (policy,) = res.policies
    if policy == ID_CP_IPADDR_ASNUMBER:
        if res.v2 or res.mixed:
            return [
                _err(
                    "policy.version-mismatch",
                    "the original policy (id-cp 2) goes with the id-pe 7 and 8 extensions, not the RFC 8360 ones",
                    "RFC 8360 section 4.2.4.4",
                )
            ]
        return []
    if policy == ID_CP_IPADDR_ASNUMBER_V2:
        if procedure is Procedure.RFC6487:
            return [
                _err(
                    "policy.v2-under-rfc6487",
                    "the validation-reconsidered policy (id-cp 3) is not valid under RFC 6487 section 7",
                    "RFC 6487 section 4.8.9, RFC 8360 section 4.2.1",
                )
            ]
        if not res.v2 or res.mixed:
            return [
                _err(
                    "policy.version-mismatch",
                    "the validation-reconsidered policy (id-cp 3) needs the id-pe 28 and 29 extensions",
                    "RFC 8360 sections 4.2.2.1 and 4.2.4.4",
                )
            ]
        return []
    return [
        _err(
            "policy.unknown",
            f"certificate policy {policy} is not the RPKI policy",
            "RFC 6487 section 4.8.9",
        )
    ]


def resolve(res: CertResources, parent: ResourceSet | None) -> ResourceSet:
    """The resources a certificate claims, with ``inherit`` replaced by the issuer's set.

    ``parent`` is the issuer's resolved set (its Verified Resource Set under RFC 8360). A trust
    anchor passes ``None``; ``ResourceReadError`` if it, or any certificate, inherits with no
    issuer set to inherit from. A family the issuer lacks resolves to nothing (so the
    certificate, if it inherits it, claims nothing there).
    """
    ip: dict[Family, tuple[Range, ...]] = {}
    if res.ip is not None:
        for family in res.ip.families:
            key = (family.afi, family.safi)
            if family.inherit:
                if parent is None:
                    raise ResourceReadError("a trust anchor cannot inherit its resources")
                ip[key] = parent.ip_ranges(*key)
            else:
                ip[key] = family.ranges
    asn: tuple[Range, ...] = ()
    if res.asn is not None and res.asn.asnum is not None:
        if res.asn.asnum.inherit:
            if parent is None:
                raise ResourceReadError("a trust anchor cannot inherit its resources")
            asn = parent.asn
        else:
            asn = res.asn.asnum.ranges
    return ResourceSet.of(ip, asn)


@dataclass(frozen=True, slots=True)
class PathStep:
    """The outcome of one certificate in :func:`validate_path`.

    ``claimed`` is what the certificate says (inherit resolved), ``overclaim`` what it says that
    the certificate above does not, ``vrs`` its Verified Resource Set (the intersection under RFC
    8360, the claim otherwise) and ``accepted`` whether the path may continue through it.
    """

    index: int
    claimed: ResourceSet
    overclaim: ResourceSet
    vrs: ResourceSet
    accepted: bool
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class PathResult:
    """The result of :func:`validate_path`: the procedure used, every step, and the verdict."""

    procedure: Procedure
    steps: tuple[PathStep, ...]

    @property
    def valid(self) -> bool:
        return all(step.accepted for step in self.steps)

    @property
    def vrs(self) -> ResourceSet:
        """The Verified Resource Set of the last certificate, empty if the path is invalid."""
        return self.steps[-1].vrs if self.valid and self.steps else ResourceSet()


def validate_path(
    chain: Sequence[CertResources], *, procedure: Procedure = Procedure.RFC6487
) -> PathResult:
    """The resource half of path validation, trust anchor first (RFC 6487 section 7, RFC 8360).

    ``chain[0]`` is the trust anchor certificate; each later certificate is issued by the one
    before it. For each certificate the claimed resources are compared with the Verified
    Resource Set above it: no overclaim is accepted under either procedure; an overclaim is a
    rejection under ``Procedure.RFC6487`` (section 7.1: every adjacent pair must encompass) and
    under ``Procedure.RFC8360`` for a certificate with the original policy, but under RFC 8360
    section 4.2.4.4 step 8 a certificate with the validation-reconsidered policy is accepted with
    a warning that lists the overclaim, and its VRS is the intersection. A step after a rejected
    one is not evaluated against a set and is reported rejected. The profile of each certificate
    is :func:`profile_check`, not repeated here.
    """
    steps: list[PathStep] = []
    above: ResourceSet | None = None
    broken = False
    for index, res in enumerate(chain):
        findings: list[Finding] = []
        try:
            claimed = resolve(res, above)
        except ResourceReadError as error:
            steps.append(
                PathStep(
                    index,
                    ResourceSet(),
                    ResourceSet(),
                    ResourceSet(),
                    False,
                    (_err("path.inherit", str(error), "RFC 3779 sections 2.3 and 3.3"),),
                )
            )
            broken = True
            above = ResourceSet()
            continue
        if broken:
            steps.append(
                PathStep(
                    index,
                    claimed,
                    ResourceSet(),
                    ResourceSet(),
                    False,
                    (
                        _err(
                            "path.broken",
                            "a certificate above was rejected",
                            "RFC 6487 section 7.2",
                        ),
                    ),
                )
            )
            continue
        over = ResourceSet() if above is None else claimed.difference(above)
        vrs = claimed
        accepted = True
        if not over.is_empty:
            if procedure is Procedure.RFC8360 and res.uses_v2_policy:
                vrs = claimed.intersection(above) if above is not None else claimed
                findings.append(
                    Finding(
                        Severity.WARNING,
                        "path.overclaim-accepted",
                        "the certificate overclaims; accepted for the intersection with the issuer's Verified Resource Set",
                        "RFC 8360 section 4.2.4.4 step 8",
                    )
                )
            else:
                accepted = False
                spec = (
                    "RFC 6487 section 7.1"
                    if procedure is Procedure.RFC6487
                    else "RFC 8360 section 4.2.4.4 step 8"
                )
                findings.append(
                    _err(
                        "path.overclaim",
                        "the certificate claims resources its issuer does not hold",
                        spec,
                    )
                )
                vrs = ResourceSet()
                broken = True
        steps.append(PathStep(index, claimed, over, vrs, accepted, tuple(findings)))
        above = vrs
    return PathResult(procedure, tuple(steps))


def outside(vrs: ResourceSet, prefixes: Iterable[Network]) -> tuple[Network, ...]:
    """The prefixes that are not inside ``vrs``: the ROA check of RFC 9582 section 5 (RFC 8360
    section 4.2.5 for the VRS-IP), as the list of violations, empty when every prefix is covered.
    """
    bad: list[Network] = []
    for prefix in prefixes:
        afi = 1 if prefix.version == 4 else 2
        span = (int(prefix.network_address), int(prefix.broadcast_address))
        if not ranges_cover(vrs.ip_ranges(afi), (span,)):
            bad.append(prefix)
    return tuple(bad)
