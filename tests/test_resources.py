"""Resource certificates: the profile of RFC 6487 section 4.8, and path validation under RFC 6487 section 7 or RFC 8360.

The certificates are built in ``rpkibuild.py`` (no byte vector exists in these RFCs); the resource
numbers are those of RFC 3779 Appendix B (10/8, 172.16/12, AS 135 and 3000-3999) so that they can be
checked against the RFC by eye. The decoder is asn1core's and has its own vectors there.
"""

from __future__ import annotations

import ipaddress
import random
from typing import Any

import pytest
from asn1core import parse_certificate
from asn1core.resources import ranges_cover

from rpkit import resources as r
from rpkit.findings import Severity, errors, warnings

from . import rpkibuild as b

IP = b.ip_blocks(
    {(1, None): [b.prefix_range("10.0.0.0/8"), b.prefix_range("172.16.0.0/12")], (2, None): None}
)
AS = b.as_ids(asnum=[(135, 135), (3000, 3999)])


def read(spec: b.CertSpec, *, lenient: bool = False) -> r.CertResources:
    return r.read_resources(parse_certificate(b.make_cert(spec)), lenient=lenient)


def ca(**kw) -> b.CertSpec:
    base: dict[str, Any] = {
        "ca": True,
        "subject": "TA",
        "issuer": "TA",
        "subject_key": "ta",
        "issuer_key": "ta",
        "self_signed": True,
        "ip": IP,
        "asn": AS,
    }
    base.update(kw)
    return b.CertSpec(**base)


def rules(findings) -> list[str]:
    return [f.rule for f in findings]


def test_read_resources_of_a_conforming_ca_certificate():
    res = read(ca())
    assert not res.v2
    assert not res.mixed
    assert res.ip_critical is True
    assert res.as_critical is True
    assert res.policies == (b.CP_V1,)
    assert res.ip is not None
    assert res.ip.families[0].ranges == (
        (167772160, 184549375),
        (2886729728, 2887778303),
    )
    assert res.asn is not None
    assert res.asn.asnum is not None
    assert res.asn.asnum.ranges == ((135, 135), (3000, 3999))
    assert r.profile_check(res) == ()


def test_the_rfc_8360_extension_oids_are_read_as_v2():
    res = read(ca(v2_extensions=True, policies=(b.CP_V2,)))
    assert res.v2
    assert res.ip is not None
    assert r.profile_check(res, procedure=r.Procedure.RFC8360) == ()


def test_a_certificate_with_both_oids_of_one_extension_is_refused():
    with pytest.raises(r.ResourceReadError, match="carries both"):
        read(ca(both_ip_versions=True))
    with pytest.raises(r.ResourceReadError, match="not a SEQUENCE"):
        read(ca(ip=bytes([4, 0])))


def test_strict_read_refuses_a_non_canonical_set_and_lenient_read_reports_it_as_an_error():
    unsorted = b.ip_blocks(
        {(1, None): [b.prefix_range("172.16.0.0/12"), b.prefix_range("10.0.0.0/8")]}
    )
    spec = ca(ip=unsorted)
    with pytest.raises(r.ResourceReadError, match=r"ascending|sorted|order"):
        read(spec)
    res = read(spec, lenient=True)
    assert [rule for rule, _ in res.defects] == ["ranges-unsorted-or-overlap"]
    assert res.ip is not None
    assert res.ip.families[0].ranges == ((167772160, 184549375), (2886729728, 2887778303))
    found = r.profile_check(res)
    assert rules(found) == ["resources.non-canonical.ranges-unsorted-or-overlap"]
    assert all(f.severity is Severity.ERROR for f in found)


def test_a_lenient_read_still_refuses_what_is_not_a_resource_set():
    with pytest.raises(r.ResourceReadError):
        read(ca(ip=b.seq(b.integer(1))), lenient=True)


def test_profile_missing_extensions_and_criticality():
    bare = read(ca(ip=None, asn=None))
    assert rules(r.profile_check(bare)) == ["resources.missing"]
    soft = read(ca(ip_critical=False, as_critical=False))
    assert rules(r.profile_check(soft)) == [
        "resources.ip-not-critical",
        "resources.as-not-critical",
    ]


def test_profile_safi_empty_set_rdi_and_missing_asnum():
    safi = read(ca(ip=b.ip_blocks({(1, 1): [b.prefix_range("10.0.0.0/8")]}), asn=None))
    assert rules(r.profile_check(safi)) == ["resources.safi"]
    empty_ip = read(ca(ip=b.ip_blocks({(1, None): []}), asn=None))
    assert rules(r.profile_check(empty_ip)) == ["resources.empty"]
    empty_as = read(ca(ip=None, asn=b.as_ids(asnum=[])))
    assert rules(r.profile_check(empty_as)) == ["resources.as-empty"]
    rdi = read(ca(ip=None, asn=b.as_ids(asnum=[(1, 1)], rdi=[(2, 2)])))
    assert rules(r.profile_check(rdi)) == ["resources.rdi"]
    only_rdi = read(ca(ip=None, asn=b.as_ids(rdi=[(2, 2)])))
    assert set(rules(r.profile_check(only_rdi))) == {"resources.rdi", "resources.as-empty"}


def test_inherit_alone_satisfies_the_profile():
    inherit = read(ca(ip=b.ip_blocks({(1, None): None}), asn=b.as_ids(asnum=None)))
    assert r.profile_check(inherit) == ()


def test_profile_policy_rules():
    none = read(ca(policies=()))
    assert rules(r.profile_check(none)) == ["policy.count"]
    two = read(ca(policies=(b.CP_V1, "1.2.3.4")))
    assert rules(r.profile_check(two)) == ["policy.count"]
    other = read(ca(policies=("1.2.3.4",)))
    assert rules(r.profile_check(other)) == ["policy.unknown"]
    v2_in_6487 = read(ca(policies=(b.CP_V2,), v2_extensions=True))
    assert rules(r.profile_check(v2_in_6487)) == ["policy.v2-under-rfc6487"]
    assert r.profile_check(v2_in_6487, procedure=r.Procedure.RFC8360) == ()
    v2_policy_v1_ext = read(ca(policies=(b.CP_V2,)))
    assert rules(r.profile_check(v2_policy_v1_ext, procedure=r.Procedure.RFC8360)) == [
        "policy.version-mismatch"
    ]
    v1_policy_v2_ext = read(ca(policies=(b.CP_V1,), v2_extensions=True))
    assert rules(r.profile_check(v1_policy_v2_ext)) == ["policy.version-mismatch"]


# -- sets -------------------------------------------------------------------------------------------------------


def rs(ip=None, asn=()):
    return r.ResourceSet.of(ip, asn)


def test_resource_set_operations_equal_a_brute_force_over_small_integers():
    rng = random.Random(3779)

    def random_ranges():
        out = []
        for _ in range(rng.randint(0, 5)):
            low = rng.randint(0, 40)
            out.append((low, low + rng.randint(0, 8)))
        return out

    def members(ranges):
        return {v for lo, hi in ranges for v in range(lo, hi + 1)}

    for _ in range(300):
        a, c = random_ranges(), random_ranges()
        left, right = rs(asn=a), rs(asn=c)
        assert members(left.intersection(right).asn) == members(a) & members(c)
        assert members(left.difference(right).asn) == members(a) - members(c)
        assert left.covers(right) == (members(c) <= members(a))
        assert left.covers(right) == ranges_cover(
            left.asn, right.asn
        )  # asn1core's arithmetic agrees


def test_ranges_are_coalesced_and_empty_families_dropped():
    s = rs({(1, None): [(5, 9), (1, 4), (20, 21)], (2, None): []}, [(7, 7), (8, 8)])
    assert s.ip == (((1, None), ((1, 9), (20, 21))),)
    assert s.asn == ((7, 8),)
    assert rs().is_empty
    assert not s.is_empty


def test_a_family_the_parent_lacks_is_not_covered():
    parent = rs({(1, None): [(0, 100)]})
    child = rs({(2, None): [(0, 1)]})
    assert not parent.covers(child)
    assert parent.covers(rs())


def test_resolve_replaces_inherit_with_the_issuer_set_and_refuses_it_at_a_trust_anchor():
    parent = rs({(1, None): [(10, 20)]}, [(1, 5)])
    child = read(
        ca(ip=b.ip_blocks({(1, None): None, (2, None): [(0, 3)]}), asn=b.as_ids(asnum=None))
    )
    got = r.resolve(child, parent)
    assert got.ip_ranges(1) == ((10, 20),)
    assert got.ip_ranges(2) == ((0, 3),)
    assert got.asn == ((1, 5),)
    with pytest.raises(r.ResourceReadError, match="trust anchor"):
        r.resolve(child, None)


# -- paths ---------------------------------------------------------------------------------------------------------


def v4(*prefixes: str):
    return b.ip_blocks({(1, None): [b.prefix_range(p) for p in prefixes]})


def chain(*specs: b.CertSpec) -> list[r.CertResources]:
    return [read(s) for s in specs]


def test_a_nested_chain_is_valid_under_either_procedure():
    path = chain(
        ca(ip=v4("10.0.0.0/8"), asn=None),
        ca(subject="CA1", ip=v4("10.1.0.0/16"), asn=None),
        ca(subject="EE", ip=v4("10.1.2.0/24"), asn=None),
    )
    for procedure in r.Procedure:
        result = r.validate_path(path, procedure=procedure)
        assert result.valid
        assert result.procedure is procedure
        assert [s.accepted for s in result.steps] == [True, True, True]
        assert result.vrs.ip_ranges(1) == (
            (int(ipaddress.ip_address("10.1.2.0")), int(ipaddress.ip_address("10.1.2.255"))),
        )


def test_the_default_procedure_is_rfc_6487_and_an_overclaim_rejects_the_certificate():
    path = chain(
        ca(ip=v4("10.0.0.0/8"), asn=None),
        ca(subject="CA1", ip=v4("10.1.0.0/16", "192.0.2.0/24"), asn=None),
        ca(subject="EE", ip=v4("10.1.2.0/24"), asn=None),
    )
    result = r.validate_path(path)
    assert result.procedure is r.Procedure.RFC6487
    assert not result.valid
    assert [s.accepted for s in result.steps] == [True, False, False]
    assert rules(result.steps[1].findings) == ["path.overclaim"]
    assert result.steps[1].findings[0].spec == "RFC 6487 section 7.1"
    assert result.steps[1].overclaim.ip_ranges(1) == (
        (int(ipaddress.ip_address("192.0.2.0")), int(ipaddress.ip_address("192.0.2.255"))),
    )
    assert rules(result.steps[2].findings) == ["path.broken"]
    assert result.vrs.is_empty


def test_rfc_8360_accepts_a_v2_overclaim_for_the_intersection_with_a_warning():
    v2 = {"v2_extensions": True, "policies": (b.CP_V2,)}
    path = chain(
        ca(ip=v4("10.0.0.0/8"), asn=None, **v2),
        ca(subject="CA1", ip=v4("10.1.0.0/16", "192.0.2.0/24"), asn=None, **v2),
        ca(subject="EE", ip=v4("10.1.2.0/24", "192.0.2.0/25"), asn=None, **v2),
    )
    result = r.validate_path(path, procedure=r.Procedure.RFC8360)
    assert result.valid
    middle = result.steps[1]
    assert rules(warnings(middle.findings)) == ["path.overclaim-accepted"]
    assert middle.findings[0].spec == "RFC 8360 section 4.2.4.4 step 8"
    assert middle.vrs.ip_ranges(1) == (
        (int(ipaddress.ip_address("10.1.0.0")), int(ipaddress.ip_address("10.1.255.255"))),
    )
    # the EE's claim of 192.0.2.0/25 is not in any VRS above it: the VRS shrinks to what is
    assert result.vrs.ip_ranges(1) == (
        (int(ipaddress.ip_address("10.1.2.0")), int(ipaddress.ip_address("10.1.2.255"))),
    )
    assert not errors(result.steps[2].findings)
    # the same chain under RFC 6487 is rejected: the default procedure does not read the v2 policy
    assert not r.validate_path(path).valid


def test_rfc_8360_still_rejects_an_overclaim_under_the_original_policy():
    path = chain(
        ca(ip=v4("10.0.0.0/8"), asn=None),
        ca(subject="CA1", ip=v4("11.0.0.0/8"), asn=None),
    )
    result = r.validate_path(path, procedure=r.Procedure.RFC8360)
    assert not result.valid
    assert result.steps[1].findings[0].spec == "RFC 8360 section 4.2.4.4 step 8"


def test_inheritance_resolves_along_the_chain_and_as_numbers_are_checked_too():
    path = chain(
        ca(ip=v4("10.0.0.0/8"), asn=b.as_ids(asnum=[(100, 200)])),
        ca(subject="CA1", ip=b.ip_blocks({(1, None): None}), asn=b.as_ids(asnum=[(150, 160)])),
        ca(subject="EE", ip=b.ip_blocks({(1, None): None}), asn=b.as_ids(asnum=None)),
    )
    result = r.validate_path(path)
    assert result.valid
    assert result.steps[2].claimed.asn == ((150, 160),)
    assert result.steps[2].claimed.ip_ranges(1) == result.steps[0].claimed.ip_ranges(1)
    over = chain(
        ca(ip=v4("10.0.0.0/8"), asn=b.as_ids(asnum=[(100, 200)])),
        ca(subject="CA1", ip=v4("10.1.0.0/16"), asn=b.as_ids(asnum=[(150, 250)])),
    )
    bad = r.validate_path(over)
    assert not bad.valid
    assert bad.steps[1].overclaim.asn == ((201, 250),)


def test_a_trust_anchor_that_inherits_is_rejected_and_breaks_the_path():
    path = chain(
        ca(ip=b.ip_blocks({(1, None): None}), asn=None),
        ca(subject="CA1", ip=v4("10.0.0.0/8"), asn=None),
    )
    result = r.validate_path(path)
    assert not result.valid
    assert rules(result.steps[0].findings) == ["path.inherit"]
    assert not result.steps[1].accepted


def test_outside_lists_the_roa_prefixes_not_in_the_vrs():
    vrs = rs(
        {(1, None): [b.prefix_range("10.0.0.0/8")], (2, None): [b.prefix_range("2001:db8::/32")]}
    )
    nets = [
        ipaddress.ip_network(p)
        for p in ("10.1.0.0/16", "11.0.0.0/8", "2001:db8:1::/48", "2001:dba::/32", "0.0.0.0/0")
    ]
    assert [str(n) for n in r.outside(vrs, nets)] == ["11.0.0.0/8", "2001:dba::/32", "0.0.0.0/0"]
    assert r.outside(vrs, []) == ()
    assert r.outside(rs(), nets[:1]) == (nets[0],)
