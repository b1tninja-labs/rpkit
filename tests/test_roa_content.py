"""ROA eContent (RFC 9582 section 4). Content is built in ``rpkibuild.py``: the RFC prints no byte vector.

The prefix example is the RFC's own (section 4.3.2.2: 203.0.113.0/24 with maxLength 26 authorises
203.0.113.0/24, 203.0.113.128/25 and 203.0.113.192/26 but not 203.0.113.0/27).
"""

from __future__ import annotations

import ipaddress

import pytest

from rpkit.findings import Severity
from rpkit.roa import Roa, RoaError, Vrp, parse_roa_content

from . import rpkibuild as b


def rules(roa: Roa) -> list[str]:
    return [f.rule for f in roa.findings]


def test_the_rfc_9582_example_parses_to_a_vrp_with_max_length_26():
    roa = parse_roa_content(b.roa_content(64500, [(1, [("203.0.113.0/24", 26)])]))
    assert roa.asn == 64500
    assert roa.vrps() == (Vrp(ipaddress.ip_network("203.0.113.0/24"), 26, 64500),)
    assert roa.canonical
    assert roa.findings == ()


def test_an_absent_max_length_is_the_prefix_length_and_both_families_read():
    roa = parse_roa_content(
        b.roa_content(
            0,
            [(1, [("10.0.0.0/8", None)]), (2, [("2001:db8::/32", None), ("2001:db8:1::/48", 56)])],
        )
    )
    assert [(str(v.prefix), v.max_length) for v in roa.vrps()] == [
        ("10.0.0.0/8", 8),
        ("2001:db8::/32", 32),
        ("2001:db8:1::/48", 56),
    ]
    assert roa.asn == 0
    assert roa.addresses[0].max_length is None


def test_prefix_bit_lengths_that_are_not_octet_aligned_and_the_default_route():
    roa = parse_roa_content(b.roa_content(1, [(1, [("0.0.0.0/0", 8), ("10.0.0.0/21", 24)])]))
    assert [str(a.prefix) for a in roa.addresses] == ["0.0.0.0/0", "10.0.0.0/21"]


@pytest.mark.parametrize(
    ("content", "rule"),
    [
        (b.roa_content(1, [(1, [("10.0.0.0/8", None)])], version=0), "roa.version"),
        (b.roa_content(1, [(1, [("10.0.0.0/8", None)])], version=1), "roa.version"),
        (b.roa_content(1, [(1, [("10.0.0.0/8", 7)])]), "roa.maxlength"),
        (b.roa_content(1, [(1, [("10.0.0.0/8", 33)])]), "roa.maxlength"),
        (b.roa_content(1, [(2, [("2001:db8::/32", 129)])]), "roa.maxlength"),
        (
            b.roa_content(1, [(1, [("10.0.0.0/8", None)]), (1, [("11.0.0.0/8", None)])]),
            "roa.afi-repeated",
        ),
        (b.roa_content(1, [(3, [("10.0.0.0/8", None)])]), "roa.afi"),
        (b.roa_content(1, [(2, [("::ffff:10.0.0.0/104", None)])]), "roa.mapped"),
        (b.roa_content(1, [(2, [("::ffff:0:0/96", None)])]), "roa.mapped"),
        (b.roa_content(1 << 32, [(1, [("10.0.0.0/8", None)])]), "roa.asid"),
        (b.seq(b.integer(1), b.seq()), "roa.families"),
        (b.seq(b.integer(1), b.seq(b.seq(b.octets(b"\x00\x01"), b.seq()))), "roa.addresses"),
        (b.roa_content(1, [(1, [("10.0.0.0/8", None)])]) + b"\x00", "roa.trailing"),
        (b"\x30\x80\x00\x00", "roa.der"),
        (b.seq(b.integer(1)), "roa.structure"),
    ],
)
def test_content_that_rfc_9582_forbids_is_refused_with_the_rule_named(content, rule):
    with pytest.raises(RoaError) as raised:
        parse_roa_content(content)
    assert rule in [f.rule for f in raised.value.findings]
    assert all(f.severity is Severity.ERROR for f in raised.value.findings)


def test_ipv6_prefixes_next_to_the_mapped_block_are_accepted():
    # RFC 9582 section 4.3.1 refuses IPv4 prefixes written as mapped addresses; ::fffe:0:0/95 is wider
    # than the mapped block and ::fffe:0:0/96 is outside it.
    for prefix in ("::fffe:0:0/95", "::fffe:0:0/96", "::/0"):
        assert parse_roa_content(b.roa_content(1, [(2, [(prefix, None)])])).addresses


def test_a_superfluous_max_length_is_a_warning_not_an_error():
    roa = parse_roa_content(b.roa_content(1, [(1, [("10.0.0.0/8", 8)])]))
    assert rules(roa) == ["roa.maxlength-superfluous"]
    assert roa.vrps()[0].max_length == 8


def test_the_same_prefix_with_two_max_lengths_is_a_warning_and_both_vrps_stay():
    roa = parse_roa_content(b.roa_content(1, [(1, [("10.0.0.0/8", 8), ("10.0.0.0/8", 16)])]))
    assert "roa.duplicate-prefix" in rules(roa)
    assert [v.max_length for v in roa.vrps()] == [8, 16]


@pytest.mark.parametrize(
    "entries",
    [
        [("11.0.0.0/8", None), ("10.0.0.0/8", None)],  # not ascending by address
        [("10.0.0.0/16", None), ("10.0.0.0/8", None)],  # not ascending by prefix length
        [("10.0.0.0/8", 16), ("10.0.0.0/8", 9)],  # not ascending by max length
        [("10.0.0.0/8", 16), ("10.0.0.0/8", 16)],  # exact duplicate
    ],
)
def test_section_4_3_3_canonical_order_is_checked(entries):
    roa = parse_roa_content(b.roa_content(1, [(1, entries)]))
    assert not roa.canonical
    assert "roa.not-canonical" in rules(roa)


def test_a_canonical_ordering_across_families_and_lengths_has_no_finding():
    roa = parse_roa_content(
        b.roa_content(
            1,
            [
                (1, [("10.0.0.0/8", None), ("10.0.0.0/16", 20), ("10.1.0.0/16", None)]),
                (2, [("2001:db8::/32", None)]),
            ],
        )
    )
    assert roa.canonical


def test_v6_family_listed_before_v4_is_not_canonical():
    roa = parse_roa_content(
        b.roa_content(1, [(2, [("2001:db8::/32", None)]), (1, [("10.0.0.0/8", None)])])
    )
    assert not roa.canonical
