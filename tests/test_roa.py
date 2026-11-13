"""The VRP payload type (RFC 6811 section 2 triple) that SLURM and a future ROA decoder share."""

from __future__ import annotations

import ipaddress

import pytest

from rpkit.roa import MAX_ASN, Vrp, vrp_sort_key


def test_vrp_holds_the_rfc_6811_triple() -> None:
    v = Vrp(ipaddress.ip_network("192.0.2.0/24"), 26, 64496)
    assert (str(v.prefix), v.max_length, v.asn) == ("192.0.2.0/24", 26, 64496)


@pytest.mark.parametrize(("length", "asn"), [(23, 1), (33, 1), (24, -1), (24, MAX_ASN + 1)])
def test_vrp_refuses_impossible_fields(length: int, asn: int) -> None:
    with pytest.raises(ValueError, match=r"max length|ASN"):
        Vrp(ipaddress.ip_network("192.0.2.0/24"), length, asn)


def test_vrp_refuses_wrong_types_and_accepts_as0() -> None:
    with pytest.raises(TypeError):
        Vrp("192.0.2.0/24", 24, 1)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Vrp(ipaddress.ip_network("192.0.2.0/24"), True, 1)
    with pytest.raises(TypeError):
        Vrp(ipaddress.ip_network("192.0.2.0/24"), 24, True)
    assert Vrp(ipaddress.ip_network("192.0.2.0/24"), 24, 0).asn == 0


def test_sort_key_orders_both_families_without_a_type_error() -> None:
    mixed = [
        Vrp(ipaddress.ip_network("2001:db8::/32"), 32, 1),
        Vrp(ipaddress.ip_network("203.0.113.0/24"), 24, 1),
        Vrp(ipaddress.ip_network("192.0.2.0/24"), 24, 2),
        Vrp(ipaddress.ip_network("192.0.2.0/24"), 24, 1),
    ]
    ordered = sorted(mixed, key=vrp_sort_key)
    assert [(str(v.prefix), v.asn) for v in ordered] == [
        ("192.0.2.0/24", 1),
        ("192.0.2.0/24", 2),
        ("203.0.113.0/24", 1),
        ("2001:db8::/32", 1),
    ]
