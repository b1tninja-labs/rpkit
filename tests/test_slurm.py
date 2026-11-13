"""RFC 8416: parse and apply SLURM files, with the RFC's own figures as vectors.

Vector sources (rfclib, read 2026-11-13): Figure 2 (the empty file), Figure 3 (the three
prefix-filter shapes), Figure 5 (prefix assertions) and Figure 7 (a full file). Figure 7 prints
``"<some base64 SKI>"`` placeholders that are not base64, so this suite fills them with real values
(a documentation SPKI from RFC 8630 section 2.4 for the router key); the strict parser refuses the
placeholders, and ``test_figure_7_placeholders_are_refused`` pins that. RFC 8416 has one erratum on
file, 7080 (held for document update, not verified): a ``comment`` on a BGPsec assertion, which
``test_bgpsec_assertion_comment_is_accepted`` pins as a design choice.
"""

from __future__ import annotations

import base64
import copy
import ipaddress
import json
import pathlib
from typing import Any

import pytest

from rpkit.roa import Vrp
from rpkit.slurm import (
    MAX_SLURM_BYTES,
    PrefixAssertion,
    PrefixFilter,
    RouterKey,
    Slurm,
    SlurmError,
    apply_slurm,
    apply_slurm_router_keys,
    parse_slurm,
)

TAL = (pathlib.Path(__file__).parent / "data" / "rfc8630-section-2.4.tal").read_text()
SPKI_B64 = "".join(TAL.split("\n\n", 1)[1].split())  # 294 bytes, so no '=' padding
SKI_FOO, SKI_BAR = "Zm9v", "YmFy"  # the RFC's own Figure 7 values for 'foo' and 'bar'


def net(text: str) -> Any:
    return ipaddress.ip_network(text)


def vrp(prefix: str, max_length: int | None, asn: int) -> Vrp:
    network = net(prefix)
    return Vrp(network, network.prefixlen if max_length is None else max_length, asn)


def doc(
    prefix_filters: list[Any] | None = None,
    bgpsec_filters: list[Any] | None = None,
    prefix_assertions: list[Any] | None = None,
    bgpsec_assertions: list[Any] | None = None,
) -> dict[str, Any]:
    return {
        "slurmVersion": 1,
        "validationOutputFilters": {
            "prefixFilters": prefix_filters or [],
            "bgpsecFilters": bgpsec_filters or [],
        },
        "locallyAddedAssertions": {
            "prefixAssertions": prefix_assertions or [],
            "bgpsecAssertions": bgpsec_assertions or [],
        },
    }


def dump(document: Any) -> bytes:
    return json.dumps(document).encode()


# Figure 7 with its placeholders replaced.
FIGURE_7 = doc(
    prefix_filters=[
        {"prefix": "192.0.2.0/24", "comment": "All VRPs encompassed by prefix"},
        {"asn": 64496, "comment": "All VRPs matching ASN"},
        {
            "prefix": "198.51.100.0/24",
            "asn": 64497,
            "comment": "All VRPs encompassed by prefix, matching ASN",
        },
    ],
    bgpsec_filters=[
        {"asn": 64496, "comment": "All keys for ASN"},
        {"SKI": SKI_FOO, "comment": "Key matching Router SKI"},
        {"asn": 64497, "SKI": SKI_BAR, "comment": "Key for ASN 64497 matching Router SKI"},
    ],
    prefix_assertions=[
        {"asn": 64496, "prefix": "198.51.100.0/24", "comment": "My other important route"},
        {
            "asn": 64496,
            "prefix": "2001:DB8::/32",
            "maxPrefixLength": 48,
            "comment": "My other important de-aggregated routes",
        },
    ],
    bgpsec_assertions=[
        {
            "asn": 64496,
            "comment": "My known key for my important ASN",
            "SKI": SKI_FOO,
            "routerPublicKey": SPKI_B64,
        }
    ],
)


# ---- parse -----------------------------------------------------------------------------------


def test_slurm_empty_file_is_identity() -> None:
    """Figure 2: no filters, no assertions; the output is the input (sorted, de-duplicated)."""
    empty = parse_slurm(dump(doc()))
    assert empty == Slurm()
    roas = [vrp("198.51.100.0/24", None, 64496), vrp("192.0.2.0/24", 26, 64497)]
    assert apply_slurm(roas, empty) == sorted(roas, key=lambda v: int(v.prefix.network_address))


def test_figure_7_parses_into_typed_members() -> None:
    parsed = parse_slurm(dump(FIGURE_7))
    assert [(f.prefix, f.asn) for f in parsed.prefix_filters] == [
        (net("192.0.2.0/24"), None),
        (None, 64496),
        (net("198.51.100.0/24"), 64497),
    ]
    assert [(f.asn, f.ski) for f in parsed.bgpsec_filters] == [
        (64496, None),
        (None, b"foo"),
        (64497, b"bar"),
    ]
    assert parsed.prefix_assertions[1] == PrefixAssertion(
        net("2001:db8::/32"), 64496, 48, "My other important de-aggregated routes"
    )
    (key,) = parsed.bgpsec_assertions
    assert (key.asn, key.ski, len(key.router_public_key)) == (64496, b"foo", 294)
    assert key.comment == "My known key for my important ASN"


def test_figure_7_placeholders_are_refused() -> None:
    broken = copy.deepcopy(FIGURE_7)
    broken["locallyAddedAssertions"]["bgpsecAssertions"][0]["SKI"] = "<some base64 SKI>"
    with pytest.raises(SlurmError, match="SKI"):
        parse_slurm(dump(broken))


def test_bgpsec_assertion_comment_is_accepted() -> None:
    """Design choice, see erratum 7080 in the module docstring."""
    parsed = parse_slurm(dump(FIGURE_7))
    assert parsed.bgpsec_assertions[0].comment is not None


def test_comments_are_optional_everywhere() -> None:
    parsed = parse_slurm(
        dump(
            doc(
                prefix_filters=[{"asn": 1}],
                bgpsec_filters=[{"asn": 1}],
                prefix_assertions=[{"prefix": "192.0.2.0/24", "asn": 1}],
                bgpsec_assertions=[{"asn": 1, "SKI": SKI_FOO, "routerPublicKey": SPKI_B64}],
            )
        )
    )
    assert parsed.prefix_filters[0].comment is None
    assert parsed.prefix_assertions[0].max_length is None


# ---- apply: prefix half ----------------------------------------------------------------------


def test_figure_3_filters_each_rule() -> None:
    config = parse_slurm(dump(FIGURE_7))
    kept = vrp("192.0.0.0/16", 24, 1)  # covers the filter prefix but is not covered by it
    roas = [
        vrp("192.0.2.0/24", None, 1),  # filter 1: equal to the filter prefix
        vrp("192.0.2.128/25", None, 2),  # filter 1: covered by it
        kept,
        vrp("203.0.113.0/24", None, 64496),  # filter 2: ASN only, prefix irrelevant
        vrp("198.51.100.0/24", None, 64497),  # filter 3: both match
        vrp("198.51.100.0/24", None, 64498),  # filter 3: prefix matches, ASN does not
        vrp("203.0.113.0/24", None, 64497),  # filter 3: ASN matches, prefix does not
        vrp("2001:db8::/32", 40, 1),  # no filter touches IPv6 here
    ]
    result = apply_slurm(roas, config)
    assert kept in result
    assert vrp("198.51.100.0/24", None, 64498) in result
    assert vrp("203.0.113.0/24", None, 64497) in result
    assert vrp("2001:db8::/32", 40, 1) in result
    for removed in (roas[0], roas[1], roas[3]):
        assert removed not in result
    # The only VRP filter 3 removes is the one matching both parts; the assertion re-adds the
    # same 198.51.100.0/24 for AS 64496, so a 64497 VRP stays gone.
    assert vrp("198.51.100.0/24", None, 64497) not in result


def test_prefix_filter_does_not_cross_address_families() -> None:
    covered = PrefixFilter(net("::/0"), None)
    assert not covered.matches(vrp("10.0.0.0/8", None, 1))
    assert PrefixFilter(net("0.0.0.0/0"), None).matches(vrp("10.0.0.0/8", None, 1))
    assert PrefixFilter(net("::/0"), None).matches(vrp("2001:db8::/32", None, 1))


def test_slurm_assertion_survives_matching_filter() -> None:
    """RFC 8416 3.2: locally added assertions MUST NOT be removed by output filtering."""
    config = parse_slurm(
        dump(
            doc(
                prefix_filters=[{"asn": 64496}],
                prefix_assertions=[{"prefix": "198.51.100.0/24", "asn": 64496}],
            )
        )
    )
    result = apply_slurm([vrp("203.0.113.0/24", None, 64496)], config)
    assert result == [vrp("198.51.100.0/24", None, 64496)]


def test_slurm_dedupes_assertion_equal_to_existing_vrp() -> None:
    config = parse_slurm(
        dump(
            doc(
                prefix_assertions=[
                    {"prefix": "192.0.2.0/24", "asn": 1},
                    {"prefix": "192.0.2.0/24", "asn": 1, "maxPrefixLength": 24, "comment": "twice"},
                ]
            )
        )
    )
    existing = vrp("192.0.2.0/24", None, 1)
    assert apply_slurm([existing, existing], config) == [existing]


def test_assertion_without_max_length_uses_the_prefix_length() -> None:
    """Design decision (module docstring): absent maxPrefixLength is the prefix length."""
    config = parse_slurm(dump(doc(prefix_assertions=[{"prefix": "2001:db8::/32", "asn": 7}])))
    assert apply_slurm([], config) == [vrp("2001:db8::/32", 32, 7)]


def test_apply_reads_a_generator_once_and_orders_both_families() -> None:
    config = parse_slurm(dump(doc(prefix_assertions=[{"prefix": "2001:db8::/32", "asn": 7}])))
    source = (v for v in [vrp("203.0.113.0/24", None, 2), vrp("192.0.2.0/24", None, 1)])
    result = apply_slurm(source, config)
    assert [str(v.prefix) for v in result] == ["192.0.2.0/24", "203.0.113.0/24", "2001:db8::/32"]


# ---- apply: BGPsec half ----------------------------------------------------------------------


def test_router_key_filters_and_assertions() -> None:
    config = parse_slurm(dump(FIGURE_7))
    spki = base64.b64decode(SPKI_B64)
    keys = [
        RouterKey(64496, b"zzz", spki),  # removed: ASN filter
        RouterKey(1, b"foo", spki),  # removed: SKI-only filter
        RouterKey(64497, b"bar", spki),  # removed: both match
        RouterKey(64497, b"baz", spki),  # kept: ASN matches the third filter, SKI does not
        RouterKey(2, b"bar", spki),  # kept: SKI matches the third filter, ASN does not
    ]
    result = apply_slurm_router_keys(keys, config)
    assert result == [
        RouterKey(2, b"bar", spki),
        RouterKey(64496, b"foo", spki),  # the assertion, which no filter may remove
        RouterKey(64497, b"baz", spki),
    ]


# ---- hostile input ---------------------------------------------------------------------------


def mutated(path: list[str], value: Any) -> bytes:
    document = copy.deepcopy(FIGURE_7)
    node = document
    for step in path[:-1]:
        node = node[int(step)] if isinstance(node, list) else node[step]
    last: Any = int(path[-1]) if isinstance(node, list) else path[-1]
    if value is KeyError:
        del node[last]
    else:
        node[last] = value
    return dump(document)


PF = ["validationOutputFilters", "prefixFilters", "0"]
PA = ["locallyAddedAssertions", "prefixAssertions", "0"]
BA = ["locallyAddedAssertions", "bgpsecAssertions", "0"]


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        (mutated(["slurmVersion"], 2), "slurmVersion"),
        (mutated(["slurmVersion"], "1"), "slurmVersion"),
        (mutated(["slurmVersion"], 1.0), "slurmVersion"),
        (mutated(["slurmVersion"], True), "slurmVersion"),
        (mutated(["slurmVersion"], KeyError), "missing"),
        (mutated(["validationOutputFilters"], KeyError), "missing"),
        (mutated(["locallyAddedAssertions", "bgpsecAssertions"], KeyError), "missing"),
        (mutated(["validationOutputFilters", "prefixFilters"], KeyError), "missing"),
        (mutated(["unknownMember"], 1), "undefined"),
        (mutated(["validationOutputFilters", "extra"], []), "undefined"),
        (mutated(["locallyAddedAssertions", "extra"], []), "undefined"),
        (mutated(["validationOutputFilters", "prefixFilters"], {}), "array"),
        (mutated([*PF[:-1], "0"], {"comment": "neither"}), "needs a prefix"),
        (mutated(PF, {"prefix": "192.0.2.0/24", "extra": 1}), "undefined"),
        (mutated(PF, {"asn": -1}), "asn"),
        (mutated(PF, {"asn": 2**32}), "asn"),
        (mutated(PF, {"asn": True}), "asn"),
        (mutated(PF, {"asn": "64496"}), "asn"),
        (mutated(PF, {"asn": 1.5}), "asn"),
        (mutated(PF, {"prefix": "192.0.2.1/24"}), "host bits"),
        (mutated(PF, {"prefix": "192.0.2.0"}), "address/length"),
        (mutated(PF, {"prefix": "192.0.2.0/255.255.255.0"}), "address/length"),
        (mutated(PF, {"prefix": "2001:db8::/129"}), "valid prefix"),
        (mutated(PF, {"prefix": "192.0.2.0/33"}), "valid prefix"),
        (mutated(PF, {"prefix": "fe80::1%eth0/64"}), "address/length"),
        (mutated(PF, {"prefix": 5}), "address/length"),
        (mutated(PF, {"asn": 1, "comment": 5}), "comment"),
        (mutated(PA, {"prefix": "192.0.2.0/24"}), "missing"),
        (mutated(PA, {"asn": 1}), "missing"),
        (
            mutated(PA, {"prefix": "192.0.2.0/24", "asn": 1, "maxPrefixLength": 23}),
            "maxPrefixLength",
        ),
        (
            mutated(PA, {"prefix": "192.0.2.0/24", "asn": 1, "maxPrefixLength": 33}),
            "maxPrefixLength",
        ),
        (
            mutated(PA, {"prefix": "192.0.2.0/24", "asn": 1, "maxPrefixLength": "26"}),
            "maxPrefixLength",
        ),
        (
            mutated(PA, {"prefix": "192.0.2.0/24", "asn": 1, "maxPrefixLength": True}),
            "maxPrefixLength",
        ),
        (
            mutated(["validationOutputFilters", "bgpsecFilters", "0"], {"comment": "x"}),
            "needs an asn",
        ),
        (mutated(["validationOutputFilters", "bgpsecFilters", "0"], {"SKI": "Zm9v="}), "SKI"),
        (mutated(["validationOutputFilters", "bgpsecFilters", "0"], {"SKI": "Zm9"}), "SKI"),
        (mutated(["validationOutputFilters", "bgpsecFilters", "0"], {"SKI": ""}), "SKI"),
        (mutated(BA, {"asn": 1, "SKI": SKI_FOO}), "missing"),
        (mutated(BA, {"asn": 1, "routerPublicKey": SPKI_B64}), "missing"),
        (mutated([*BA, "routerPublicKey"], "Zm9v"), "DER"),
        (mutated([*BA, "routerPublicKey"], SPKI_B64[:-4]), "DER"),
        (mutated([*BA, "asn"], 2**33), "asn"),
    ],
)
def test_slurm_rejects_each_deviation(raw: bytes, why: str) -> None:
    with pytest.raises(SlurmError, match=why):
        parse_slurm(raw)


def test_slurm_filter_with_neither_prefix_nor_asn_is_refused() -> None:
    raw = dump(doc(prefix_filters=[{"comment": "matches nothing, so it is a typo"}]))
    with pytest.raises(SlurmError, match="needs a prefix"):
        parse_slurm(raw)


def test_slurm_rejects_duplicate_json_keys() -> None:
    raw = b'{"slurmVersion": 1, "slurmVersion": 1}'
    with pytest.raises(SlurmError, match="duplicate"):
        parse_slurm(raw)
    nested = dump(doc()).replace(
        b'"prefixFilters": []', b'"prefixFilters": [], "prefixFilters": []'
    )
    with pytest.raises(SlurmError, match="duplicate"):
        parse_slurm(nested)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"[]",
        b"null",
        b'"1"',
        b"{",
        b'{"slurmVersion": NaN}',
        b'{"slurmVersion": Infinity}',
        b"\xef\xbb\xbf" + dump(doc()),
        b"\xff" + dump(doc()),
    ],
)
def test_slurm_rejects_non_json_and_hostile_shapes(raw: bytes) -> None:
    with pytest.raises(SlurmError):
        parse_slurm(raw)


def test_slurm_rejects_huge_nesting() -> None:
    """Hostile depth is a SlurmError, never a RecursionError reaching the caller."""
    for raw in (b"[" * 200_000, b'{"a":' * 200_000):
        with pytest.raises(SlurmError):
            parse_slurm(raw)


def test_slurm_size_cap() -> None:
    padded = dump(doc(prefix_filters=[{"asn": 1, "comment": "x" * MAX_SLURM_BYTES}]))
    assert len(padded) > MAX_SLURM_BYTES
    with pytest.raises(SlurmError, match="byte cap"):
        parse_slurm(padded)


def test_failed_parse_never_returns_a_partial_file() -> None:
    document = copy.deepcopy(FIGURE_7)
    document["locallyAddedAssertions"]["prefixAssertions"].append({"prefix": "bad", "asn": 1})
    with pytest.raises(SlurmError):
        parse_slurm(dump(document))
