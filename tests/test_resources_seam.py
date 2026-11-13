"""The seam to asn1core's RFC 3779 decoder: rpkit consumes it, asn1core owns and tests it.

The decoder lives in ``asn1core/resources.py`` with the full vector set (RFC 3779 Appendix B and C,
errata 2537 and 6792, every canonical-form refusal). This file pins only that rpkit can reach it
through the sibling-path dependency and that the RFC's Appendix C bytes decode to the documented
numbers, so a change to the seam fails here, in the project that depends on it.
"""

from __future__ import annotations

from asn1core.resources import ASResourceSet, parse_as_resources, parse_ip_resources

# RFC 3779 Appendix C, extnValue content: AS 135, 3000-3999, 5001; rdi inherit.
APPENDIX_C = bytes.fromhex("301aa014301202020087300802020bb802020f9f02021389a1020500")
# Appendix B, second example (erratum 6792 applied): 10/8 and 172.16/12; IPv4 multicast inherit; IPv6.
APPENDIX_B2 = bytes.fromhex(
    "302c3010040300010130090302000a030304ac10300704030001020500300f040200023009030700200100000002"
)


def test_asn1core_decodes_rfc3779_appendix_c() -> None:
    res = parse_as_resources(APPENDIX_C)
    assert res.asnum == ASResourceSet(False, ((135, 135), (3000, 3999), (5001, 5001)))
    assert res.rdi == ASResourceSet(True, ())


def test_asn1core_decodes_rfc3779_appendix_b_with_erratum_6792() -> None:
    res = parse_ip_resources(APPENDIX_B2)
    assert [(f.afi, f.safi, f.inherit) for f in res.families] == [
        (1, 1, False),
        (1, 2, True),
        (2, None, False),
    ]
    assert res.families[0].ranges[1] == (172 << 24 | 16 << 16, 172 << 24 | 31 << 16 | 0xFFFF)
