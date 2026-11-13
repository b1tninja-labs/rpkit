"""CRL profile (RFC 6487 section 5, RFC 9829 section 3.1) and ROA validation end to end (RFC 6487 section 7, RFC 9582 section 5).

The PKI is built in ``rpkibuild.py``: a trust anchor TA (10.0.0.0/8), a CA below it (10.1.0.0/16) and
an EE certificate (10.1.2.0/24) whose key signs the ROA. No RFC prints bytes for any of these.
"""

from __future__ import annotations

import datetime

import pytest
from asn1core import parse_certificate

from rpkit.resources import Procedure
from rpkit.validation import check_crl, validate_roa

from . import rpkibuild as b

NOW = b.NOW


def v4(*prefixes: str) -> bytes:
    return b.ip_blocks({(1, None): [b.prefix_range(p) for p in prefixes]})


def pki(
    *,
    ta_ip="10.0.0.0/8",
    ca_ip="10.1.0.0/16",
    ee_ip="10.1.2.0/24",
    v2=False,
    ee_serial=300,
    **ee_kw,
):
    flags = {"v2_extensions": True, "policies": (b.CP_V2,)} if v2 else {}
    ta = b.make_cert(
        b.CertSpec(
            subject="TA",
            issuer="TA",
            subject_key="ta",
            issuer_key="ta",
            serial=1,
            ca=True,
            self_signed=True,
            ip=v4(ta_ip),
            **flags,
        )
    )
    ca = b.make_cert(
        b.CertSpec(
            subject="CA1",
            issuer="TA",
            subject_key="ca1",
            issuer_key="ta",
            serial=2,
            ca=True,
            ip=v4(ca_ip),
            **flags,
        )
    )
    spec = {
        "subject": "EE",
        "issuer": "CA1",
        "subject_key": "ee",
        "issuer_key": "ca1",
        "serial": ee_serial,
        "ip": v4(ee_ip),
        **flags,
    }
    spec.update(ee_kw)
    ee = b.make_cert(b.CertSpec(**spec))
    return ta, ca, ee


def roa(ee: bytes, prefix="10.1.2.0/24", max_length=24, **kw) -> bytes:
    content = b.roa_content(64500, [(1, [(prefix, max_length)])])
    return b.make_signed_object(
        ee_cert=ee, content_type=kw.pop("content_type", b.ID_CT_ROA), econtent=content, **kw
    )


def crls(*, ta_revoked=(), ca_revoked=()):
    return [
        b.make_crl(issuer="TA", issuer_key="ta", revoked=ta_revoked),
        b.make_crl(issuer="CA1", issuer_key="ca1", revoked=ca_revoked),
    ]


def rules(result) -> list[str]:
    return [f.rule for f in result.findings if f.severity.value == "error"]


# -- CRL ---------------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ta_cert():
    return parse_certificate(pki()[0])


def test_a_conforming_crl_is_valid_and_lists_its_revoked_serials(ta_cert):
    result = check_crl(b.make_crl(revoked=(7, 9), number=5), ta_cert, NOW)
    assert result.valid
    assert result.revoked_serials == {7, 9}
    assert result.number == 5
    assert result.findings == ()


def test_the_largest_crl_number_is_accepted_and_the_next_is_not(ta_cert):
    assert check_crl(b.make_crl(number=2**159 - 1), ta_cert, NOW).valid
    assert "crl.number" in [
        f.rule for f in check_crl(b.make_crl(number=2**159), ta_cert, NOW).findings
    ]


@pytest.mark.parametrize(
    ("kw", "rule"),
    [
        ({"crl_number_critical": True}, "crl.number"),
        ({"extra_extension": True}, "crl.extension"),
        ({"omit_aki": True}, "crl.extension"),
        ({"issuer": "OTHER"}, "crl.issuer"),
        ({"issuer_key": "ca1"}, "crl.signature"),
        ({"next_update": NOW - datetime.timedelta(hours=1)}, "crl.stale"),
        (
            {
                "this_update": NOW + datetime.timedelta(hours=1),
                "next_update": NOW + datetime.timedelta(hours=2),
            },
            "crl.not-yet-valid",
        ),
    ],
)
def test_each_crl_rule_is_enforced(ta_cert, kw, rule):
    result = check_crl(b.make_crl(**kw), ta_cert, NOW)
    assert not result.valid
    assert rule in [f.rule for f in result.findings]


def test_a_crl_signed_by_the_issuer_but_naming_another_key_in_its_aki_is_refused(ta_cert):
    other = parse_certificate(pki()[1])  # the CA's certificate: its SKI is not the TA's
    result = check_crl(b.make_crl(), other, NOW)
    assert "crl.aki" in [f.rule for f in result.findings]


def test_a_crl_that_is_not_a_crl_gives_no_crl_and_one_error(ta_cert):
    result = check_crl(b"\x30\x03\x02\x01\x01", ta_cert, NOW)
    assert result.crl is None
    assert [f.rule for f in result.findings] == ["crl.parse"]
    with pytest.raises(ValueError, match="timezone"):
        check_crl(b.make_crl(), ta_cert, datetime.datetime(2026, 1, 1))


# -- ROA -----------------------------------------------------------------------------------------------------


def test_a_conforming_roa_validates_and_yields_its_vrp():
    ta, ca, ee = pki()
    result = validate_roa(roa(ee), [ta, ca], crls(), NOW)
    assert result.valid, result.findings
    assert result.procedure is Procedure.RFC6487
    assert [(str(v.prefix), v.max_length, v.asn) for v in result.vrps] == [
        ("10.1.2.0/24", 24, 64500)
    ]


@pytest.mark.parametrize(
    ("scenario", "rule"),
    [
        ("revoked-ee", "path.revoked"),
        ("revoked-ca", "path.revoked"),
        ("expired", "path.validity"),
        ("outside", "roa.outside-resources"),
        ("overclaim", "path.overclaim"),
        ("ee-inherit", "roa.ee-ip"),
        ("ee-as", "roa.ee-as"),
        ("bad-signature", "signature.invalid"),
        ("wrong-issuer-key", "path.signature"),
        ("not-a-roa", "roa.content-type"),
    ],
)
def test_each_failure_makes_the_roa_invalid_and_yields_no_vrps(scenario, rule):
    ta, ca, ee = pki()
    blob, chain, lists, at = None, [ta, ca], crls(), NOW
    if scenario == "revoked-ee":
        lists = crls(ca_revoked=(300,))
    elif scenario == "revoked-ca":
        lists = crls(ta_revoked=(2,))
    elif scenario == "expired":
        at = NOW + datetime.timedelta(days=90)
        lists = [
            b.make_crl(
                issuer="TA",
                issuer_key="ta",
                this_update=at,
                next_update=at + datetime.timedelta(days=1),
            ),
            b.make_crl(
                issuer="CA1",
                issuer_key="ca1",
                this_update=at,
                next_update=at + datetime.timedelta(days=1),
            ),
        ]
    elif scenario == "overclaim":
        ta, ca, ee = pki(ca_ip="11.0.0.0/8", ee_ip="11.1.0.0/16")
        chain = [ta, ca]
        blob = roa(ee, "11.1.0.0/16", 16)
    elif scenario == "ee-inherit":
        ee = pki(ee_ip="10.1.2.0/24")[2]
        ee = b.make_cert(
            b.CertSpec(
                subject="EE",
                issuer="CA1",
                subject_key="ee",
                issuer_key="ca1",
                serial=300,
                ip=b.ip_blocks({(1, None): None}),
            )
        )
    elif scenario == "ee-as":
        ee = pki(asn=b.as_ids(asnum=[(1, 2)]))[2]
    result_blob = (
        blob
        if blob is not None
        else roa(
            ee,
            "10.9.0.0/16" if scenario == "outside" else "10.1.2.0/24",
            16 if scenario == "outside" else 24,
            **({"tamper_signature": True} if scenario == "bad-signature" else {}),
            **({"content_type": b.ID_CT_MANIFEST} if scenario == "not-a-roa" else {}),
        )
    )
    if scenario == "wrong-issuer-key":
        ca = b.make_cert(
            b.CertSpec(
                subject="CA1",
                issuer="TA",
                subject_key="ca1",
                issuer_key="ca1",
                serial=2,
                ca=True,
                ip=v4("10.1.0.0/16"),
            )
        )
        chain = [ta, ca]
    result = validate_roa(result_blob, chain, lists, at)
    assert not result.valid
    assert result.vrps == ()
    assert rule in rules(result), rules(result)


def test_a_missing_crl_for_a_ca_in_the_path_is_an_error():
    ta, ca, ee = pki()
    result = validate_roa(roa(ee), [ta, ca], [crls()[0]], NOW)
    assert not result.valid
    assert "path.crl-missing" in rules(result)
    assert not validate_roa(roa(ee), [ta, ca], [], NOW).valid


def test_an_empty_chain_and_a_non_der_blob_are_reported_not_raised():
    ta, ca, ee = pki()
    assert "path.empty" in rules(validate_roa(roa(ee), [], crls(), NOW))
    assert not validate_roa(b"\x00", [ta, ca], crls(), NOW).valid
    with pytest.raises(ValueError, match="timezone"):
        validate_roa(roa(ee), [ta, ca], crls(), datetime.datetime(2026, 1, 1))


def test_rfc_8360_accepts_the_roa_when_the_overclaim_does_not_touch_its_prefix():
    # The CA claims 10.1/16 and 192.0.2/24 but the TA holds only 10/8; the EE asks for 10.1.2/24 only.
    ta, ca, ee = pki(v2=True, ca_ip="10.1.0.0/16")
    ca = b.make_cert(
        b.CertSpec(
            subject="CA1",
            issuer="TA",
            subject_key="ca1",
            issuer_key="ta",
            serial=2,
            ca=True,
            ip=v4("10.1.0.0/16", "192.0.2.0/24"),
            v2_extensions=True,
            policies=(b.CP_V2,),
        )
    )
    blob = roa(ee)
    default = validate_roa(blob, [ta, ca], crls(), NOW)
    assert (
        not default.valid
    )  # RFC 6487 section 7: the overclaiming CA, and the v2 policy, are refused
    reconsidered = validate_roa(blob, [ta, ca], crls(), NOW, procedure=Procedure.RFC8360)
    assert reconsidered.valid, reconsidered.findings
    assert reconsidered.procedure is Procedure.RFC8360
    assert "path.overclaim-accepted" in [f.rule for f in reconsidered.findings]
    assert len(reconsidered.vrps) == 1


def test_rfc_8360_still_refuses_a_roa_prefix_inside_the_overclaim():
    ta, ca, ee = pki(v2=True, ee_ip="192.0.2.0/24")
    ca = b.make_cert(
        b.CertSpec(
            subject="CA1",
            issuer="TA",
            subject_key="ca1",
            issuer_key="ta",
            serial=2,
            ca=True,
            ip=v4("10.1.0.0/16", "192.0.2.0/24"),
            v2_extensions=True,
            policies=(b.CP_V2,),
        )
    )
    result = validate_roa(
        roa(ee, "192.0.2.0/24", 24), [ta, ca], crls(), NOW, procedure=Procedure.RFC8360
    )
    assert not result.valid
    assert "roa.outside-resources" in rules(result)
