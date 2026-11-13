"""The RPKI signed object (RFC 6488 as amended by RFC 9589) on signeddata's ``cms.load``.

RFC 6488 prints no byte vector, so each object is built in ``rpkibuild.py`` and signed with a throwaway
RSA-2048 key; every test below changes one element to break exactly one rule of RFC 6488 section 2
or 3, RFC 9589 section 4 or RFC 7935 sections 2 and 3.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from rpkit.signedobject import (
    SignedObjectError,
    check_signed_attrs,
    decode_signed_object,
    verify_rsa_sha256,
)

from . import rpkibuild as b

IP = b.ip_blocks({(1, None): [b.prefix_range("10.0.0.0/8")]})
ROA = b.roa_content(64500, [(1, [("10.0.0.0/24", 24)])])
EE = b.make_cert(b.CertSpec(ip=IP))


def build(**kw) -> bytes:
    args: dict[str, Any] = {"ee_cert": EE, "content_type": b.ID_CT_ROA, "econtent": ROA}
    args.update(kw)
    return b.make_signed_object(**args)


def rules(blob: bytes) -> list[str]:
    with pytest.raises(SignedObjectError) as raised:
        decode_signed_object(blob)
    return [f.rule for f in raised.value.findings]


def test_a_conforming_object_decodes_and_verifies():
    obj = decode_signed_object(build())
    assert obj.content_type == b.ID_CT_ROA
    assert obj.econtent == ROA
    assert obj.signing_time == b.NOW
    assert (
        obj.ee_certificate.subject.rfc4514
        if hasattr(obj.ee_certificate.subject, "rfc4514")
        else True
    )
    assert verify_rsa_sha256(obj) == ()


def test_sha256_with_rsa_is_accepted_as_the_signature_algorithm_as_rfc_7935_requires():
    obj = decode_signed_object(build(signature_oid=b.ID_SHA256_WITH_RSA))
    assert verify_rsa_sha256(obj) == ()


def test_the_manifest_content_type_works_like_the_roa_one():
    obj = decode_signed_object(build(content_type=b.ID_CT_MANIFEST, econtent=b"payload"))
    assert obj.content_type == b.ID_CT_MANIFEST


@pytest.mark.parametrize(
    ("kw", "rule"),
    [
        ({"version": 2}, "signed-object.version"),
        ({"signer_version": 2}, "signed-object.signer-version"),
        (
            {"digest_oids": (b.ID_SHA256, "2.16.840.1.101.3.4.2.3")},
            "signed-object.digest-algorithms",
        ),
        ({"digest_oids": ("1.3.14.3.2.26",)}, "signed-object.digest-algorithms"),
        ({"signer_digest_oid": "1.3.14.3.2.26"}, "signed-object.signer-digest"),
        ({"signature_oid": "1.2.840.10045.4.3.2"}, "signed-object.signature-algorithm"),
        ({"crls": (b.make_crl(),)}, "signed-object.crls"),
        ({"certs": ()}, "signed-object.certificates"),
        ({"certs": (EE, EE)}, "signed-object.certificates"),
        ({"signers": 2}, "signed-object.signers"),
        (
            {"unsigned_attrs": (b.attribute(b.ID_SIGNING_TIME, b.utc_time(b.NOW)),)},
            "signed-object.unsigned-attrs",
        ),
        ({"sid_ski": b"\x00" * 20}, "signed-object.ee-ski"),
        ({"signing_time": None}, "signed-attrs.missing"),
        ({"binary_signing_time": True}, "signed-attrs.forbidden"),
        ({"drop_content_type_attr": True}, "signed-attrs.missing"),
        ({"content_type_attr_value": b.ID_CT_MANIFEST}, "signed-attrs.content-type"),
        (
            {"extra_attrs": (b.attribute("1.2.840.113549.1.9.15", b.null()),)},
            "signed-attrs.forbidden",
        ),
        (
            {"extra_attrs": (b.attribute(b.ID_CONTENT_TYPE, b.oid(b.ID_CT_ROA)),)},
            "signed-attrs.repeated",
        ),
        (
            {
                "extra_attrs": (
                    b.seq(b.oid(b.ID_SIGNING_TIME), b.set_of(b.utc_time(b.NOW), b.utc_time(b.NOW))),
                )
            },
            "signed-attrs.repeated",
        ),
    ],
)
def test_each_rfc_6488_and_9589_rule_is_enforced(kw, rule):
    assert rule in rules(build(**kw))


def test_binary_signing_time_was_allowed_by_rfc_6488_and_is_refused_after_rfc_9589():
    blob = build(binary_signing_time=True)
    with pytest.raises(SignedObjectError):
        decode_signed_object(blob)
    from signeddata import cms

    signer = cms.load(blob, der=True).signer_infos[0]
    assert check_signed_attrs(signer, b.ID_CT_ROA, signing_time_required=False) == ()
    assert [f.rule for f in check_signed_attrs(signer, b.ID_CT_ROA)] == ["signed-attrs.forbidden"]


def test_signing_time_was_optional_in_rfc_6488_and_is_required_by_rfc_9589():
    from signeddata import cms

    signer = cms.load(build(signing_time=None), der=True).signer_infos[0]
    assert check_signed_attrs(signer, b.ID_CT_ROA, signing_time_required=False) == ()
    assert [f.rule for f in check_signed_attrs(signer, b.ID_CT_ROA)] == ["signed-attrs.missing"]


def test_non_der_cms_is_refused():
    blob = build()
    ber = bytes([0x30, 0x80]) + blob[2 + (blob[1] & 0x7F if blob[1] & 0x80 else 0) :] + b"\x00\x00"
    assert rules(ber) == ["signed-object.cms"]
    assert rules(b"\x30\x03\x02\x01\x01") == ["signed-object.cms"]
    assert rules(b"") == ["signed-object.cms"]


def test_a_tampered_signature_and_a_wrong_digest_are_reported_by_verify():
    bad_sig = decode_signed_object(build(tamper_signature=True))
    assert [f.rule for f in verify_rsa_sha256(bad_sig)] == ["signature.invalid"]
    bad_digest = decode_signed_object(build(message_digest=b"\x00" * 32))
    assert "signature.digest" in [f.rule for f in verify_rsa_sha256(bad_digest)]


def test_a_signature_by_another_key_does_not_verify_under_the_ee_key():
    ee_ski = b.ski_of(b.key("ee"))
    obj = decode_signed_object(build(signer="ta", sid_ski=ee_ski))
    assert [f.rule for f in verify_rsa_sha256(obj)] == ["signature.invalid"]


def test_an_rsa_1024_ee_key_is_refused_by_rfc_7935_section_3():
    b._KEYS["weak"] = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
    ee = b.make_cert(b.CertSpec(ip=IP, subject_key="weak"))
    obj = decode_signed_object(
        b.make_signed_object(signer="weak", ee_cert=ee, content_type=b.ID_CT_ROA, econtent=ROA)
    )
    assert "signature.key" in [f.rule for f in verify_rsa_sha256(obj)]


def test_changing_econtent_after_signing_breaks_the_digest_not_the_syntax():
    good = build()
    forged = good.replace(ROA, ROA[:-1] + bytes([ROA[-1] ^ 1]))
    assert forged != good
    obj = decode_signed_object(forged)
    assert "signature.digest" in [f.rule for f in verify_rsa_sha256(obj)]
