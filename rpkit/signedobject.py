"""The RPKI signed object: the RFC 6488 profile of CMS SignedData, as amended by RFC 9589.

``decode_signed_object`` reads a blob with signeddata's ``cms.load`` (strict DER, because RFC 6488
section 2 requires it) and applies the syntax checks of RFC 6488 section 3 item 1, read through
rfclib on 2026-11-13, with the two items RFC 9589 section 4 replaces (the signing-time attribute is
now required and binary-signing-time is forbidden): version 3 twice, one digest algorithm that is
SHA-256 (RFC 7935 section 2, with the parameters rule of RFC 5754 section 2), exactly one EE
certificate whose SubjectKeyIdentifier is the SignerInfo sid, no crls, one SignerInfo, signedAttrs
that are exactly content-type, message-digest and signing-time (each once, one value), a content-type
attribute equal to eContentType, no unsignedAttrs, and a signatureAlgorithm of rsaEncryption or
sha256WithRSAEncryption (RFC 7935 section 2: both must be accepted on verifying). The result of a
failed profile is :class:`SignedObjectError` carrying every finding.

``verify_rsa_sha256`` is item 2 of section 3: the message-digest equals the SHA-256 of eContent, and
the signature over the signedAttrs (re-tagged from [0] to SET OF, RFC 5652 section 5.4) verifies
under the EE certificate key, an RSA 2048-bit key with exponent 65537 (RFC 7935 section 3). The RSA
arithmetic is ``rpkit._rsa`` and so ``sigwire[verify]``. Item 3, the EE certificate's path to a trust
anchor, is :mod:`rpkit.validation`. EE certificate validity is not checked here.
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass

import asn1core
from asn1core import Asn1Error, check_generalized_time, check_oid, check_utc_time
from asn1core.extensions import parse_subject_key_identifier
from asn1core.keys import RsaPublicKey, parse_spki
from signeddata import cms
from sigwire.verify import VerifyError

from ._rsa import verify_rsa_sha256 as _verify
from .findings import Finding, Severity

__all__ = [
    "ID_CONTENT_TYPE",
    "ID_MESSAGE_DIGEST",
    "ID_SIGNING_TIME",
    "SignedObject",
    "SignedObjectError",
    "check_signed_attrs",
    "decode_signed_object",
    "verify_rsa_sha256",
]

ID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
ID_SIGNING_TIME = "1.2.840.113549.1.9.5"
ID_BINARY_SIGNING_TIME = "1.2.840.113549.1.9.16.2.46"
ID_SHA256 = "2.16.840.1.101.3.4.2.1"
ID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
ID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
_SKI = "2.5.29.14"


class SignedObjectError(ValueError):
    """A blob that is not a valid RPKI signed object; ``findings`` lists every error found."""

    def __init__(self, findings: tuple[Finding, ...]) -> None:
        super().__init__("; ".join(str(f) for f in findings))
        self.findings = findings


@dataclass(frozen=True, slots=True)
class SignedObject:
    """A signed object that passed the RFC 6488 syntax checks (signature not yet verified).

    ``econtent`` is the payload, ``content_type`` its OID, ``ee_certificate`` the one EE
    certificate and ``signing_time`` the RFC 9589 attribute. ``signed_attrs_raw`` and
    ``signature`` are what :func:`verify_rsa_sha256` checks; ``message_digest`` is the attribute
    value.
    """

    content_type: str
    econtent: bytes
    ee_certificate: asn1core.Certificate
    signing_time: datetime.datetime
    message_digest: bytes
    signed_attrs_raw: bytes
    signature: bytes
    cms: cms.SignedData


def _err(rule: str, message: str, spec: str) -> Finding:
    return Finding(Severity.ERROR, rule, message, spec)


def _single_value(attr: cms.Attribute) -> bytes | None:
    return attr.values[0] if len(attr.values) == 1 else None


def check_signed_attrs(
    signer: cms.SignerInfo, content_type: str, *, signing_time_required: bool = True
) -> tuple[Finding, ...]:
    """The signedAttrs rules of RFC 6488 section 2.1.6.4 as RFC 9589 section 4 amends them.

    The attributes must be present, and be content-type, message-digest and signing-time only
    (with ``signing_time_required`` false the RFC 6488 original, where signing-time is optional
    and binary-signing-time allowed, is read instead). Each appears once with a single value, and
    the content-type value equals ``content_type``, the eContentType. Returns the errors found.
    """
    spec = "RFC 6488 section 2.1.6.4, RFC 9589 section 4"
    if signer.signed_attrs is None:
        return (_err("signed-attrs.absent", "signedAttrs is absent", spec),)
    allowed = {ID_CONTENT_TYPE, ID_MESSAGE_DIGEST, ID_SIGNING_TIME}
    if not signing_time_required:
        allowed.add(ID_BINARY_SIGNING_TIME)
    required = {ID_CONTENT_TYPE, ID_MESSAGE_DIGEST} | (
        {ID_SIGNING_TIME} if signing_time_required else set()
    )
    found: list[Finding] = []
    seen: dict[str, cms.Attribute] = {}
    for attr in signer.signed_attrs:
        if attr.oid not in allowed:
            found.append(
                _err("signed-attrs.forbidden", f"attribute {attr.oid} must not be present", spec)
            )
        elif attr.oid in seen:
            found.append(
                _err("signed-attrs.repeated", f"attribute {attr.oid} appears more than once", spec)
            )
        else:
            seen[attr.oid] = attr
        if len(attr.values) != 1:
            found.append(
                _err(
                    "signed-attrs.values",
                    f"attribute {attr.oid} has {len(attr.values)} values, one is required",
                    spec,
                )
            )
    for oid_ in sorted(required - seen.keys()):
        found.append(_err("signed-attrs.missing", f"attribute {oid_} is required", spec))
    ct = seen.get(ID_CONTENT_TYPE)
    value = None if ct is None else _single_value(ct)
    if value is not None:
        try:
            node, _ = asn1core.decode(value, der=True)
            attr_type = ".".join(map(str, check_oid(node.payload or b"")))
        except Asn1Error as error:
            found.append(_err("signed-attrs.content-type", f"content-type value: {error}", spec))
        else:
            if attr_type != content_type:
                found.append(
                    _err(
                        "signed-attrs.content-type",
                        f"content-type {attr_type} differs from eContentType {content_type}",
                        "RFC 6488 section 2.1.6.4.1",
                    )
                )
    return tuple(found)


def _digest_algorithm_ok(alg: cms.AlgorithmIdentifier) -> bool:
    # RFC 5754 section 2: parameters absent or NULL are both to be accepted.
    return alg.oid == ID_SHA256 and (alg.parameters is None or alg.parameters == b"\x05\x00")


def _read_time(attr: cms.Attribute) -> datetime.datetime:
    value = _single_value(attr)
    if value is None:
        raise Asn1Error("signing-time needs one value")
    node, _ = asn1core.decode(value, der=True)
    if node.tag.number == 23:
        return check_utc_time(node.payload or b"")
    if node.tag.number == 24:
        return check_generalized_time(node.payload or b"")
    raise Asn1Error("signing-time is neither UTCTime nor GeneralizedTime")


def decode_signed_object(blob: bytes) -> SignedObject:
    """Decode a blob as an RPKI signed object (RFC 6488) and apply the profile (see the module docstring).

    ``SignedObjectError`` carries every finding; a blob that is not DER CMS at all gives one
    finding, ``cms.load``'s message. The signature and the EE certificate's path are not checked.
    """
    try:
        data = cms.load(blob, der=True)
    except (cms.CmsError, Asn1Error) as error:
        raise SignedObjectError(
            (_err("signed-object.cms", str(error), "RFC 6488 section 2"),)
        ) from error
    spec = "RFC 6488 section 3"
    found: list[Finding] = []
    if data.version != 3:
        found.append(
            _err(
                "signed-object.version",
                f"SignedData version {data.version}, 3 required",
                "RFC 6488 section 2.1.1",
            )
        )
    if len(data.digest_algorithms) != 1 or not _digest_algorithm_ok(data.digest_algorithms[0]):
        found.append(
            _err(
                "signed-object.digest-algorithms",
                "digestAlgorithms is not exactly SHA-256",
                "RFC 6488 section 2.1.2, RFC 7935 section 2",
            )
        )
    if data.econtent is None:
        found.append(
            _err("signed-object.detached", "eContent is absent", "RFC 6488 section 2.1.3.2")
        )
    if data.crls:
        found.append(_err("signed-object.crls", "crls must be omitted", "RFC 6488 section 2.1.5"))
    certs = [c for c in data.certificates if c.kind is cms.CertificateKind.CERTIFICATE]
    if len(data.certificates) != 1 or len(certs) != 1:
        found.append(
            _err(
                "signed-object.certificates",
                f"{len(data.certificates)} certificates, exactly one EE certificate is required",
                "RFC 6488 section 2.1.4",
            )
        )
    if len(data.signer_infos) != 1:
        found.append(
            _err(
                "signed-object.signers",
                f"{len(data.signer_infos)} SignerInfo, exactly one is required",
                "RFC 6488 section 2.1",
            )
        )
    if found or not certs or len(data.signer_infos) != 1 or data.econtent is None:
        raise SignedObjectError(tuple(found))
    signer = data.signer_infos[0]
    if signer.version != 3:
        found.append(
            _err(
                "signed-object.signer-version",
                f"SignerInfo version {signer.version}, 3 required",
                "RFC 6488 section 2.1.6.1",
            )
        )
    if signer.subject_key_identifier is None:
        found.append(
            _err(
                "signed-object.sid", "sid is not a SubjectKeyIdentifier", "RFC 6488 section 2.1.6.2"
            )
        )
    if not _digest_algorithm_ok(signer.digest_algorithm):
        found.append(
            _err(
                "signed-object.signer-digest",
                "SignerInfo digestAlgorithm is not SHA-256",
                "RFC 6488 section 2.1.6.3, RFC 7935 section 2",
            )
        )
    if signer.signature_algorithm.oid not in (ID_RSA_ENCRYPTION, ID_SHA256_WITH_RSA):
        found.append(
            _err(
                "signed-object.signature-algorithm",
                f"signatureAlgorithm {signer.signature_algorithm.oid} is neither rsaEncryption nor sha256WithRSAEncryption",
                "RFC 7935 section 2",
            )
        )
    if signer.unsigned_attrs is not None:
        found.append(
            _err(
                "signed-object.unsigned-attrs",
                "unsignedAttrs must be omitted",
                "RFC 6488 section 2.1.6.7",
            )
        )
    found.extend(check_signed_attrs(signer, data.encap_content_type))
    try:
        ee = asn1core.parse_certificate(certs[0].raw)
    except Asn1Error as error:
        found.append(_err("signed-object.ee-certificate", str(error), spec))
        raise SignedObjectError(tuple(found)) from error
    ski_ext = ee.extension(_SKI)
    if ski_ext is None:
        found.append(
            _err(
                "signed-object.ee-ski",
                "the EE certificate has no SubjectKeyIdentifier",
                "RFC 6488 section 2.1.6.2",
            )
        )
    elif (
        signer.subject_key_identifier is not None
        and parse_subject_key_identifier(ski_ext.value) != signer.subject_key_identifier
    ):
        found.append(
            _err(
                "signed-object.ee-ski",
                "the sid does not match the EE certificate's SubjectKeyIdentifier",
                spec,
            )
        )
    attrs = {a.oid: a for a in signer.signed_attrs or ()}
    signing_time = None
    digest = b""
    if ID_SIGNING_TIME in attrs:
        try:
            signing_time = _read_time(attrs[ID_SIGNING_TIME])
        except Asn1Error as error:
            found.append(_err("signed-attrs.signing-time", str(error), "RFC 9589 section 4"))
    if (
        ID_MESSAGE_DIGEST in attrs
        and (value := _single_value(attrs[ID_MESSAGE_DIGEST])) is not None
    ):
        try:
            node, _ = asn1core.decode(value, der=True)
            if node.tag.number != 4 or node.payload is None:
                raise Asn1Error("message-digest is not an OCTET STRING")
            digest = node.payload
        except Asn1Error as error:
            found.append(
                _err("signed-attrs.message-digest", str(error), "RFC 6488 section 2.1.6.4.2")
            )
    if found or signing_time is None or signer.signed_attrs_raw is None:
        raise SignedObjectError(tuple(found))
    return SignedObject(
        content_type=data.encap_content_type,
        econtent=data.econtent,
        ee_certificate=ee,
        signing_time=signing_time,
        message_digest=digest,
        signed_attrs_raw=signer.signed_attrs_raw,
        signature=signer.signature,
        cms=data,
    )


def verify_rsa_sha256(obj: SignedObject) -> tuple[Finding, ...]:
    """RFC 6488 section 3 item 2: digest and signature check; returns the errors, none if good.

    The message-digest attribute must equal SHA-256 of eContent. The signature is verified over
    the signedAttrs with the first octet changed from ``A0`` to ``31`` (RFC 5652 section 5.4;
    the attributes are DER, which ``cms.load`` read strictly), under the EE certificate's RSA
    key, which must be 2048 bits with exponent 65537 (RFC 7935 section 3).
    """
    found: list[Finding] = []
    if hashlib.sha256(obj.econtent).digest() != obj.message_digest:
        found.append(
            _err(
                "signature.digest",
                "message-digest differs from the SHA-256 of eContent",
                "RFC 5652 section 5.4",
            )
        )
    try:
        key = parse_spki(obj.ee_certificate.subject_public_key_info).key
    except Asn1Error as error:
        return (*found, _err("signature.key", f"EE key unreadable: {error}", "RFC 7935 section 3"))
    if not isinstance(key, RsaPublicKey):
        return (*found, _err("signature.key", "EE key is not RSA", "RFC 7935 section 3"))
    if key.modulus.bit_length() != 2048 or key.public_exponent != 65537:
        found.append(
            _err(
                "signature.key",
                f"EE key is RSA-{key.modulus.bit_length()} with e={key.public_exponent}, RFC 7935 requires 2048 bits and 65537",
                "RFC 7935 section 3",
            )
        )
    if any(f.rule == "signature.key" for f in found):
        return tuple(found)
    signed = b"\x31" + obj.signed_attrs_raw[1:]
    try:
        good = _verify(key.modulus, key.public_exponent, signed, obj.signature)
    except VerifyError as error:
        return (
            *found,
            _err(
                "signature.key",
                f"the verifier refused the key or signature: {error}",
                "RFC 7935 section 3",
            ),
        )
    if not good:
        found.append(
            _err(
                "signature.invalid",
                "the signature does not verify under the EE certificate key",
                "RFC 6488 section 3 item 2",
            )
        )
    return tuple(found)
