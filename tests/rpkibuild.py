"""Builders for RPKI test objects: resource certificates, CRLs, signed objects, ROA and manifest content.

There is no byte vector for any of these in RFC 6487, 6488, 9286 or 9582, so each scenario is built
here from the ASN.1 of the document under test and signed with a throwaway RSA-2048 key through the
``cryptography`` package. The DER is encoded by hand (``tlv``) so that a test can write the
deliberate faults a relying party must refuse: an extra signed attribute, a wrong version, an
unsorted resource set. Nothing here is imported by the package.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

UTC = datetime.UTC
ID_SIGNED_DATA = "1.2.840.113549.1.7.2"
ID_CT_ROA = "1.2.840.113549.1.9.16.1.24"
ID_CT_MANIFEST = "1.2.840.113549.1.9.16.1.26"
ID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
ID_SIGNING_TIME = "1.2.840.113549.1.9.5"
ID_BINARY_SIGNING_TIME = "1.2.840.113549.1.9.16.2.46"
ID_SHA256 = "2.16.840.1.101.3.4.2.1"
ID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
ID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
CP_V1 = "1.3.6.1.5.5.7.14.2"
CP_V2 = "1.3.6.1.5.5.7.14.3"


# -- DER ----------------------------------------------------------------------------------------


def length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + length(len(content)) + content


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def set_of(*parts: bytes) -> bytes:
    return tlv(0x31, b"".join(sorted(parts)))


def integer(n: int) -> bytes:
    size = max(1, (n.bit_length() + 8) // 8)
    return tlv(2, n.to_bytes(size, "big", signed=True))


def oid(dotted: str) -> bytes:
    arcs = [int(x) for x in dotted.split(".")]
    body = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(reversed(chunk))
    return tlv(6, body)


def octets(data: bytes) -> bytes:
    return tlv(4, data)


def null() -> bytes:
    return b"\x05\x00"


def bit_string(data: bytes, unused: int = 0) -> bytes:
    return tlv(3, bytes([unused]) + data)


def ia5(text: str) -> bytes:
    return tlv(0x16, text.encode("ascii"))


def generalized(when: datetime.datetime) -> bytes:
    return tlv(0x18, when.astimezone(UTC).strftime("%Y%m%d%H%M%SZ").encode())


def utc_time(when: datetime.datetime) -> bytes:
    return tlv(0x17, when.astimezone(UTC).strftime("%y%m%d%H%M%SZ").encode())


def explicit(number: int, content: bytes) -> bytes:
    return tlv(0xA0 | number, content)


def implicit_primitive(number: int, content: bytes) -> bytes:
    return tlv(0x80 | number, content)


def algorithm(dotted: str, *, parameters: bytes | None = None) -> bytes:
    return seq(oid(dotted), *([parameters] if parameters is not None else []))


# -- RFC 3779 resources ---------------------------------------------------------------------------


def _address_item(low: int, high: int, width: int) -> bytes:
    size = high - low + 1
    if size & (size - 1) == 0 and low % size == 0:
        prefix_len = width - (size.bit_length() - 1)
        nbytes = (prefix_len + 7) // 8
        unused = nbytes * 8 - prefix_len
        top = low >> (width - prefix_len) if prefix_len else 0
        return bit_string((top << unused).to_bytes(nbytes, "big") if nbytes else b"", unused)
    zeros = (low & -low).bit_length() - 1 if low else width
    min_len = width - zeros
    inverted = ~high & ((1 << width) - 1)
    ones = (inverted & -inverted).bit_length() - 1 if inverted else width
    max_len = width - ones

    def bits(value: int, bit_len: int) -> bytes:
        nbytes = (bit_len + 7) // 8
        unused = nbytes * 8 - bit_len
        top = value >> (width - bit_len) if bit_len else 0
        return bit_string((top << unused).to_bytes(nbytes, "big") if nbytes else b"", unused)

    return seq(bits(low, min_len), bits(high, max_len))


def ip_blocks(families: dict[tuple[int, int | None], list[tuple[int, int]] | None]) -> bytes:
    """IPAddrBlocks DER. ``None`` as a family's ranges means ``inherit``; ranges are inclusive ints.

    Order of ``families`` and of each range list is kept as given, so a test can write an
    unsorted set on purpose.
    """
    out = []
    for (afi, safi), ranges in families.items():
        key = afi.to_bytes(2, "big") + (bytes([safi]) if safi is not None else b"")
        width = 32 if afi == 1 else 128
        choice = (
            null() if ranges is None else seq(*(_address_item(lo, hi, width) for lo, hi in ranges))
        )
        out.append(seq(octets(key), choice))
    return seq(*out)


def as_ids(
    asnum: list[tuple[int, int]] | None | str = "absent",
    rdi: list[tuple[int, int]] | None | str = "absent",
) -> bytes:
    """ASIdentifiers DER. A list is the ranges, ``None`` is ``inherit``, ``"absent"`` omits the element."""

    def choice(ranges: list[tuple[int, int]] | None) -> bytes:
        if ranges is None:
            return null()
        return seq(
            *(integer(lo) if lo == hi else seq(integer(lo), integer(hi)) for lo, hi in ranges)
        )

    parts = []
    if asnum != "absent":
        parts.append(explicit(0, choice(asnum)))  # type: ignore[arg-type]
    if rdi != "absent":
        parts.append(explicit(1, choice(rdi)))  # type: ignore[arg-type]
    return seq(*parts)


def prefix_range(text: str) -> tuple[int, int]:
    net = ipaddress.ip_network(text)
    return int(net.network_address), int(net.broadcast_address)


# -- certificates and CRLs ---------------------------------------------------------------------------


_KEYS: dict[str, rsa.RSAPrivateKey] = {}


def key(name: str) -> rsa.RSAPrivateKey:
    """A cached RSA-2048 key by name (generation is the slow part of the suite)."""
    if name not in _KEYS:
        _KEYS[name] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _KEYS[name]


def ski_of(private: rsa.RSAPrivateKey) -> bytes:
    return x509.SubjectKeyIdentifier.from_public_key(private.public_key()).digest


NOW = datetime.datetime(2026, 11, 13, 12, 0, tzinfo=UTC)


@dataclass
class CertSpec:
    """What :func:`make_cert` needs; every field has the value of a conforming certificate."""

    subject: str = "EE"
    issuer: str = "TA"
    subject_key: str = "ee"
    issuer_key: str = "ta"
    serial: int = 1
    not_before: datetime.datetime = NOW - datetime.timedelta(days=1)
    not_after: datetime.datetime = NOW + datetime.timedelta(days=30)
    ca: bool = False
    ip: bytes | None = None
    asn: bytes | None = None
    v2_extensions: bool = False
    policies: tuple[str, ...] = (CP_V1,)
    ip_critical: bool = True
    as_critical: bool = True
    crl_uri: str | None = "rsync://rpki.example.net/repo/ca.crl"
    self_signed: bool = False
    both_ip_versions: bool = False


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(spec: CertSpec) -> bytes:
    """A DER certificate shaped like an RPKI resource certificate, signed by ``spec.issuer_key``."""
    subject = key(spec.subject_key)
    issuer = key(spec.issuer_key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(spec.subject))
        .issuer_name(_name(spec.issuer))
        .public_key(subject.public_key())
        .serial_number(spec.serial)
        .not_valid_before(spec.not_before)
        .not_valid_after(spec.not_after)
    )
    if spec.ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(subject.public_key()), critical=False
    )
    if not spec.self_signed:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()), critical=False
        )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=not spec.ca,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=spec.ca,
            crl_sign=spec.ca,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    if spec.policies:
        builder = builder.add_extension(
            x509.CertificatePolicies(
                [x509.PolicyInformation(x509.ObjectIdentifier(p), None) for p in spec.policies]
            ),
            critical=True,
        )
    if spec.crl_uri and not spec.self_signed:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(spec.crl_uri)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    ip_oid = "1.3.6.1.5.5.7.1.28" if spec.v2_extensions else "1.3.6.1.5.5.7.1.7"
    as_oid = "1.3.6.1.5.5.7.1.29" if spec.v2_extensions else "1.3.6.1.5.5.7.1.8"
    if spec.ip is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(ip_oid), spec.ip),
            critical=spec.ip_critical,
        )
    if spec.ip is not None and spec.both_ip_versions:
        other = "1.3.6.1.5.5.7.1.7" if spec.v2_extensions else "1.3.6.1.5.5.7.1.28"
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(other), spec.ip), critical=True
        )
    if spec.asn is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(as_oid), spec.asn),
            critical=spec.as_critical,
        )
    cert = builder.sign(issuer, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def make_crl(
    *,
    issuer: str = "TA",
    issuer_key: str = "ta",
    revoked: tuple[int, ...] = (),
    number: int = 1,
    this_update: datetime.datetime = NOW - datetime.timedelta(hours=1),
    next_update: datetime.datetime = NOW + datetime.timedelta(hours=23),
    extra_extension: bool = False,
    crl_number_critical: bool = False,
    omit_aki: bool = False,
) -> bytes:
    signer = key(issuer_key)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_name(issuer))
        .last_update(this_update)
        .next_update(next_update)
        .add_extension(x509.CRLNumber(number), critical=crl_number_critical)
    )
    if not omit_aki:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False
        )
    if extra_extension:
        builder = builder.add_extension(
            x509.IssuingDistributionPoint(
                full_name=None,
                relative_name=None,
                only_contains_user_certs=False,
                only_contains_ca_certs=False,
                only_some_reasons=None,
                indirect_crl=True,
                only_contains_attribute_certs=False,
            ),
            critical=True,
        )
    for serial in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(this_update)
            .build()
        )
    crl = builder.sign(signer, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.DER)


# -- signed objects -----------------------------------------------------------------------------------


def attribute(dotted: str, *values: bytes) -> bytes:
    return seq(oid(dotted), set_of(*values))


def make_signed_object(
    *,
    signer: str = "ee",
    ee_cert: bytes,
    content_type: str,
    econtent: bytes,
    signing_time: datetime.datetime | None = NOW,
    binary_signing_time: bool = False,
    extra_attrs: tuple[bytes, ...] = (),
    drop_content_type_attr: bool = False,
    content_type_attr_value: str | None = None,
    message_digest: bytes | None = None,
    version: int = 3,
    signer_version: int = 3,
    digest_oids: tuple[str, ...] = (ID_SHA256,),
    signer_digest_oid: str = ID_SHA256,
    signature_oid: str = ID_RSA_ENCRYPTION,
    sid_ski: bytes | None = None,
    crls: tuple[bytes, ...] = (),
    certs: tuple[bytes, ...] | None = None,
    unsigned_attrs: tuple[bytes, ...] = (),
    signers: int = 1,
    tamper_signature: bool = False,
) -> bytes:
    """A DER CMS SignedData in the RFC 6488 shape, each element adjustable to break a rule."""
    private = key(signer)
    attrs: list[bytes] = []
    if not drop_content_type_attr:
        attrs.append(attribute(ID_CONTENT_TYPE, oid(content_type_attr_value or content_type)))
    digest = message_digest if message_digest is not None else hashlib.sha256(econtent).digest()
    attrs.append(attribute(ID_MESSAGE_DIGEST, octets(digest)))
    if signing_time is not None:
        attrs.append(attribute(ID_SIGNING_TIME, utc_time(signing_time)))
    if binary_signing_time:
        attrs.append(attribute(ID_BINARY_SIGNING_TIME, integer(int(NOW.timestamp()))))
    attrs.extend(extra_attrs)
    attrs_content = b"".join(sorted(attrs))
    signed_set = tlv(0x31, attrs_content)  # tag 31, the form RFC 5652 section 5.4 signs
    signature = private.sign(signed_set, padding.PKCS1v15(), hashes.SHA256())
    if tamper_signature:
        signature = signature[:-1] + bytes([signature[-1] ^ 1])
    sid = implicit_primitive(0, sid_ski if sid_ski is not None else ski_of(private))
    signer_info = seq(
        integer(signer_version),
        sid,
        algorithm(signer_digest_oid),
        tlv(0xA0, attrs_content),
        algorithm(signature_oid, parameters=null()),
        octets(signature),
        *([tlv(0xA1, b"".join(unsigned_attrs))] if unsigned_attrs else []),
    )
    cert_set = certs if certs is not None else (ee_cert,)
    body = [
        integer(version),
        set_of(*(algorithm(o) for o in digest_oids)),
        seq(oid(content_type), explicit(0, octets(econtent))),
    ]
    if cert_set:
        body.append(tlv(0xA0, b"".join(cert_set)))
    if crls:
        body.append(tlv(0xA1, b"".join(crls)))
    body.append(set_of(*([signer_info] * signers)))
    return seq(oid(ID_SIGNED_DATA), explicit(0, seq(*body)))


# -- eContent -----------------------------------------------------------------------------------------------


def roa_content(
    asn: int,
    blocks: list[tuple[int, list[tuple[str, int | None]]]],
    *,
    version: int | None = None,
) -> bytes:
    """RouteOriginAttestation DER: ``blocks`` is ``[(afi, [(prefix text, maxLength or None)])]``."""
    parts = []
    if version is not None:
        parts.append(explicit(0, integer(version)))
    parts.append(integer(asn))
    families = []
    for afi, entries in blocks:
        width = 32 if afi == 1 else 128
        addresses = []
        for text, max_length in entries:
            net = ipaddress.ip_network(text)
            nbytes = (net.prefixlen + 7) // 8
            unused = nbytes * 8 - net.prefixlen
            data = net.network_address.packed[:nbytes]
            if unused and nbytes:
                data = data[:-1] + bytes([data[-1] & (0xFF << unused) & 0xFF])
            item = [bit_string(data, unused)]
            if max_length is not None:
                item.append(integer(max_length))
            addresses.append(seq(*item))
        del width
        families.append(seq(octets(afi.to_bytes(2, "big")), seq(*addresses)))
    parts.append(seq(*families))
    return seq(*parts)


def manifest_content(
    number: int,
    this_update: datetime.datetime,
    next_update: datetime.datetime,
    files: list[tuple[str, bytes]],
    *,
    version: int | None = None,
    hash_alg: str = ID_SHA256,
    hash_unused: int = 0,
) -> bytes:
    """Manifest DER: ``files`` is ``[(name, hash octets)]`` with the hash as given."""
    parts = []
    if version is not None:
        parts.append(explicit(0, integer(version)))
    parts += [
        integer(number),
        generalized(this_update),
        generalized(next_update),
        oid(hash_alg),
        seq(*(seq(ia5(name), bit_string(digest, hash_unused)) for name, digest in files)),
    ]
    return seq(*parts)
