"""CRL checks and ROA validation (RFC 6487, RFC 9829, RFC 9582, RFC 6488, RFC 7935).

``check_crl`` applies the CRL profile: RFC 6487 section 5 as RFC 9829 section 3.1 revises it,
read through rfclib on 2026-11-13 (a version 2 CRL; exactly two extensions, Authority Key
Identifier and CRL Number, each once; the CRL Number non-critical and within 0..2^159-1, otherwise
ignored; revoked entries with only a serial number and a revocation date; sha256WithRSAEncryption,
RFC 7935 section 2) and the signature under the issuer's key through pkix. It says which serials are
revoked and whether the CRL is current at a given time.

``validate_roa`` composes the pieces for one ROA: the signed object profile and signature
(:mod:`rpkit.signedobject`), the ROA content (:mod:`rpkit.roa`), and RFC 6487 section 7.2 over the
certification path from the trust anchor certificate to the EE certificate: signatures and validity
through pkix, issuer and subject names, revocation by the issuer's CRL, the resource profile and
path procedure of :mod:`rpkit.resources` (RFC 6487 section 7 by default, RFC 8360 selectable), and
the RFC 9582 section 5 conditions on the EE certificate (an IP resources extension without
``inherit``, no AS resources extension, every ROA prefix inside the resources). The result names the
procedure. It does not fetch anything, decide which trust anchor to trust, or look for a CRL
elsewhere than in the ``crls`` it is given: a CA certificate whose issuer has no CRL among them is
an error.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import TYPE_CHECKING

import asn1core
from asn1core import Asn1Error, check_integer, names_equal
from asn1core.crl import Crl, parse_crl
from asn1core.extensions import parse_subject_key_identifier
from pkix.errors import PkixError
from pkix.validity import check_signature, check_signed_data, check_validity

from . import resources as res
from .findings import Finding, Severity, errors
from .roa import ROA_CONTENT_TYPE, Roa, RoaError, Vrp, parse_roa_content
from .signedobject import SignedObjectError, decode_signed_object, verify_rsa_sha256

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from typing import Any

    Repository = Any  # placeholder: give it a real type in the milestone that needs it
    RovState = Any  # placeholder: give it a real type in the milestone that needs it
    SignedObject = Any  # placeholder: give it a real type in the milestone that needs it
    ValidationResult = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "CrlResult",
    "RoaValidation",
    "check_crl",
    "validate_origin",
    "validate_roa",
]

_AKI = "2.5.29.35"
_CRL_NUMBER = "2.5.29.20"
_SKI = "2.5.29.14"
_BASIC_CONSTRAINTS = "2.5.29.19"
ID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
MAX_CRL_NUMBER = 2**159 - 1


def _err(rule: str, message: str, spec: str) -> Finding:
    return Finding(Severity.ERROR, rule, message, spec)


@dataclass(frozen=True, slots=True)
class CrlResult:
    """What :func:`check_crl` found: the CRL, its number, the revoked serials and the errors."""

    crl: Crl | None
    number: int | None
    revoked_serials: frozenset[int]
    findings: tuple[Finding, ...]

    @property
    def valid(self) -> bool:
        return self.crl is not None and not errors(self.findings)


def _inner_algorithm(crl: Crl) -> bytes:
    tbs, _ = asn1core.decode(crl.tbs_cert_list, der=True)
    fields = list(tbs.children)
    if fields and fields[0].tag.number == 2 and fields[0].tag.is_universal():
        fields.pop(0)
    return fields[0].raw


def check_crl(
    crl_der: bytes, issuer: asn1core.Certificate | bytes, at: datetime.datetime
) -> CrlResult:
    """Check a CRL against the profile and the issuer certificate, at the time ``at``.

    ``at`` must be timezone-aware. The CRL must be signed by ``issuer``'s key, name it as its
    issuer, carry the issuer's SubjectKeyIdentifier in its Authority Key Identifier, and be
    current: thisUpdate not after ``at`` and nextUpdate not before it (RFC 6487 section 7.2 item 5
    needs a CRL that is itself valid). A CRL that cannot be parsed gives ``crl=None`` and one
    error. Every violation is an ERROR finding; the revoked serials are returned even when other
    errors exist, so a caller can see them, but ``valid`` is then false.
    """
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")
    cert = (
        issuer if isinstance(issuer, asn1core.Certificate) else asn1core.parse_certificate(issuer)
    )
    try:
        crl = parse_crl(crl_der)
    except Asn1Error as error:
        return CrlResult(
            None, None, frozenset(), (_err("crl.parse", str(error), "RFC 6487 section 5"),)
        )
    found: list[Finding] = []
    if crl.version != 1:
        found.append(_err("crl.version", "the CRL is not version 2", "RFC 6487 section 5"))
    if not names_equal(crl.issuer, cert.subject):
        found.append(
            _err(
                "crl.issuer",
                "the CRL issuer is not the issuer certificate's subject",
                "RFC 6487 section 5",
            )
        )
    try:
        result = check_signed_data(
            crl.tbs_cert_list,
            crl.signature_algorithm_raw,
            _inner_algorithm(crl),
            crl.signature_value,
            cert.subject_public_key_info,
            what="CRL",
        )
        if result.algorithm != ID_SHA256_WITH_RSA or result.key != "RSA-2048":
            found.append(
                _err(
                    "crl.algorithm",
                    f"{result.algorithm} with {result.key}; RFC 7935 requires sha256WithRSAEncryption and RSA-2048",
                    "RFC 7935 sections 2 and 3",
                )
            )
    except PkixError as error:
        found.append(_err("crl.signature", str(error), "RFC 6487 section 5, RFC 7935"))
    number = _check_extensions(crl, cert, found)
    for entry in crl.revoked:
        if entry.extensions:
            found.append(
                _err(
                    "crl.entry-extensions",
                    f"entry for serial {entry.serial} has extensions",
                    "RFC 6487 section 5",
                )
            )
    if at < crl.this_update:
        found.append(
            _err(
                "crl.not-yet-valid",
                "thisUpdate is after the time of validation",
                "RFC 6487 section 7.2",
            )
        )
    if crl.next_update is None or at > crl.next_update:
        found.append(
            _err("crl.stale", "nextUpdate is absent or has passed", "RFC 6487 section 7.2")
        )
    return CrlResult(crl, number, frozenset(crl.revoked_serials), tuple(found))


def _check_extensions(crl: Crl, cert: asn1core.Certificate, found: list[Finding]) -> int | None:
    spec = "RFC 6487 section 5, RFC 9829 section 3.1"
    oids = [e.dotted_oid for e in crl.extensions]
    for extra in sorted(set(oids) - {_AKI, _CRL_NUMBER}):
        found.append(_err("crl.extension", f"extension {extra} is not allowed", spec))
    for needed in (_AKI, _CRL_NUMBER):
        if oids.count(needed) != 1:
            found.append(
                _err(
                    "crl.extension",
                    f"extension {needed} must appear exactly once, found {oids.count(needed)}",
                    spec,
                )
            )
    number = None
    for ext in crl.extensions:
        if ext.dotted_oid == _CRL_NUMBER:
            if ext.critical:
                found.append(_err("crl.number", "the CRL Number is critical", spec))
            try:
                node, _ = asn1core.decode(ext.value, der=True)
                number = check_integer(node.payload or b"")
            except Asn1Error as error:
                found.append(_err("crl.number", str(error), spec))
            else:
                if not 0 <= number <= MAX_CRL_NUMBER:
                    found.append(_err("crl.number", "the CRL Number is outside 0..2^159-1", spec))
        elif ext.dotted_oid == _AKI:
            ski = cert.extension(_SKI)
            try:
                node, _ = asn1core.decode(ext.value, der=True)
                key_id = next((c.payload for c in node.children if c.tag.is_context(0)), None)
            except Asn1Error as error:
                found.append(_err("crl.aki", str(error), spec))
                continue
            if ski is None or key_id != parse_subject_key_identifier(ski.value):
                found.append(
                    _err(
                        "crl.aki",
                        "the Authority Key Identifier is not the issuer's SubjectKeyIdentifier",
                        "RFC 6487 section 5",
                    )
                )
    return number


@dataclass(frozen=True, slots=True)
class RoaValidation:
    """The result of :func:`validate_roa`: the procedure, the ROA and its VRPs when valid, and every finding."""

    procedure: res.Procedure
    roa: Roa | None
    findings: tuple[Finding, ...]

    @property
    def valid(self) -> bool:
        return self.roa is not None and not errors(self.findings)

    @property
    def vrps(self) -> tuple[Vrp, ...]:
        """The VRPs of a valid ROA, and nothing for an invalid one (RFC 6488: it is discarded)."""
        return self.roa.vrps() if self.valid and self.roa is not None else ()


def _cert(der: bytes) -> asn1core.Certificate:
    return asn1core.parse_certificate(der)


def _path_findings(
    chain: Sequence[asn1core.Certificate],
    crls: Sequence[CrlResult],
    at: datetime.datetime,
) -> list[Finding]:
    """Signatures, names, validity and revocation along ``chain`` (trust anchor first, EE last)."""
    found: list[Finding] = []
    spec = "RFC 6487 section 7.2"
    for index, cert in enumerate(chain):
        label = f"certificate {index}"
        issuer = chain[index - 1] if index else cert
        if index and not names_equal(cert.issuer, issuer.subject):
            found.append(_err("path.names", f"{label}: issuer is not the subject above it", spec))
        try:
            check_signature(cert, issuer)
        except PkixError as error:
            found.append(_err("path.signature", f"{label}: {error}", spec))
        if not check_validity(cert, at).ok:
            found.append(
                _err("path.validity", f"{label}: not valid at the time of validation", spec)
            )
        if index:
            matching = [
                c for c in crls if c.crl is not None and names_equal(c.crl.issuer, issuer.subject)
            ]
            if not matching:
                found.append(
                    _err(
                        "path.crl-missing",
                        f"{label}: no CRL from its issuer",
                        "RFC 6487 section 7.2 item 5, RFC 9829 section 3.2",
                    )
                )
            for crl in matching:
                if cert.serial in crl.revoked_serials:
                    found.append(
                        _err("path.revoked", f"{label}: serial {cert.serial} is revoked", spec)
                    )
    return found


def validate_roa(
    blob: bytes,
    chain: Sequence[bytes],
    crls: Iterable[bytes],
    at: datetime.datetime,
    *,
    procedure: res.Procedure = res.Procedure.RFC6487,
) -> RoaValidation:
    """Validate one ROA end to end (see the module docstring). Behaviour defined by RFC 6487.

    ``blob`` is the signed object; ``chain`` the CA certificates from the trust anchor certificate
    (trusted by the caller, so not otherwise vetted) down to the EE certificate's issuer, as DER;
    ``crls`` the CRLs to consult; ``at`` the time of validation (timezone-aware). Under RFC 6487
    section 7 (the default) a certificate that overclaims is rejected; ``Procedure.RFC8360``
    selects RFC 8360 section 4.2.4.4. Every error is in ``findings``; the VRPs are returned only
    for a ROA with none. The trust anchor's own validity is checked at ``at`` like the others.
    """
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")
    found: list[Finding] = []
    try:
        signed = decode_signed_object(blob)
    except SignedObjectError as error:
        return RoaValidation(procedure, None, error.findings)
    found.extend(verify_rsa_sha256(signed))
    if signed.content_type != ROA_CONTENT_TYPE:
        found.append(
            _err(
                "roa.content-type",
                f"eContentType {signed.content_type} is not a ROA",
                "RFC 9582 section 3",
            )
        )
        return RoaValidation(procedure, None, tuple(found))
    try:
        roa = parse_roa_content(signed.econtent)
    except RoaError as error:
        return RoaValidation(procedure, None, tuple(found) + error.findings)
    found.extend(roa.findings)
    if not chain:
        found.append(_err("path.empty", "no trust anchor certificate", "RFC 6487 section 7.2"))
        return RoaValidation(procedure, roa, tuple(found))
    certs = [_cert(c) for c in chain] + [signed.ee_certificate]
    crl_results = [check_crl(c, certs[_issuer_index(c, certs)], at) for c in crls]
    for result in crl_results:
        found.extend(result.findings)
    found.extend(_path_findings(certs, crl_results, at))
    resources = []
    for index, cert in enumerate(certs):
        try:
            read = res.read_resources(cert)
        except res.ResourceReadError as error:
            found.append(_err("resources.read", f"certificate {index}: {error}", "RFC 3779"))
            return RoaValidation(procedure, roa, tuple(found))
        found.extend(res.profile_check(read, procedure=procedure))
        resources.append(read)
    ee = resources[-1]
    if ee.ip is None or any(f.inherit for f in ee.ip.families):
        found.append(
            _err(
                "roa.ee-ip",
                "the EE certificate needs IP resources without inherit",
                "RFC 9582 section 5",
            )
        )
    if ee.asn is not None:
        found.append(
            _err(
                "roa.ee-as", "the EE certificate must not carry AS resources", "RFC 9582 section 5"
            )
        )
    if certs[-1].extension(_BASIC_CONSTRAINTS) is not None:
        found.append(
            _err(
                "roa.ee-ca",
                "the EE certificate carries Basic Constraints",
                "RFC 6487 section 4.8.1",
            )
        )
    path = res.validate_path(resources, procedure=procedure)
    for step in path.steps:
        found.extend(step.findings)
    if path.valid:
        stray = res.outside(path.vrs, [a.prefix for a in roa.addresses])
        for prefix in stray:
            found.append(
                _err(
                    "roa.outside-resources",
                    f"{prefix} is not in the EE certificate's verified resources",
                    "RFC 9582 section 5",
                )
            )
    return RoaValidation(procedure, roa, tuple(found))


def _issuer_index(crl_der: bytes, certs: Sequence[asn1core.Certificate]) -> int:
    """Which certificate in ``certs`` issued the CRL, or 0 so an unmatched CRL fails its own checks."""
    try:
        issuer = parse_crl(crl_der).issuer
    except Asn1Error:
        return 0
    for index, cert in enumerate(certs):
        if names_equal(issuer, cert.subject):
            return index
    return 0


def validate_origin(prefix: str, asn: int, roas: Iterable) -> RovState:
    """Pending behaviour defined by RFC 6811 (route origin validation), RFC 8481.

    Not implemented yet. See the ``validation.validate_origin()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code. The row's home is
    an open owner decision: routevalid already implements the same classification on plain data
    and depends on rpkit, so rpkit importing it back would be a cycle. RFC 6480 is the
    architecture document, not the specification of this function.
    """
    raise NotImplementedError("validate_origin() is not implemented: RFC 6811")
