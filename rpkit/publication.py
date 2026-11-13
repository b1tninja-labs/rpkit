"""Which CRL applies to a certificate, and the profile of the two extensions that locate it.

RFC 9829 section 2 (read through rfclib on 2026-11-13) says that exactly one CRL is appropriate and
relevant for a resource certificate: the unique CRL object that is the target of the certificate's
CRL Distribution Points extension *and* is listed in the issuing CA's current manifest fileList with
a matching hash. Section 3.2 writes that into RFC 6487 section 7.2 item 5 ("as identified by the
issuer's current manifest and the CRLDP of the certificate"), and section 2 adds that "a resource
certificate cannot be validated without consulting the current manifest of the certificate's
issuer". RFC 9286 section 6.1 puts the manifest and every file it lists at one publication point;
section 6.3 makes a stale or premature manifest a failed fetch.

* :func:`crldp_findings` is RFC 6487 section 4.8.6: present unless self-signed, non-critical, one
  DistributionPoint with a fullName of URIs, no Reasons, no cRLIssuer, an rsync URI among them.
* :func:`aia_findings` is section 4.8.7: present unless self-signed, non-critical, an rsync URI
  with the accessMethod id-ad-caIssuers. :func:`check_aia` adds that the URI is the one the issuer's
  certificate was fetched from.
* :func:`select_crl` takes a certificate and the issuer's :class:`PublicationPoint` (its manifest and
  the files fetched next to it) and returns the one CRL, or the findings that say why there is none.

Nothing here fetches or decides trust. The caller says where the files came from.
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from asn1core import Asn1Error
from asn1core.extensions import parse_access_descriptions, parse_crl_distribution_points

from .findings import Finding, Severity, errors

if TYPE_CHECKING:
    from collections.abc import Mapping

    import asn1core

    from .manifest import Manifest

__all__ = [
    "CrlChoice",
    "PublicationPoint",
    "aia_findings",
    "check_aia",
    "crl_uris",
    "crldp_findings",
    "issuer_uris",
    "select_crl",
]

_CRLDP = "2.5.29.31"
_AIA = "1.3.6.1.5.5.7.1.1"
_CA_ISSUERS = (1, 3, 6, 1, 5, 5, 7, 48, 2)
_URI = "uniformResourceIdentifier"


def _err(rule: str, message: str, spec: str) -> Finding:
    return Finding(Severity.ERROR, rule, message, spec)


def _is_rsync(uri: str) -> bool:
    return uri[:8].lower() == "rsync://"


@dataclass(frozen=True, slots=True)
class PublicationPoint:
    """An issuer's publication point as fetched: its current manifest and the files beside it.

    ``uri`` is the rsync directory URI (RFC 9286 section 6.1: the id-ad-caRepository of the CA
    certificate); ``files`` maps file name to content for the files fetched there; ``manifest`` is
    the parsed current manifest. ``certificate_uri`` is where the CA certificate itself was fetched
    from, when the caller knows it, so that the Authority Information Access of the certificates
    below can be checked against it.
    """

    uri: str
    manifest: Manifest
    files: Mapping[str, bytes]
    certificate_uri: str | None = None

    @property
    def directory(self) -> str:
        return self.uri if self.uri.endswith("/") else self.uri + "/"


@dataclass(frozen=True, slots=True)
class CrlChoice:
    """What :func:`select_crl` decided: the CRL's URI and bytes, or None, and why."""

    uri: str | None
    crl: bytes | None
    findings: tuple[Finding, ...]

    @property
    def valid(self) -> bool:
        return self.crl is not None and not errors(self.findings)


def crl_uris(cert: asn1core.Certificate) -> tuple[str, ...]:
    """The rsync URIs of the CRL Distribution Points extension, in order; empty when it is absent
    or unreadable (:func:`crldp_findings` says which)."""
    ext = cert.extension(_CRLDP)
    if ext is None:
        return ()
    try:
        points = parse_crl_distribution_points(ext.value)
    except Asn1Error:
        return ()
    out: list[str] = []
    for point in points:
        for name in point.full_name or ():
            if name.kind == _URI and isinstance(name.value, str) and _is_rsync(name.value):
                out.append(name.value)
    return tuple(out)


def issuer_uris(cert: asn1core.Certificate) -> tuple[str, ...]:
    """The rsync URIs of the id-ad-caIssuers entries of the Authority Information Access."""
    ext = cert.extension(_AIA)
    if ext is None:
        return ()
    try:
        descriptions = parse_access_descriptions(ext.value)
    except Asn1Error:
        return ()
    return tuple(
        d.location.value
        for d in descriptions
        if d.method == _CA_ISSUERS
        and d.location.kind == _URI
        and isinstance(d.location.value, str)
        and _is_rsync(d.location.value)
    )


def crldp_findings(cert: asn1core.Certificate) -> tuple[Finding, ...]:
    """RFC 6487 section 4.8.6 on one certificate (a self-signed one must omit the extension)."""
    spec = "RFC 6487 section 4.8.6"
    ext = cert.extension(_CRLDP)
    if cert.self_issued:
        if ext is None:
            return ()
        return (_err("crldp.self-signed", "a self-signed certificate must omit CRLDP", spec),)
    if ext is None:
        return (_err("crldp.missing", "the CRL Distribution Points extension is absent", spec),)
    found: list[Finding] = []
    if ext.critical:
        found.append(_err("crldp.critical", "the extension is critical", spec))
    try:
        points = parse_crl_distribution_points(ext.value)
    except Asn1Error as error:
        return (*found, _err("crldp.malformed", str(error), spec))
    if len(points) != 1:
        found.append(
            _err(
                "crldp.distribution-points",
                f"{len(points)} DistributionPoints; the profile allows exactly one",
                spec,
            )
        )
    for point in points:
        if point.crl_issuer is not None:
            found.append(_err("crldp.crl-issuer", "cRLIssuer must be omitted", spec))
        if point.reasons is not None:
            found.append(_err("crldp.reasons", "Reasons must be omitted", spec))
        if point.full_name is None:
            found.append(_err("crldp.full-name", "distributionPoint must be a fullName", spec))
            continue
        if any(name.kind != _URI for name in point.full_name):
            found.append(_err("crldp.name-form", "every generalName must be a URI", spec))
    if not crl_uris(cert):
        found.append(_err("crldp.no-rsync", "no rsync URI among the distribution points", spec))
    return tuple(found)


def aia_findings(cert: asn1core.Certificate) -> tuple[Finding, ...]:
    """RFC 6487 section 4.8.7 on one certificate (a self-signed one must omit the extension)."""
    spec = "RFC 6487 section 4.8.7"
    ext = cert.extension(_AIA)
    if cert.self_issued:
        if ext is None:
            return ()
        return (_err("aia.self-signed", "a self-signed certificate must omit AIA", spec),)
    if ext is None:
        return (_err("aia.missing", "the Authority Information Access extension is absent", spec),)
    found: list[Finding] = []
    if ext.critical:
        found.append(_err("aia.critical", "the extension is critical", spec))
    try:
        parse_access_descriptions(ext.value)
    except Asn1Error as error:
        return (*found, _err("aia.malformed", str(error), spec))
    if not issuer_uris(cert):
        found.append(_err("aia.no-rsync", "no rsync id-ad-caIssuers URI", spec))
    return tuple(found)


def check_aia(cert: asn1core.Certificate, issuer_uri: str) -> tuple[Finding, ...]:
    """RFC 6487 section 4.8.7: the AIA rsync URI references the issuer's certificate where it is
    published. ``issuer_uri`` is where the caller fetched that certificate from."""
    if issuer_uri in issuer_uris(cert):
        return ()
    return (
        _err(
            "aia.mismatch",
            f"the AIA does not name {issuer_uri}",
            "RFC 6487 section 4.8.7",
        ),
    )


def select_crl(
    cert: asn1core.Certificate,
    point: PublicationPoint,
    at: datetime.datetime | None = None,
) -> CrlChoice:
    """The one CRL for ``cert``: named by its CRLDP, at ``point``, listed with a matching hash.

    RFC 9829 section 2. Each rsync URI of the CRLDP must lie directly in the publication point's
    directory (RFC 9286 section 6.1), name a file the manifest lists (otherwise the CRL is missing,
    RFC 9286 section 6, last sentence of the chicken-and-egg note) that was fetched, and hash to
    the listed value (section 6.5). More than one distinct CRL satisfying that is ambiguous and
    refused. With ``at`` (timezone-aware) the manifest must also be current (section 6.3: thisUpdate
    not after it, nextUpdate not before it); otherwise the time is not looked at.
    """
    spec = "RFC 9829 section 2, RFC 9286 section 6"
    found: list[Finding] = []
    if at is not None:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if at < point.manifest.this_update:
            found.append(
                _err("manifest.premature", "thisUpdate is after the time", "RFC 9286 section 6.3")
            )
        if at > point.manifest.next_update:
            found.append(_err("manifest.stale", "nextUpdate has passed", "RFC 9286 section 6.3"))
    uris = crl_uris(cert)
    if not uris:
        found.append(_err("crl.no-uri", "the certificate names no rsync CRL", spec))
        return CrlChoice(None, None, tuple(found))
    listed = {entry.name: entry.hash for entry in point.manifest.files}
    base = point.directory
    matched: dict[str, bytes] = {}
    for uri in uris:
        name = uri[len(base) :]
        if not uri.startswith(base) or not name or "/" in name:
            found.append(
                _err(
                    "crl.elsewhere", f"{uri} is not directly in the publication point {base}", spec
                )
            )
        elif name not in listed:
            found.append(_err("crl.not-listed", f"{name} is not in the issuer's manifest", spec))
        elif name not in point.files:
            found.append(_err("crl.not-fetched", f"{name} is listed but was not fetched", spec))
        elif hashlib.sha256(point.files[name]).digest() != listed[name]:
            found.append(
                _err("crl.hash-mismatch", f"{name} does not match its manifest hash", spec)
            )
        else:
            matched[uri] = point.files[name]
    if len(set(matched.values())) > 1:
        found.append(_err("crl.ambiguous", "the URIs select different CRLs", spec))
        return CrlChoice(None, None, tuple(found))
    if not matched:
        return CrlChoice(None, None, tuple(found))
    uri, data = next(iter(matched.items()))
    return CrlChoice(uri, data, tuple(found))
