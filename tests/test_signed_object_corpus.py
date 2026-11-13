"""A real RPKI repository, every object parsed and every ROA validated: row ``validation.signed-object-corpus``.

The corpus is the RIPE NCC RPKI repository archive for the AFRINIC trust anchor on 2026-11-12
(``tools/corpus.json``: URL, SHA-256, size, the date read and the terms), fetched by
``tools/fetch_corpus.py`` into a cache outside the repository. Nothing is vendored; without the
cache every test here skips with the command that fills it. The archive holds what Routinator
fetched (``unvalidated``), what it accepted (``validated``), the trust anchor certificate, and,
in a second file, Routinator's VRPs for the same run, which is the second implementation the
ROADMAP's interop row asks for.

Every ``.cer``, ``.crl``, ``.mft`` and ``.roa`` of the fetched tree is parsed. Each ROA whose chain
can be built from the archive alone (the EE certificate's Authority Information Access names its
issuer's certificate, the CRL Distribution Points its issuer's CRL, up to the trust anchor) goes
through :func:`rpkit.validation.validate_roa` at Routinator's own generation time. The counts are
exact: the bytes are pinned, so a changed count means rpkit changed. The census takes about five
minutes, so those tests carry the ``corpus`` marker and run only with ``RPKIT_CORPUS=1`` or
``-m corpus`` (``tests/conftest.py``).
"""

from __future__ import annotations

import collections
import datetime
import hashlib
import importlib.util
import ipaddress
import json
import lzma
import pathlib
import tarfile
from dataclasses import dataclass, field
from typing import Any

import asn1core
import pytest
from asn1core.crl import parse_crl
from asn1core.extensions import parse_access_descriptions, parse_crl_distribution_points

from rpkit import resources as res
from rpkit.manifest import ManifestError, parse_manifest
from rpkit.roa import RoaError, Vrp, parse_roa_content
from rpkit.signedobject import SignedObjectError, decode_signed_object, verify_rsa_sha256
from rpkit.validation import validate_roa

TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "fetch_corpus.py"
REPO = "ripe-archive-afrinic-20261112-repo.tar.xz"
OPERATOR_DIGEST = "ripe-archive-afrinic-20261112-repo.tar.xz.sha256"
ROUTINATOR = "ripe-archive-afrinic-20261112-output.json.xz"
# Routinator's "generatedTime" in output.json for this run: the time of validation used here.
AT = datetime.datetime(2026, 11, 12, 5, 3, 21, tzinfo=datetime.UTC)
_AIA = "1.3.6.1.5.5.7.1.1"  # Authority Information Access
_CRLDP = "2.5.29.31"  # CRL Distribution Points
_CA_ISSUERS = (1, 3, 6, 1, 5, 5, 7, 48, 2)


def _tool() -> Any:
    spec = importlib.util.spec_from_file_location("rpkit_fetch_corpus", TOOL)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FETCH = _tool()


def corpus(name: str) -> pathlib.Path:
    """The cached file, checked against its pin; a loud skip when it is not there."""
    (entry,) = [e for e in FETCH.load_manifest() if e["name"] == name]
    path = FETCH.cached(entry)
    if path is None:
        pytest.skip(
            f"real-data corpus absent: {name} is not in {FETCH.cache_dir()} with its pinned "
            f"SHA-256; run `python tools/fetch_corpus.py` (or set {FETCH.ENV})"
        )
    return path


@dataclass
class Archive:
    ta: bytes
    trees: dict[str, dict[str, bytes]]


def load_archive(path: pathlib.Path) -> Archive:
    """The archive's trees as rsync URI -> bytes, and the trust anchor certificate."""
    trees: dict[str, dict[str, bytes]] = {"validated": {}, "unvalidated": {}}
    ta = b""
    with tarfile.open(path) as tar:
        for member in tar:
            if not member.isfile():
                continue
            parts = member.name.split("/")
            handle = tar.extractfile(member)
            assert handle is not None
            data = handle.read()
            if parts[5] == "ta":
                ta = data
            elif len(parts) > 8 and parts[6] in trees:
                trees[parts[6]]["rsync://" + "/".join(parts[8:])] = data
    return Archive(ta, trees)


def _rsync(values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value.startswith("rsync://"):
            return value
    return None


def issuer_uri(cert: asn1core.Certificate) -> str | None:
    ext = cert.extension(_AIA)
    if ext is None:
        return None
    return _rsync(
        ad.location.value for ad in parse_access_descriptions(ext.value) if ad.method == _CA_ISSUERS
    )


def crl_uri(cert: asn1core.Certificate) -> str | None:
    ext = cert.extension(_CRLDP)
    if ext is None:
        return None
    return _rsync(
        gn.value for dp in parse_crl_distribution_points(ext.value) for gn in dp.full_name or ()
    )


@dataclass
class Census:
    parsed: collections.Counter[str] = field(default_factory=collections.Counter)
    refused: collections.Counter[tuple[str, str]] = field(default_factory=collections.Counter)
    warnings: collections.Counter[tuple[str, str]] = field(default_factory=collections.Counter)
    outcomes: collections.Counter[str] = field(default_factory=collections.Counter)
    findings: collections.Counter[tuple[str, str]] = field(default_factory=collections.Counter)
    invalid: dict[str, tuple[str, ...]] = field(default_factory=dict)
    valid_uris: set[str] = field(default_factory=set)
    vrps: set[Vrp] = field(default_factory=set)


def _note(counter: collections.Counter[tuple[str, str]], kind: str, rule: str) -> None:
    counter[(kind, rule)] += 1


def take_census(archive: Archive) -> Census:
    objects = archive.trees["unvalidated"]
    ta = asn1core.parse_certificate(archive.ta)
    census = Census()
    certs: dict[str, asn1core.Certificate] = {}
    for uri, blob in objects.items():
        kind = uri.rsplit(".", 1)[-1]
        try:
            if kind == "cer":
                cert = asn1core.parse_certificate(blob)
                certs[uri] = cert
                for finding in res.profile_check(res.read_resources(cert)):
                    _note(census.warnings, kind, finding.rule)
            elif kind == "crl":
                parse_crl(blob)
            elif kind in ("roa", "mft"):
                signed = decode_signed_object(blob)
                for finding in verify_rsa_sha256(signed):
                    _note(census.refused, kind, finding.rule)
                content = (
                    parse_roa_content(signed.econtent)
                    if kind == "roa"
                    else parse_manifest(signed.econtent)
                )
                for finding in content.findings:
                    _note(census.warnings, kind, finding.rule)
            else:
                continue
        except (SignedObjectError, RoaError, ManifestError) as error:
            for finding in error.findings:
                _note(census.refused, kind, finding.rule)
            continue
        except (asn1core.Asn1Error, res.ResourceReadError, ValueError) as error:
            _note(census.refused, kind, type(error).__name__)
            continue
        census.parsed[kind] += 1
    for uri, blob in objects.items():
        if uri.endswith(".roa"):
            _validate(uri, blob, objects, certs, ta, census)
    return census


def _validate(
    uri: str,
    blob: bytes,
    objects: dict[str, bytes],
    certs: dict[str, asn1core.Certificate],
    ta: asn1core.Certificate,
    census: Census,
) -> None:
    try:
        cert = decode_signed_object(blob).ee_certificate
    except SignedObjectError:
        census.outcomes["not decoded"] += 1
        return
    chain: list[bytes] = []
    crls: list[bytes] = []
    for _ in range(16):
        where = crl_uri(cert)
        if where in objects:
            crls.append(objects[where])
        parent_uri = issuer_uri(cert)
        parent = certs.get(parent_uri or "")
        if parent is None and asn1core.names_equal(cert.issuer, ta.subject):
            parent = ta
        if parent is None:
            census.outcomes["no chain in the archive"] += 1
            return
        chain.insert(0, parent.raw)
        if parent.raw == ta.raw:
            break
        cert = parent
    result = validate_roa(blob, chain, crls, AT)
    census.outcomes["valid" if result.valid else "invalid"] += 1
    for finding in result.findings:
        _note(census.findings, str(finding.severity), finding.rule)
    if result.valid:
        census.valid_uris.add(uri)
        census.vrps.update(result.vrps)
    else:
        census.invalid[hashlib.sha256(blob).hexdigest()] = tuple(
            f.rule for f in result.findings if str(f.severity) == "error"
        )


@pytest.fixture(scope="module")
def archive() -> Archive:
    return load_archive(corpus(REPO))


@pytest.fixture(scope="module")
def census(archive: Archive) -> Census:
    return take_census(archive)


def test_manifest_pins_every_file_with_a_read_label():
    for entry in FETCH.load_manifest():
        assert entry["url"].startswith("https://"), entry["name"]
        assert len(entry["sha256"]) == 64, entry["name"]
        assert entry["size"] > 0, entry["name"]
        assert entry["read"] == "2026-11-13", entry["name"]
        assert "vendored" in entry["terms"], entry["name"]


def test_the_archive_operator_publishes_the_same_digest():
    published = corpus(OPERATOR_DIGEST).read_text(encoding="ascii").split()
    (entry,) = [e for e in FETCH.load_manifest() if e["name"] == REPO]
    assert published == [entry["sha256"], "repo.tar.xz"]


@pytest.mark.corpus
def test_every_fetched_object_parses(census: Census):
    """34,370 files fetched; every certificate, CRL, manifest and ROA parses and every signature verifies."""
    assert census.parsed == {"cer": 1491, "crl": 1574, "mft": 1585, "roa": 12652}
    assert census.refused == {}
    # RFC 9582 warnings on real ROAs: a maxLength equal to the prefix length, and a prefix twice
    assert census.warnings == {
        ("roa", "roa.maxlength-superfluous"): 33336,
        ("roa", "roa.duplicate-prefix"): 46,
    }


@pytest.mark.corpus
def test_validate_roa_outcomes_and_findings(census: Census):
    """Every ROA with a chain in the archive, validated at Routinator's generation time.

    The one invalid ROA (sha256 fb8d7398...) is signed by an EE certificate claiming
    102.219.68.0/22, which its issuer (CN=F367278DAF, IPv6 and AS328920 only) does not hold:
    a real overclaim (RFC 6487 section 7.2), which Routinator also rejected. The 59 without a
    chain sit in 15 publication points whose CA certificate is no longer in the repository: the
    EE's Authority Information Access names a certificate nobody publishes, so they are orphans.
    """
    assert census.outcomes == {"valid": 12592, "invalid": 1, "no chain in the archive": 59}
    assert census.findings == {
        ("warning", "roa.maxlength-superfluous"): 33266,
        ("warning", "roa.duplicate-prefix"): 46,
        ("error", "path.overclaim"): 1,
    }
    assert census.invalid == {
        "fb8d739873780c60ba6fdf557f2e590d490c923392698a5222adbaad21f5c381": ("path.overclaim",)
    }


@pytest.mark.corpus
def test_valid_roas_are_the_ones_routinator_kept(archive: Archive, census: Census):
    kept = {uri for uri in archive.trees["validated"] if uri.endswith(".roa")}
    # Routinator's validated tree also keeps the overclaiming ROA's file; it emits no VRP for it.
    assert kept - census.valid_uris == {
        "rsync://rpki.afrinic.net/repository/member_repository/F367278D/"
        "1D3860A0852A11EE9DCD1B734AD9E6FC/C450DAB0852B11EEA03755784AD9E6FC.roa"
    }
    assert census.valid_uris <= kept


@pytest.mark.corpus
def test_vrps_equal_routinators(census: Census):
    """The interop check: the VRP set equals Routinator's output.json for the same run, exactly."""
    data = json.loads(lzma.decompress(corpus(ROUTINATOR).read_bytes()))
    theirs = {
        (ipaddress.ip_network(r["prefix"]), r["maxLength"], int(r["asn"].removeprefix("AS")))
        for r in data["roas"]
    }
    ours = {(v.prefix, v.max_length, v.asn) for v in census.vrps}
    assert len(theirs) == 32842
    assert ours == theirs
