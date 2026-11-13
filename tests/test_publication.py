"""Which CRL applies: RFC 9829 section 2 and section 3.2, RFC 9286 section 6, RFC 6487 sections 4.8.6 and 4.8.7.

Row ``validation.crldp-aia-match``. No RFC prints bytes for any of this, so every case is built in
``rpkibuild.py`` and signed with a throwaway key. The PKI is the one of ``test_validation``: a trust
anchor TA, a CA below it and an EE certificate below that, each CA with a publication point.
"""

from __future__ import annotations

import datetime
import hashlib
from typing import Any

import pytest
from asn1core import parse_certificate
from cryptography import x509

from rpkit.manifest import FileEntry, Manifest
from rpkit.publication import (
    PublicationPoint,
    aia_findings,
    check_aia,
    crl_uris,
    crldp_findings,
    issuer_uris,
    select_crl,
)
from rpkit.validation import ValidationCache, validate_roa

from . import rpkibuild as b
from .test_validation import v4

NOW = b.NOW
TA_DIR = "rsync://rpki.example.net/ta/"
CA_DIR = "rsync://rpki.example.net/ca1/"
CA_CERT_URI = TA_DIR + "ca1.cer"
TA_CERT_URI = "rsync://rpki.example.net/ta.cer"


def rules(findings) -> list[str]:
    return sorted(f.rule for f in findings if f.severity.value == "error")


def manifest(files: dict[str, bytes], *, stale: bool = False, premature: bool = False) -> Manifest:
    this_update = NOW - datetime.timedelta(hours=1)
    next_update = NOW + datetime.timedelta(hours=23)
    if stale:
        this_update, next_update = (
            NOW - datetime.timedelta(days=3),
            NOW - datetime.timedelta(days=2),
        )
    if premature:
        this_update, next_update = (
            NOW + datetime.timedelta(days=1),
            NOW + datetime.timedelta(days=2),
        )
    return Manifest(
        number=7,
        this_update=this_update,
        next_update=next_update,
        hash_algorithm="2.16.840.1.101.3.4.2.1",
        files=tuple(FileEntry(n, hashlib.sha256(d).digest()) for n, d in files.items()),
    )


def point(uri: str, files: dict[str, bytes], **kw) -> PublicationPoint:
    return PublicationPoint(uri, manifest(files, **kw), dict(files))


def cert(**kw) -> bytes:
    return b.make_cert(b.CertSpec(**kw))


class World:
    """TA, CA1 and an EE, each certificate naming its issuer's CRL and certificate."""

    def __init__(self, *, ee_serial=300, ca_revoked=(), ta_revoked=(), ee_kw=None):
        self.ta = cert(
            subject="TA",
            issuer="TA",
            subject_key="ta",
            issuer_key="ta",
            ca=True,
            self_signed=True,
            ip=v4("10.0.0.0/8"),
        )
        self.ca = cert(
            subject="CA1",
            issuer="TA",
            subject_key="ca1",
            issuer_key="ta",
            serial=2,
            ca=True,
            ip=v4("10.1.0.0/16"),
            crl_uri=TA_DIR + "ta.crl",
            aia_uri=TA_CERT_URI,
        )
        spec = {
            "subject": "EE",
            "issuer": "CA1",
            "subject_key": "ee",
            "issuer_key": "ca1",
            "serial": ee_serial,
            "ip": v4("10.1.2.0/24"),
            "crl_uri": CA_DIR + "ca1.crl",
            "aia_uri": CA_CERT_URI,
        }
        spec.update(ee_kw or {})
        self.ee = cert(**spec)
        self.ta_crl = b.make_crl(issuer="TA", issuer_key="ta", revoked=ta_revoked)
        self.ca_crl = b.make_crl(issuer="CA1", issuer_key="ca1", revoked=ca_revoked)
        content = b.roa_content(64500, [(1, [("10.1.2.0/24", 24)])])
        self.roa = b.make_signed_object(ee_cert=self.ee, content_type=b.ID_CT_ROA, econtent=content)

    def points(self, **kw):
        ta_point = PublicationPoint(
            TA_DIR,
            manifest({"ta.crl": self.ta_crl, "ca1.cer": self.ca}),
            {"ta.crl": self.ta_crl, "ca1.cer": self.ca},
            certificate_uri=TA_CERT_URI,
        )
        ca_point = PublicationPoint(
            CA_DIR,
            manifest({"ca1.crl": self.ca_crl, "x.roa": self.roa}, **kw),
            {"ca1.crl": self.ca_crl, "x.roa": self.roa},
            certificate_uri=CA_CERT_URI,
        )
        return {_ski(self.ta): ta_point, _ski(self.ca): ca_point}

    def validate(self, points, **kw):
        return validate_roa(self.roa, [self.ta, self.ca], [], NOW, publication_points=points, **kw)


def _ski(der: bytes) -> bytes:
    ext = x509.load_der_x509_certificate(der).extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    )
    return ext.value.digest


# -- the two extensions ---------------------------------------------------------------------------------------


def test_a_conforming_certificate_has_no_crldp_or_aia_findings():
    world = World()
    ee = parse_certificate(world.ee)
    assert crldp_findings(ee) == ()
    assert aia_findings(ee) == ()
    assert crl_uris(ee) == (CA_DIR + "ca1.crl",)
    assert issuer_uris(ee) == (CA_CERT_URI,)


def test_a_self_signed_certificate_must_omit_both():
    ta = parse_certificate(World().ta)
    assert crldp_findings(ta) == ()
    assert aia_findings(ta) == ()


def test_a_certificate_without_the_extensions_is_refused():
    plain = parse_certificate(cert(crl_uri=None))
    assert rules(crldp_findings(plain)) == ["crldp.missing"]
    assert rules(aia_findings(plain)) == ["aia.missing"]


def point_of(uri: str, **kw) -> x509.DistributionPoint:
    args: dict[str, Any] = {
        "full_name": [x509.UniformResourceIdentifier(uri)],
        "relative_name": None,
        "reasons": None,
        "crl_issuer": None,
    }
    args.update(kw)
    return x509.DistributionPoint(**args)


@pytest.mark.parametrize(
    ("override", "critical", "expected"),
    [
        (x509.CRLDistributionPoints([point_of("rsync://h/a.crl")]), True, ["crldp.critical"]),
        (
            x509.CRLDistributionPoints([point_of("rsync://h/a.crl"), point_of("rsync://h/b.crl")]),
            False,
            ["crldp.distribution-points"],
        ),
        (
            x509.CRLDistributionPoints(
                [point_of("rsync://h/a.crl", reasons=frozenset([x509.ReasonFlags.key_compromise]))]
            ),
            False,
            ["crldp.reasons"],
        ),
        (
            x509.CRLDistributionPoints(
                [point_of("rsync://h/a.crl", crl_issuer=[x509.DNSName("example.net")])]
            ),
            False,
            ["crldp.crl-issuer"],
        ),
        (
            x509.CRLDistributionPoints(
                [point_of("rsync://h/a.crl", full_name=[x509.DNSName("h")])]
            ),
            False,
            ["crldp.name-form", "crldp.no-rsync"],
        ),
        (
            x509.CRLDistributionPoints([point_of("https://h/a.crl")]),
            False,
            ["crldp.no-rsync"],
        ),
        (
            x509.CRLDistributionPoints(
                [
                    point_of(
                        "https://h/a.crl",
                        full_name=[
                            x509.UniformResourceIdentifier("rsync://h/a.crl"),
                            x509.UniformResourceIdentifier("https://h/a.crl"),
                        ],
                    )
                ]
            ),
            False,
            [],
        ),
    ],
)
def test_each_crldp_rule_of_rfc_6487_section_4_8_6_is_enforced(override, critical, expected):
    der = cert(crldp_override=override, crldp_critical=critical)
    assert rules(crldp_findings(parse_certificate(der))) == expected


def test_aia_rules_of_rfc_6487_section_4_8_7():
    critical = parse_certificate(cert(aia_uri="rsync://h/ta.cer", aia_critical=True))
    assert rules(aia_findings(critical)) == ["aia.critical"]
    https = parse_certificate(cert(aia_uri="https://h/ta.cer"))
    assert rules(aia_findings(https)) == ["aia.no-rsync"]


def test_the_aia_must_name_where_the_issuer_certificate_was_fetched_from():
    ee = parse_certificate(World().ee)
    assert check_aia(ee, CA_CERT_URI) == ()
    assert rules(check_aia(ee, "rsync://rpki.example.net/other/ca1.cer")) == ["aia.mismatch"]


# -- select_crl --------------------------------------------------------------------------------------------


def test_the_crl_named_by_the_crldp_and_listed_with_its_hash_is_selected():
    world = World()
    ee = parse_certificate(world.ee)
    choice = select_crl(ee, point(CA_DIR, {"ca1.crl": world.ca_crl, "x.roa": world.roa}), NOW)
    assert choice.valid
    assert choice.uri == CA_DIR + "ca1.crl"
    assert choice.crl == world.ca_crl


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("not-listed", ["crl.not-listed"]),
        ("hash", ["crl.hash-mismatch"]),
        ("not-fetched", ["crl.not-fetched"]),
        ("elsewhere", ["crl.elsewhere"]),
        ("subdirectory", ["crl.elsewhere"]),
        ("stale", ["manifest.stale"]),
        ("premature", ["manifest.premature"]),
    ],
)
def test_a_crl_the_manifest_does_not_vouch_for_is_not_selected(scenario, expected):
    world = World()
    ee = parse_certificate(world.ee)
    files = {"ca1.crl": world.ca_crl}
    kw = {}
    if scenario == "not-listed":
        listed = {"other.crl": world.ta_crl}
        pp = PublicationPoint(CA_DIR, manifest(listed), {"ca1.crl": world.ca_crl})
    elif scenario == "hash":
        pp = PublicationPoint(CA_DIR, manifest(files), {"ca1.crl": world.ta_crl})
    elif scenario == "not-fetched":
        pp = PublicationPoint(CA_DIR, manifest(files), {})
    elif scenario == "elsewhere":
        pp = point("rsync://rpki.example.net/elsewhere/", files)
    elif scenario == "subdirectory":
        pp = point("rsync://rpki.example.net/", {"ca1/ca1.crl": world.ca_crl})
    else:
        kw = {scenario: True}
        pp = point(CA_DIR, files, **kw)
    choice = select_crl(ee, pp, NOW)
    assert rules(choice.findings) == expected
    assert not choice.valid
    if scenario in ("stale", "premature"):
        assert choice.crl == world.ca_crl  # the CRL is right; the manifest is not current
    else:
        assert choice.crl is None


def test_the_time_is_only_looked_at_when_given():
    world = World()
    ee = parse_certificate(world.ee)
    assert select_crl(ee, point(CA_DIR, {"ca1.crl": world.ca_crl}, stale=True)).valid
    with pytest.raises(ValueError, match="timezone-aware"):
        select_crl(ee, point(CA_DIR, {"ca1.crl": world.ca_crl}), datetime.datetime(2026, 1, 1))


def test_two_uris_selecting_different_crls_are_ambiguous():
    world = World()
    two = x509.CRLDistributionPoints(
        [
            point_of(
                CA_DIR + "a.crl",
                full_name=[
                    x509.UniformResourceIdentifier(CA_DIR + "a.crl"),
                    x509.UniformResourceIdentifier(CA_DIR + "b.crl"),
                ],
            )
        ]
    )
    ee = parse_certificate(cert(crldp_override=two))
    both = point(CA_DIR, {"a.crl": world.ca_crl, "b.crl": world.ta_crl})
    choice = select_crl(ee, both, NOW)
    assert rules(choice.findings) == ["crl.ambiguous"]
    same = point(CA_DIR, {"a.crl": world.ca_crl, "b.crl": world.ca_crl})
    assert select_crl(ee, same, NOW).valid


def test_a_certificate_with_no_rsync_crl_has_none_selected():
    ee = parse_certificate(cert(crl_uri="https://h/x.crl"))
    assert rules(select_crl(ee, point(CA_DIR, {}), NOW).findings) == ["crl.no-uri"]


# -- validate_roa with publication points -----------------------------------------------------------------


def test_a_roa_validates_when_every_crl_is_the_one_its_manifest_selects():
    world = World()
    result = world.validate(world.points())
    assert result.valid, [str(f) for f in result.findings]
    assert [str(v.prefix) for v in result.vrps] == ["10.1.2.0/24"]


def test_a_serial_on_the_selected_crl_is_revoked():
    world = World(ca_revoked=(300,))
    result = world.validate(world.points())
    assert rules(result.findings) == ["path.revoked"]
    assert result.vrps == ()


def test_a_crl_that_the_manifest_does_not_list_is_not_consulted_even_if_it_is_valid():
    """The old rule (any CRL under the issuer's name) would accept the supplied one; RFC 9829 does not."""
    world = World()
    points = world.points()
    unlisted = PublicationPoint(CA_DIR, manifest({"x.roa": world.roa}), {"ca1.crl": world.ca_crl})
    points[_ski(world.ca)] = unlisted
    assert world.validate(points, cache=ValidationCache()).valid is False
    found = rules(world.validate(points).findings)
    assert found == ["crl.not-listed", "path.crl-missing"]
    old = validate_roa(world.roa, [world.ta, world.ca], [world.ta_crl, world.ca_crl], NOW)
    assert old.valid


def test_an_issuer_without_a_publication_point_cannot_be_validated_under():
    world = World()
    points = world.points()
    del points[_ski(world.ca)]
    assert rules(world.validate(points).findings) == ["path.manifest-missing"]


def test_a_stale_manifest_fails_the_certificate_it_vouches_for():
    world = World()
    assert rules(world.validate(world.points(stale=True)).findings) == ["manifest.stale"]


def test_the_aia_is_checked_against_where_the_issuer_certificate_came_from():
    world = World(ee_kw={"aia_uri": "rsync://rpki.example.net/ca1/other.cer"})
    assert rules(world.validate(world.points()).findings) == ["aia.mismatch"]


def test_a_certificate_missing_its_extensions_is_refused_in_this_mode_only():
    world = World(ee_kw={"crl_uri": None, "aia_uri": None})
    found = rules(world.validate(world.points()).findings)
    assert found == ["aia.missing", "crl.no-uri", "crldp.missing", "path.crl-missing"]


# -- the cache ------------------------------------------------------------------------------------------------


def test_a_cache_changes_when_the_work_is_done_and_never_the_answer(monkeypatch):
    import rpkit.validation as validation

    world = World(ca_revoked=(300,))
    calls = {"crl": 0}
    real = validation.check_crl

    def counting(*args, **kw):
        calls["crl"] += 1
        return real(*args, **kw)

    monkeypatch.setattr(validation, "check_crl", counting)
    shared = ValidationCache()
    first = world.validate(world.points(), cache=shared)
    after_first = calls["crl"]
    second = world.validate(world.points(), cache=shared)
    assert second == first
    assert calls["crl"] == after_first, "the second ROA reused both CRL checks"
    fresh = world.validate(world.points())
    assert fresh == first
    assert calls["crl"] == after_first + after_first
    assert rules(first.findings) == ["path.revoked"]


def test_a_cache_keeps_a_crl_result_per_time():
    world = World()
    cache = ValidationCache()
    ta = parse_certificate(world.ta)
    early = cache.crl(world.ta_crl, [ta], NOW)
    late = cache.crl(world.ta_crl, [ta], NOW + datetime.timedelta(days=30))
    assert early.valid
    assert [f.rule for f in late.findings] == ["crl.stale"]
