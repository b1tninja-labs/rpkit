"""Manifest eContent, file checks and replay (RFC 9286 sections 4.2 to 4.4, erratum 7118, RFC 9981 section 2).

Content is built in ``rpkibuild.py``; the RFC prints no byte vector. The file name example is the
RFC's own (section 4.2.2: ``vixxBTS_TVXQ-2pmGOT7.cer`` is a valid name).
"""

from __future__ import annotations

import datetime
import hashlib

import pytest

from rpkit.findings import Severity
from rpkit.manifest import (
    FileEntry,
    Manifest,
    ManifestError,
    check_manifest,
    check_replay,
    parse_manifest,
)

from . import rpkibuild as b

T0 = b.NOW
T1 = T0 + datetime.timedelta(days=1)


def h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def content(**kw) -> bytes:
    files = kw.pop("files", [("a.roa", h(b"a")), ("ca.crl", h(b"crl"))])
    return b.manifest_content(
        kw.pop("number", 7), kw.pop("this", T0), kw.pop("next", T1), files, **kw
    )


def test_a_conforming_manifest_parses():
    m = parse_manifest(content())
    assert m.number == 7
    assert (m.this_update, m.next_update) == (T0, T1)
    assert m.hash_algorithm == b.ID_SHA256
    assert [f.name for f in m.files] == ["a.roa", "ca.crl"]
    assert m.files[0].hash == h(b"a")
    assert m.findings == ()


def test_the_rfc_example_file_name_is_valid_and_a_twenty_octet_number_is_allowed():
    big = 2**159 - 1
    m = parse_manifest(content(number=big, files=[("vixxBTS_TVXQ-2pmGOT7.cer", h(b"x"))]))
    assert m.number == big
    assert m.files[0].name == "vixxBTS_TVXQ-2pmGOT7.cer"


@pytest.mark.parametrize(
    ("data", "rule"),
    [
        (content(version=0), "manifest.version"),
        (content(number=2**160), "manifest.number"),
        (content(next=T0), "manifest.times"),
        (content(next=T0 - datetime.timedelta(seconds=1)), "manifest.times"),
        (content(hash_alg="2.16.840.1.101.3.4.2.2"), "manifest.hash-algorithm"),
        (content(files=[]), "manifest.empty"),
        (content(files=[("a.roa", b"short")]), "manifest.hash"),
        (content(files=[("a.roa", h(b"a"))], hash_unused=1), "manifest.der"),
        (content(files=[("a b.roa", h(b"a"))]), "manifest.file-name"),
        (content(files=[("a.roas", h(b"a"))]), "manifest.file-name"),
        (content(files=[("noextension", h(b"a"))]), "manifest.file-name"),
        (content(files=[("dir/a.roa", h(b"a"))]), "manifest.file-name"),
        (content(files=[("a.roa", h(b"a")), ("a.roa", h(b"b"))]), "manifest.duplicate-file"),
        (content() + b"\x00", "manifest.trailing"),
        (b"\x30\x80\x00\x00", "manifest.der"),
        (b.seq(b.integer(1)), "manifest.structure"),
    ],
)
def test_content_the_profile_forbids_is_refused_with_the_rule_named(data, rule):
    with pytest.raises(ManifestError) as raised:
        parse_manifest(data)
    assert rule in [f.rule for f in raised.value.findings]
    assert all(f.severity is Severity.ERROR for f in raised.value.findings)


def test_negative_manifest_number_is_refused():
    data = b.seq(
        b.integer(-1),
        b.generalized(T0),
        b.generalized(T1),
        b.oid(b.ID_SHA256),
        b.seq(b.seq(b.ia5("a.roa"), b.bit_string(h(b"a")))),
    )
    with pytest.raises(ManifestError, match="negative"):
        parse_manifest(data)


def test_utc_time_in_place_of_generalized_time_is_refused():
    data = b.seq(
        b.integer(1),
        b.utc_time(T0),
        b.utc_time(T1),
        b.oid(b.ID_SHA256),
        b.seq(b.seq(b.ia5("a.roa"), b.bit_string(h(b"a")))),
    )
    with pytest.raises(ManifestError, match="GeneralizedTime"):
        parse_manifest(data)


def test_an_unknown_extension_is_a_warning_only():
    m = parse_manifest(content(files=[("a.xyz", h(b"a"))]))
    assert [f.rule for f in m.findings] == ["manifest.extension"]
    assert m.findings[0].severity is Severity.WARNING


def test_check_manifest_reports_missing_mismatched_and_unlisted_files():
    m = parse_manifest(content(files=[("a.roa", h(b"a")), ("b.roa", h(b"b")), ("c.cer", h(b"c"))]))
    assert check_manifest(m, {"a.roa": b"a", "b.roa": b"b", "c.cer": b"c"}) == []
    got = check_manifest(m, {"a.roa": b"a", "b.roa": b"CHANGED", "z.roa": b"z", "y.cer": b"y"})
    assert got == ["hash mismatch: b.roa", "missing: c.cer", "unlisted: y.cer", "unlisted: z.roa"]


def manifest(number: int, this: datetime.datetime) -> Manifest:
    return Manifest(
        number, this, this + datetime.timedelta(days=1), b.ID_SHA256, (FileEntry("a.roa", h(b"a")),)
    )


def test_replay_needs_a_higher_number_and_a_later_this_update():
    old = manifest(5, T0)
    assert check_replay(None, old) == ()
    assert check_replay(old, manifest(6, T1)) == ()
    assert [f.rule for f in check_replay(old, manifest(5, T1))] == ["manifest.number-not-higher"]
    assert [f.rule for f in check_replay(old, manifest(4, T1))] == ["manifest.number-not-higher"]
    assert [f.rule for f in check_replay(old, manifest(6, T0))] == [
        "manifest.this-update-not-later"
    ]
    both = check_replay(old, manifest(1, T0))
    assert [f.rule for f in both] == [
        "manifest.number-not-higher",
        "manifest.this-update-not-later",
    ]
    assert all(f.severity is Severity.ERROR for f in both)


def test_a_new_file_name_skips_the_number_check_but_alerts_and_keeps_the_time_check():
    # RFC 9981 section 2: the number check is momentarily omitted; thisUpdate still protects against replay.
    old = manifest(900, T0)
    got = check_replay(old, manifest(1, T1), filename_changed=True)
    assert [(f.rule, f.severity) for f in got] == [("manifest.filename-changed", Severity.WARNING)]
    stale = check_replay(old, manifest(1, T0), filename_changed=True)
    assert [f.rule for f in stale] == [
        "manifest.filename-changed",
        "manifest.this-update-not-later",
    ]
