"""Manifest eContent, file checks and the replay checks (RFC 9286, RFC 9981).

``parse_manifest`` reads the DER eContent of RFC 9286 section 4.2 and refuses what the profile
forbids. Read through rfclib on 2026-11-13: RFC 9286 sections 4.2 to 4.4; erratum 7118 (verified)
says the ASN.1 of Appendix A should read ``SIZE (1..MAX)`` for fileList, because section 7 says a CA's
manifest always has at least one entry, so an empty fileList is refused here although section 4.2
as printed says ``SIZE (0..MAX)``. RFC 9981 section 2 changes the replay rule: a new manifest under
a different file name is not refused for a lower manifestNumber, and the relying party must alert.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from asn1core import (
    Asn1Error,
    Tag,
    TagClass,
    check_bit_string,
    check_generalized_time,
    check_integer,
    check_oid,
    decode,
)

from .findings import Finding, Severity

if TYPE_CHECKING:
    import datetime
    from typing import Any

    SignedObject = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "ID_SHA256",
    "MAX_MANIFEST_NUMBER",
    "FileEntry",
    "Manifest",
    "ManifestError",
    "check_manifest",
    "check_replay",
    "parse_manifest",
]

ID_SHA256 = "2.16.840.1.101.3.4.2.1"
MAX_MANIFEST_NUMBER = 2**159 - 1  # RFC 9981 section 1: the largest 20-octet value
_SEQ = Tag(16, True, TagClass.universal)
_NAME = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z]{3}")
_KNOWN_EXTENSIONS = frozenset({"cer", "crl", "gbr", "mft", "roa"})


class ManifestError(ValueError):
    """A manifest eContent RFC 9286 does not allow; ``findings`` lists every error found."""

    def __init__(self, findings: tuple[Finding, ...]) -> None:
        super().__init__("; ".join(str(f) for f in findings))
        self.findings = findings


@dataclass(frozen=True, slots=True)
class FileEntry:
    """One FileAndHash: the file name and its hash octets."""

    name: str
    hash: bytes


@dataclass(frozen=True, slots=True)
class Manifest:
    """A parsed manifest (RFC 9286 section 4.2); ``findings`` holds warnings only."""

    number: int
    this_update: datetime.datetime
    next_update: datetime.datetime
    hash_algorithm: str
    files: tuple[FileEntry, ...]
    findings: tuple[Finding, ...] = ()


def _err(rule: str, message: str, spec: str = "RFC 9286 section 4.2") -> Finding:
    return Finding(Severity.ERROR, rule, message, spec)


def parse_manifest(econtent: bytes) -> Manifest:
    """Parse the DER eContent of a manifest and apply the checks of RFC 9286 sections 4.2 and 4.4.

    Refused with :class:`ManifestError`: anything not DER; octets after the SEQUENCE; a version
    that is encoded (it must be 0, the DEFAULT, which DER omits, X.690 section 11.5); a negative
    manifestNumber or one over 20 octets; times that are not GeneralizedTime in the RFC 5280 form;
    nextUpdate not later than thisUpdate (section 4.4 check 3); a hash algorithm other than
    SHA-256 (RFC 7935); an empty fileList (erratum 7118); a hash that is not a 256-bit BIT STRING;
    a file name outside ``[A-Za-z0-9_-]+`` plus a dot and three letters (section 4.2.2); the same
    name twice (a policy: the RFC is silent). An extension outside cer, crl, gbr, mft and roa is a
    warning: the IANA registry that section 4.2.2 names was not read.
    """
    try:
        top, end = decode(econtent, der=True)
    except Asn1Error as error:
        raise ManifestError((_err("manifest.der", str(error), "RFC 6488 section 2"),)) from error
    if end != len(econtent):
        raise ManifestError(
            (_err("manifest.trailing", f"{len(econtent) - end} octets follow the manifest"),)
        )
    items = list(top.children)
    if top.tag != _SEQ or not items:
        raise ManifestError((_err("manifest.structure", "Manifest is not a SEQUENCE"),))
    if items[0].tag.is_context(0):
        raise ManifestError(
            (
                _err(
                    "manifest.version",
                    "version is encoded; it must be 0, the DEFAULT, which DER omits",
                    "RFC 9286 section 4.2.1, X.690 section 11.5",
                ),
            )
        )
    if len(items) != 5 or items[0].tag != Tag(2) or items[3].tag != Tag(6) or items[4].tag != _SEQ:
        raise ManifestError(
            (
                _err(
                    "manifest.structure",
                    "expected number, thisUpdate, nextUpdate, fileHashAlg, fileList",
                ),
            )
        )
    problems: list[Finding] = []
    try:
        number = check_integer(items[0].payload or b"")
        if number < 0:
            problems.append(
                _err("manifest.number", "manifestNumber is negative", "RFC 9286 section 4.2.1")
            )
        if len(items[0].payload or b"") > 20:
            problems.append(
                _err(
                    "manifest.number",
                    "manifestNumber is longer than 20 octets",
                    "RFC 9286 section 4.2.1",
                )
            )
        times = []
        for node in items[1:3]:
            if node.tag != Tag(24):
                raise Asn1Error("thisUpdate and nextUpdate must be GeneralizedTime")
            times.append(check_generalized_time(node.payload or b""))
        algorithm = ".".join(map(str, check_oid(items[3].payload or b"")))
    except Asn1Error as error:
        raise ManifestError((_err("manifest.der", str(error)),)) from error
    this_update, next_update = times
    if next_update <= this_update:
        problems.append(
            _err("manifest.times", "nextUpdate does not follow thisUpdate", "RFC 9286 section 4.4")
        )
    if algorithm != ID_SHA256:
        problems.append(
            _err(
                "manifest.hash-algorithm",
                f"fileHashAlg {algorithm} is not SHA-256",
                "RFC 9286 section 4.2.1, RFC 7935",
            )
        )
    entries: list[FileEntry] = []
    warns: list[Finding] = []
    if not items[4].children:
        problems.append(_err("manifest.empty", "fileList is empty", "RFC 9286 erratum 7118"))
    for node in items[4].children:
        parts = node.children
        if node.tag != _SEQ or len(parts) != 2 or parts[0].tag != Tag(22) or parts[1].tag != Tag(3):
            problems.append(
                _err("manifest.structure", "FileAndHash is not { IA5String, BIT STRING }")
            )
            continue
        try:
            name = (parts[0].payload or b"").decode("ascii")
            unused, digest = check_bit_string(parts[1].payload or b"")
        except (UnicodeDecodeError, Asn1Error) as error:
            problems.append(_err("manifest.der", str(error)))
            continue
        if _NAME.fullmatch(name) is None:
            problems.append(
                _err(
                    "manifest.file-name",
                    f"{name!r} is not name.xxx of [A-Za-z0-9_-]",
                    "RFC 9286 section 4.2.2",
                )
            )
            continue
        if unused or len(digest) != 32:
            problems.append(
                _err(
                    "manifest.hash",
                    f"hash of {name} is not a 256-bit BIT STRING",
                    "RFC 9286 section 4.2.1",
                )
            )
            continue
        if any(e.name == name for e in entries):
            problems.append(_err("manifest.duplicate-file", f"{name} is listed twice", "policy"))
            continue
        if name.rsplit(".", 1)[1].lower() not in _KNOWN_EXTENSIONS:
            warns.append(
                Finding(
                    Severity.WARNING,
                    "manifest.extension",
                    f"{name}: extension is not one of cer, crl, gbr, mft, roa",
                    "RFC 9286 section 4.2.2",
                )
            )
        entries.append(FileEntry(name, digest))
    if problems:
        raise ManifestError(tuple(problems))
    return Manifest(number, this_update, next_update, algorithm, tuple(entries), tuple(warns))


def check_manifest(manifest: SignedObject, files: dict) -> list[str]:
    """Compare a parsed :class:`Manifest` with the files fetched (RFC 9286 sections 4.2 and 6).

    ``files`` maps file name to content. Returns one line per problem, in manifest order and
    then in name order: ``missing: NAME`` for a listed file not fetched, ``hash mismatch: NAME``
    for one whose SHA-256 differs, ``unlisted: NAME`` for a fetched file the manifest does not
    list. An empty list means the fetched set is exactly the listed set. Hashes are SHA-256,
    the only algorithm :func:`parse_manifest` admits.
    """
    problems: list[str] = []
    listed = {entry.name for entry in manifest.files}
    for entry in manifest.files:
        if entry.name not in files:
            problems.append(f"missing: {entry.name}")
        elif hashlib.sha256(files[entry.name]).digest() != entry.hash:
            problems.append(f"hash mismatch: {entry.name}")
    problems.extend(f"unlisted: {name}" for name in sorted(set(files) - listed))
    return problems


def check_replay(
    previous: Manifest | None, new: Manifest, *, filename_changed: bool = False
) -> tuple[Finding, ...]:
    """The two replay checks of RFC 9286 section 4.2.1 as RFC 9981 section 2 amends them.

    ``new`` must have a higher manifestNumber than ``previous``, except that a manifest under a
    different file name (``filename_changed``) is not refused for that, and the relying party
    must alert operators: that is a WARNING finding. ``new.this_update`` must be later than
    ``previous.this_update`` in every case, which is what protects against replay once the
    number check is skipped. A failed check is an ERROR; per section 4.2.1 the relying party then
    uses its cached objects. With no ``previous`` there is nothing to compare.

    This is the whole of RFC 9981 section 2 for a relying party. The issuer side (which number
    follows 2^159-1) is not defined by RFC 9981, so rpkit has no issuer function for it.
    """
    if previous is None:
        return ()
    found: list[Finding] = []
    if filename_changed:
        found.append(
            Finding(
                Severity.WARNING,
                "manifest.filename-changed",
                "the manifest file name changed: the stored manifestNumber is reset, alert operators",
                "RFC 9981 section 2",
            )
        )
    elif new.number <= previous.number:
        found.append(
            _err(
                "manifest.number-not-higher",
                f"manifestNumber {new.number} is not higher than {previous.number}",
                "RFC 9286 section 4.2.1",
            )
        )
    if new.this_update <= previous.this_update:
        found.append(
            _err(
                "manifest.this-update-not-later",
                "thisUpdate is not more recent than the previously validated manifest",
                "RFC 9286 section 4.2.1",
            )
        )
    return tuple(found)
