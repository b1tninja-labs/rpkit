"""trust anchor locators and TAKs: parse, load (RFC 8630; RFC 9691 is the TAK object, a later row).

A Trust Anchor Locator is the one RPKI input a relying party is configured with rather than fetches,
so everything that follows trusts what this module accepted. `parse_tal` is therefore strict:
it refuses a file that departs from the RFC 8630 section 2.2 format instead of guessing what the
operator meant, and it never returns a partial `Tal`.

What this module does **not** do, on purpose: fetch a TA URI (section 3 step 1, and RFC 8630
section 4 makes TLS validation of HTTPS URIs a fetch-layer duty), and compare the TAL key with the
retrieved certificate (section 3 step 3). Those are separate rows in ROADMAP.md because they need
the repository and certificate layers. The TAK profile of RFC 9691 is a different object, a signed
CMS structure, and is also its own row; RFC 7730 is obsoleted by RFC 8630 and is never cited.
"""

from __future__ import annotations

import base64
import binascii
import pathlib
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass

from asn1core import Asn1Error, TagClass, decode

__all__ = [
    "MAX_TAL_BYTES",
    "Tal",
    "TalError",
    "load_trust_anchor",
    "parse_tal",
]

# A real TAL is under 1 KiB. The cap exists so a hostile file is refused before it is decoded.
MAX_TAL_BYTES = 64 * 1024

_LINE_BREAK = re.compile(r"\r\n|\n")
_TA_SCHEMES = frozenset({"rsync", "https"})


class TalError(ValueError):
    """The bytes are not a Trust Anchor Locator under RFC 8630 section 2.2."""


@dataclass(frozen=True, slots=True)
class Tal:
    """A parsed Trust Anchor Locator.

    ``comments`` are the comment lines without their leading ``#``, ``uris`` the TA URIs in the
    order the file gave them (RFC 8630 section 3 leaves preference to the relying party), and
    ``spki_der`` the DER ``subjectPublicKeyInfo`` the file carried, exactly as decoded.
    """

    comments: tuple[str, ...]
    uris: tuple[str, ...]
    spki_der: bytes


def parse_tal(raw: bytes) -> Tal:
    """Parse a Trust Anchor Locator as RFC 8630 section 2.2 defines it.

    The format is an optional run of ``#`` comment lines, one or more TA URI lines, one blank
    line, then a base64 DER subjectPublicKeyInfo that may be wrapped across lines. Line breaks are
    CRLF or LF. Every TA URI must be an rsync or HTTPS URI naming a single object (section 2.2,
    section 2.3). Comment text is UTF-8 under the RFC 5198 section 2 restrictions: C1 controls, a
    byte order mark and a bare CR are refused as the RFC requires, and so are NUL and the other C0
    controls except TAB, which RFC 5198 says SHOULD be avoided and which has no place in a trust
    anchor file.

    Raises:
        TalError: on every departure from the format, including a key that is not one complete DER
            SEQUENCE. Nothing is returned for a file that is only partly valid.
    """
    if len(raw) > MAX_TAL_BYTES:
        raise TalError(f"TAL is {len(raw)} bytes, over the {MAX_TAL_BYTES} byte cap")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TalError("TAL is not valid UTF-8") from error
    if text.startswith("﻿"):
        raise TalError("TAL starts with a byte order mark, which RFC 5198 section 2 forbids")
    lines = _LINE_BREAK.split(text)
    if "\r" in "".join(lines):
        raise TalError("a bare CR is not a line break (RFC 5198 section 2)")
    if lines and lines[-1] == "":
        lines.pop()  # the file's final line break

    cursor = 0
    comments: list[str] = []
    while cursor < len(lines) and lines[cursor].startswith("#"):
        comments.append(_comment(lines[cursor][1:]))
        cursor += 1

    uris: list[str] = []
    while cursor < len(lines) and lines[cursor] != "":
        uris.append(_ta_uri(lines[cursor]))
        cursor += 1
    if not uris:
        raise TalError("TAL has no TA URI line")
    if cursor == len(lines):
        raise TalError("TAL has no blank line after the URI section")
    cursor += 1  # the blank line

    key_lines = lines[cursor:]
    if not key_lines:
        raise TalError("TAL has no subjectPublicKeyInfo after the blank line")
    if "" in key_lines:
        raise TalError("blank line inside the base64 subjectPublicKeyInfo")
    return Tal(tuple(comments), tuple(uris), _spki("".join(key_lines)))


def _comment(text: str) -> str:
    for char in text:
        category = unicodedata.category(char)
        if category == "Cn":
            raise TalError(f"comment holds unassigned code point U+{ord(char):04X} (RFC 5198)")
        if category == "Cc" and char != "\t":
            raise TalError(
                f"comment holds control character U+{ord(char):04X} (RFC 5198 section 2)"
            )
    return text


def _ta_uri(line: str) -> str:
    if any(char.isspace() or unicodedata.category(char) in ("Cc", "Cn") for char in line):
        raise TalError("TA URI holds whitespace or a control character")
    parts = urllib.parse.urlsplit(line)
    if parts.scheme.lower() not in _TA_SCHEMES:
        raise TalError(f"TA URI scheme {parts.scheme!r} is neither rsync nor https (RFC 8630 2.2)")
    if not parts.netloc or not line[len(parts.scheme) :].startswith("://"):
        raise TalError("TA URI has no authority")
    if not parts.path or parts.path.endswith("/"):
        raise TalError("TA URI does not name a single object (RFC 8630 section 2.3)")
    return line


def _spki(encoded: str) -> bytes:
    try:
        der = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise TalError("subjectPublicKeyInfo is not valid base64 (RFC 4648 section 4)") from error
    if base64.b64encode(der).decode("ascii") != encoded:
        raise TalError("base64 is not canonical: padding or trailing bits are wrong")
    if not der:
        raise TalError("subjectPublicKeyInfo is empty")
    try:
        node, end = decode(der, der=True)
    except Asn1Error as error:
        raise TalError(f"subjectPublicKeyInfo is not DER: {error}") from error
    if end != len(der):
        raise TalError("subjectPublicKeyInfo is followed by extra bytes")
    tag = node.tag
    if tag.number != 16 or not tag.constructed or tag.tag_class != TagClass.universal:
        raise TalError("subjectPublicKeyInfo is not a SEQUENCE")
    return der


def load_trust_anchor(path: pathlib.Path) -> Tal:
    """Read a TAL file and parse it under RFC 8630 section 2.2.

    A missing or unreadable file raises ``OSError`` from the open, unchanged. At most one byte over
    the size cap is read, so a huge file is refused without being loaded.

    Raises:
        TalError: the contents are not a TAL (see `parse_tal`).
        OSError: the file cannot be read.
    """
    with path.open("rb") as handle:
        raw = handle.read(MAX_TAL_BYTES + 1)
    return parse_tal(raw)
