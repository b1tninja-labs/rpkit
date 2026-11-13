"""RFC 8630 section 2.2: the Trust Anchor Locator format, with the RFC's own example as the vector.

`tests/data/rfc8630-section-2.4.tal` is the section 2.4 example copied from rfclib on 2026-11-13
(the RFC's 11-space indent removed, LF line endings). It is a documentation-only key; the SPKI is
294 bytes, a 2048-bit RSA key. RFC 8630 has no errata (rfclib, 2026-11-13). Hostile inputs are
derived from the section 2.2 rules and from RFC 5198 section 2, not from the parser.
"""

from __future__ import annotations

import base64
import pathlib

import pytest

from rpkit.anchors import MAX_TAL_BYTES, Tal, TalError, load_trust_anchor, parse_tal

DATA = pathlib.Path(__file__).parent / "data" / "rfc8630-section-2.4.tal"
EXAMPLE = DATA.read_bytes()
KEY_B64 = EXAMPLE.decode().split("\n\n", 1)[1].replace("\n", "")
URI = "rsync://rpki.example.org/rpki/hedgehog/root.cer"


def tal(*, comments: str = "", uris: str = URI + "\n", key: str = KEY_B64) -> bytes:
    return (comments + uris + "\n" + key + "\n").encode()


def test_parse_tal_rfc_example() -> None:
    parsed = parse_tal(EXAMPLE)
    assert parsed.comments == (
        " This TAL is intended for documentation purposes only.",
        " Do not attempt to use this in a production setting.",
    )
    assert parsed.uris == (
        "rsync://rpki.example.org/rpki/hedgehog/root.cer",
        "https://rpki.example.org/rpki/hedgehog/root.cer",
    )
    assert len(parsed.spki_der) == 294
    assert parsed.spki_der[0] == 0x30
    assert base64.b64encode(parsed.spki_der).decode() == KEY_B64


def test_parse_tal_accepts_crlf_and_wrapped_base64() -> None:
    expected = parse_tal(EXAMPLE)
    assert parse_tal(EXAMPLE.replace(b"\n", b"\r\n")) == expected
    wrapped = tal(key="\n".join(KEY_B64[i : i + 64] for i in range(0, len(KEY_B64), 64)))
    assert parse_tal(wrapped).spki_der == expected.spki_der
    assert parse_tal(tal(key=KEY_B64)).spki_der == expected.spki_der  # one unbroken line


def test_parse_tal_accepts_no_comments_no_final_line_break_and_one_uri() -> None:
    raw = (URI + "\n\n" + KEY_B64).encode()
    parsed = parse_tal(raw)
    assert parsed.comments == ()
    assert parsed.uris == (URI,)


def test_parse_tal_keeps_utf8_comment_text() -> None:
    parsed = parse_tal(tal(comments="# Zürich anchor — test\n"))
    assert parsed.comments == (" Zürich anchor — test",)


@pytest.mark.parametrize(
    "uri",
    [
        "http://rpki.example.org/root.cer",
        "ftp://rpki.example.org/root.cer",
        "file:///etc/root.cer",
        "rpki.example.org/root.cer",
        "rsync:/rpki.example.org/root.cer",
        "https:///root.cer",
        "rsync://rpki.example.org",
        "rsync://rpki.example.org/rpki/",
        "https://rpki.example.org/a b.cer",
    ],
)
def test_parse_tal_rejects_non_rsync_https_or_non_object_uri(uri: str) -> None:
    with pytest.raises(TalError):
        parse_tal(tal(uris=uri + "\n"))


def test_parse_tal_rejects_missing_blank_line() -> None:
    # With the blank line gone the key reads as one more URI line, and is refused as one.
    with pytest.raises(TalError, match="neither rsync nor https"):
        parse_tal((URI + "\n" + KEY_B64 + "\n").encode())
    with pytest.raises(TalError, match="blank line"):
        parse_tal((URI + "\n").encode())


def test_parse_tal_rejects_no_uri() -> None:
    with pytest.raises(TalError, match="no TA URI"):
        parse_tal(("\n" + KEY_B64 + "\n").encode())
    with pytest.raises(TalError, match="no TA URI"):
        parse_tal(b"")
    with pytest.raises(TalError, match="no TA URI"):
        parse_tal(b"# only a comment\n\n" + KEY_B64.encode())


def test_parse_tal_rejects_comment_after_the_uris() -> None:
    with pytest.raises(TalError):
        parse_tal((URI + "\n# late comment\n\n" + KEY_B64 + "\n").encode())


def test_parse_tal_rejects_empty_key() -> None:
    with pytest.raises(TalError, match="no subjectPublicKeyInfo"):
        parse_tal((URI + "\n\n").encode())
    with pytest.raises(TalError, match="no subjectPublicKeyInfo"):
        parse_tal((URI + "\n\n\n").encode()[:-1])


def test_parse_tal_rejects_invalid_or_noncanonical_base64() -> None:
    with pytest.raises(TalError, match="base64"):
        parse_tal(tal(key="MIIB*!"))
    with pytest.raises(TalError, match="base64"):
        parse_tal(tal(key=KEY_B64[:-1]))  # wrong padding length
    with pytest.raises(TalError, match="blank line inside"):
        parse_tal(tal(key=KEY_B64[:60] + "\n\n" + KEY_B64[60:]))
    with pytest.raises(TalError, match="base64"):
        parse_tal(tal(key=KEY_B64 + " "))  # space is not in the alphabet


def test_parse_tal_rejects_key_that_is_not_one_der_sequence() -> None:
    spki = base64.b64decode(KEY_B64)
    cases = {
        "not a sequence": base64.b64encode(b"\x04\x01\x00").decode(),
        "trailing bytes": base64.b64encode(spki + b"\x00").decode(),
        "truncated": base64.b64encode(spki[:-1]).decode(),
        "indefinite length": base64.b64encode(b"\x30\x80\x00\x00").decode(),
        "non-minimal length": base64.b64encode(b"\x30\x81\x00").decode(),
    }
    for label, key in cases.items():
        with pytest.raises(TalError, match="subjectPublicKeyInfo"):
            parse_tal(tal(key=key))
        assert label


def test_parse_tal_rejects_nul_bare_cr_bom_and_invalid_utf8() -> None:
    with pytest.raises(TalError, match="control character"):
        parse_tal(tal(comments="# bad\x00comment\n"))
    with pytest.raises(TalError, match="control character"):
        parse_tal(tal(comments="# escape \x1b[31m\n"))
    with pytest.raises(TalError, match="control character"):
        parse_tal(tal(comments="# C1 \u0085 next line\n"))
    with pytest.raises(TalError, match="bare CR"):
        parse_tal(tal(comments="# lone\rcr\n"))
    with pytest.raises(TalError, match="bare CR"):
        parse_tal(EXAMPLE.replace(b"\n\n", b"\n\r"))
    with pytest.raises(TalError, match="byte order mark"):
        parse_tal(b"\xef\xbb\xbf" + EXAMPLE)
    with pytest.raises(TalError, match="UTF-8"):
        parse_tal(b"# \xff\xfe\n" + tal())


def test_parse_tal_size_cap() -> None:
    oversized = b"# " + b"a" * MAX_TAL_BYTES + b"\n" + EXAMPLE
    with pytest.raises(TalError, match="byte cap"):
        parse_tal(oversized)
    # Exactly at the cap is parsed, not refused for its size.
    padding = b"#" + b"a" * (MAX_TAL_BYTES - len(EXAMPLE) - 2) + b"\n"
    assert len(padding + EXAMPLE) == MAX_TAL_BYTES
    assert isinstance(parse_tal(padding + EXAMPLE), Tal)


def test_load_trust_anchor_reads_a_file(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "example.tal"
    path.write_bytes(EXAMPLE)
    assert load_trust_anchor(path) == parse_tal(EXAMPLE)


def test_load_trust_anchor_missing_file_is_loud(tmp_path: pathlib.Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_trust_anchor(tmp_path / "absent.tal")


def test_load_trust_anchor_refuses_an_oversized_file_without_reading_it_all(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "huge.tal"
    path.write_bytes(b"#" + b"a" * (MAX_TAL_BYTES * 4))
    with pytest.raises(TalError, match="byte cap"):
        load_trust_anchor(path)
