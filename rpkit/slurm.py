"""local exception filtering (RFC 8416): parse a SLURM file, apply it to VRPs and router keys.

A SLURM file is the operator's local override of the validated RPKI output: Validation Output
Filters remove what validation produced, Locally Added Assertions add what the operator insists on.
`parse_slurm` is all-or-nothing, because RFC 8416 section 3.1 makes every deviation an error and
section 4.1 makes the effect atomic: a half-read file would apply some assertions and not others,
which RFC 8416 section 4.1 shows can flip one route Invalid while its neighbour is Valid.

Choices that are this module's rather than the RFC's, so a reader can tell them apart:

* ``prefix`` strings must carry a ``/length`` and no host bits. RFC 8416 names RFC 4632 section 3.1
  and RFC 5952 for the text forms and says nothing about host bits; refusing them keeps a filter
  from covering something other than what its author wrote.
* ``slurmVersion`` must be the integer ``1``; ``1.0`` is refused, though it is the same JSON number.
* duplicate JSON member names, ``NaN``/``Infinity``, a byte order mark and invalid UTF-8 are refused,
  and the file is capped at `MAX_SLURM_BYTES` before it is parsed.
* a prefix assertion with no ``maxPrefixLength`` becomes a VRP whose max length is the prefix
  length, the meaning an absent maxLength has in a ROA (RFC 9582 section 4.3.2.2); RFC 8416
  section 3.4.1 only says the triple "describes a VRP" and gives no default.
* a ``comment`` is accepted on a BGPsec assertion although the text of section 3.4.2 omits it:
  erratum 7080 (held for document update, not verified) and the RFC's own Figure 7 both carry one.

Not done here, each its own ROADMAP.md row: several SLURM files at once with the section 4.2 overlap
rejection, and the CLI/file-watching an operator needs.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from asn1core import Asn1Error, decode

from .roa import MAX_ASN, Network, Vrp, vrp_sort_key

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "MAX_SLURM_BYTES",
    "BgpsecAssertion",
    "BgpsecFilter",
    "PrefixAssertion",
    "PrefixFilter",
    "RouterKey",
    "Slurm",
    "SlurmError",
    "apply_slurm",
    "apply_slurm_router_keys",
    "parse_slurm",
]

MAX_SLURM_BYTES = 4 * 1024 * 1024

_PREFIX_TEXT = re.compile(r"[0-9A-Fa-f:.]+/[0-9]{1,3}")


class SlurmError(ValueError):
    """The bytes are not a SLURM file under RFC 8416 section 3."""


@dataclass(frozen=True, slots=True)
class PrefixFilter:
    """A Validated ROA Prefix Filter (RFC 8416 section 3.3.1): a prefix, an ASN, or both."""

    prefix: Network | None
    asn: int | None
    comment: str | None = None

    def matches(self, vrp: Vrp) -> bool:
        """Section 3.3.1 cases 1 to 3: the prefix equals or covers the VRP's, and/or the ASN is equal."""
        if self.prefix is not None and not (
            self.prefix.version == vrp.prefix.version and vrp.prefix.subnet_of(self.prefix)  # type: ignore[arg-type]
        ):
            return False
        return self.asn is None or self.asn == vrp.asn


@dataclass(frozen=True, slots=True)
class BgpsecFilter:
    """A BGPsec Assertion Filter (RFC 8416 section 3.3.2): an ASN, a router SKI, or both."""

    asn: int | None
    ski: bytes | None
    comment: str | None = None

    def matches(self, key: RouterKey) -> bool:
        return (self.asn is None or self.asn == key.asn) and (
            self.ski is None or self.ski == key.ski
        )


@dataclass(frozen=True, slots=True)
class PrefixAssertion:
    """A ROA Prefix Assertion (RFC 8416 section 3.4.1). ``max_length`` None means the prefix length."""

    prefix: Network
    asn: int
    max_length: int | None = None
    comment: str | None = None

    def vrp(self) -> Vrp:
        length = self.prefix.prefixlen if self.max_length is None else self.max_length
        return Vrp(self.prefix, length, self.asn)


@dataclass(frozen=True, slots=True)
class BgpsecAssertion:
    """A BGPsec Assertion (RFC 8416 section 3.4.2): ASN, SKI and the router's SPKI (DER)."""

    asn: int
    ski: bytes
    router_public_key: bytes
    comment: str | None = None


@dataclass(frozen=True, slots=True)
class RouterKey:
    """A BGPsec router key as RTR carries it (RFC 8210 section 5.10): ASN, SKI, SPKI DER."""

    asn: int
    ski: bytes
    spki: bytes


@dataclass(frozen=True, slots=True)
class Slurm:
    """A whole SLURM file. Every member is a tuple, in file order."""

    prefix_filters: tuple[PrefixFilter, ...] = ()
    bgpsec_filters: tuple[BgpsecFilter, ...] = ()
    prefix_assertions: tuple[PrefixAssertion, ...] = ()
    bgpsec_assertions: tuple[BgpsecAssertion, ...] = ()


def parse_slurm(raw: bytes) -> Slurm:
    """Parse a SLURM file as RFC 8416 section 3 defines it, refusing any deviation.

    Raises:
        SlurmError: on every departure (RFC 8416 section 3.1: any deviation is an error), including
            the wrong ``slurmVersion``, a member that section 3.2 does not define, a missing or
            extra member where it says "exactly", a filter with neither ``prefix`` nor ``asn``, an
            assertion missing a required member, and a malformed prefix, ASN or base64 value.
    """
    if len(raw) > MAX_SLURM_BYTES:
        raise SlurmError(f"SLURM file is {len(raw)} bytes, over the {MAX_SLURM_BYTES} byte cap")
    try:
        text = raw.decode("utf-8")
        if text.startswith("﻿"):
            raise SlurmError("SLURM file starts with a byte order mark")
        document = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except UnicodeDecodeError as error:
        raise SlurmError("SLURM file is not valid UTF-8") from error
    except RecursionError as error:
        raise SlurmError("SLURM file nests too deeply") from error
    except json.JSONDecodeError as error:
        raise SlurmError(f"SLURM file is not JSON: {error}") from error
    if not isinstance(document, dict):
        raise SlurmError("a SLURM file is one JSON object")
    _members(
        document, {"slurmVersion", "validationOutputFilters", "locallyAddedAssertions"}, "file"
    )
    version = document["slurmVersion"]
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise SlurmError(f"slurmVersion must be the number 1, not {version!r}")
    filters = _object(document["validationOutputFilters"], "validationOutputFilters")
    _members(filters, {"prefixFilters", "bgpsecFilters"}, "validationOutputFilters")
    assertions = _object(document["locallyAddedAssertions"], "locallyAddedAssertions")
    _members(assertions, {"prefixAssertions", "bgpsecAssertions"}, "locallyAddedAssertions")
    return Slurm(
        prefix_filters=tuple(_prefix_filter(x) for x in _array(filters["prefixFilters"])),
        bgpsec_filters=tuple(_bgpsec_filter(x) for x in _array(filters["bgpsecFilters"])),
        prefix_assertions=tuple(
            _prefix_assertion(x) for x in _array(assertions["prefixAssertions"])
        ),
        bgpsec_assertions=tuple(
            _bgpsec_assertion(x) for x in _array(assertions["bgpsecAssertions"])
        ),
    )


def apply_slurm(roas: Iterable[Vrp], config: Slurm) -> list[Vrp]:
    """Apply RFC 8416 filters and then assertions to a VRP set, returning the sorted, de-duplicated result.

    Order is the RFC's (section 3.2: the result is as if output filtering ran before locally adding
    assertions), so an assertion is never removed by a filter. Duplicates are dropped, as sections
    3.4.1 and 3.4.2 require for what RTR sends. ``roas`` is read once, so a generator is fine. Only
    the prefix half of the file acts here; the BGPsec half acts on router keys, through
    `apply_slurm_router_keys`, and a caller serving both must call both or the section 4.1 atomicity
    is lost.
    """
    kept = {v for v in roas if not any(f.matches(v) for f in config.prefix_filters)}
    kept.update(a.vrp() for a in config.prefix_assertions)
    return sorted(kept, key=vrp_sort_key)


def apply_slurm_router_keys(keys: Iterable[RouterKey], config: Slurm) -> list[RouterKey]:
    """Apply the BGPsec half of an RFC 8416 file (sections 3.3.2 and 3.4.2) to router keys.

    Filters remove matching keys, then assertions add theirs, duplicates excluded, sorted by
    (ASN, SKI, SPKI) so the output is deterministic.
    """
    kept = {k for k in keys if not any(f.matches(k) for f in config.bgpsec_filters)}
    kept.update(RouterKey(a.asn, a.ski, a.router_public_key) for a in config.bgpsec_assertions)
    return sorted(kept, key=lambda k: (k.asn, k.ski, k.spki))


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise SlurmError(f"duplicate JSON member {key!r}")
        out[key] = value
    return out


def _no_constants(name: str) -> Any:
    raise SlurmError(f"{name} is not a JSON number")


def _object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SlurmError(f"{where} must be a JSON object")
    return value


def _array(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise SlurmError("expected a JSON array")
    return value


def _members(
    obj: dict[str, Any], allowed: set[str], where: str, *, required: set[str] | None = None
) -> None:
    """Section 3.1: undefined members MUST NOT be used; ``required`` defaults to all of ``allowed``."""
    need = allowed if required is None else required
    extra = sorted(set(obj) - allowed)
    if extra:
        raise SlurmError(f"{where} has undefined member(s) {', '.join(extra)} (RFC 8416 3.1)")
    missing = sorted(need - set(obj))
    if missing:
        raise SlurmError(f"{where} is missing member(s) {', '.join(missing)}")


def _asn(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_ASN:
        raise SlurmError(f"asn must be an integer 0..{MAX_ASN}, not {value!r}")
    return value


def _prefix(value: Any) -> Network:
    if not isinstance(value, str) or not _PREFIX_TEXT.fullmatch(value):
        raise SlurmError(f"prefix must be address/length text, not {value!r}")
    try:
        return ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise SlurmError(f"prefix {value!r} is not a valid prefix without host bits") from error


def _comment(obj: dict[str, Any]) -> str | None:
    comment = obj.get("comment")
    if comment is not None and not isinstance(comment, str):
        raise SlurmError("comment must be a string")
    return comment


def _unpadded_base64(value: Any, what: str) -> bytes:
    """RFC 8416 sections 3.3.2 and 3.4.2: base64 'without trailing =' (RFC 4648 section 5 as cited)."""
    if not isinstance(value, str) or "=" in value or not value:
        raise SlurmError(f"{what} must be non-empty base64 without '=' padding")
    padded = value + "=" * (-len(value) % 4)
    try:
        data = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise SlurmError(f"{what} is not valid base64") from error
    if base64.b64encode(data).decode("ascii") != padded:
        raise SlurmError(f"{what} is not canonical base64")
    return data


def _prefix_filter(item: Any) -> PrefixFilter:
    obj = _object(item, "prefix filter")
    _members(obj, {"prefix", "asn", "comment"}, "prefix filter", required=set())
    if "prefix" not in obj and "asn" not in obj:
        raise SlurmError("a prefix filter needs a prefix, an asn or both (RFC 8416 3.3.1)")
    return PrefixFilter(
        _prefix(obj["prefix"]) if "prefix" in obj else None,
        _asn(obj["asn"]) if "asn" in obj else None,
        _comment(obj),
    )


def _bgpsec_filter(item: Any) -> BgpsecFilter:
    obj = _object(item, "BGPsec filter")
    _members(obj, {"asn", "SKI", "comment"}, "BGPsec filter", required=set())
    if "asn" not in obj and "SKI" not in obj:
        raise SlurmError("a BGPsec filter needs an asn, an SKI or both (RFC 8416 3.3.2)")
    return BgpsecFilter(
        _asn(obj["asn"]) if "asn" in obj else None,
        _unpadded_base64(obj["SKI"], "SKI") if "SKI" in obj else None,
        _comment(obj),
    )


def _prefix_assertion(item: Any) -> PrefixAssertion:
    obj = _object(item, "prefix assertion")
    _members(
        obj,
        {"prefix", "asn", "maxPrefixLength", "comment"},
        "prefix assertion",
        required={"prefix", "asn"},
    )
    prefix = _prefix(obj["prefix"])
    length = obj.get("maxPrefixLength")
    if length is not None:
        if isinstance(length, bool) or not isinstance(length, int):
            raise SlurmError("maxPrefixLength must be an integer")
        if not prefix.prefixlen <= length <= prefix.max_prefixlen:
            raise SlurmError(
                f"maxPrefixLength {length} is outside {prefix.prefixlen}..{prefix.max_prefixlen}"
            )
    return PrefixAssertion(prefix, _asn(obj["asn"]), length, _comment(obj))


def _bgpsec_assertion(item: Any) -> BgpsecAssertion:
    obj = _object(item, "BGPsec assertion")
    _members(
        obj,
        {"asn", "SKI", "routerPublicKey", "comment"},
        "BGPsec assertion",
        required={"asn", "SKI", "routerPublicKey"},
    )
    spki = _unpadded_base64(obj["routerPublicKey"], "routerPublicKey")
    try:
        node, end = decode(spki, der=True)
    except Asn1Error as error:
        raise SlurmError(f"routerPublicKey is not DER: {error}") from error
    if end != len(spki) or node.tag.number != 16 or not node.tag.constructed:
        raise SlurmError("routerPublicKey must be one DER SEQUENCE (a subjectPublicKeyInfo)")
    return BgpsecAssertion(
        _asn(obj["asn"]), _unpadded_base64(obj["SKI"], "SKI"), spki, _comment(obj)
    )
