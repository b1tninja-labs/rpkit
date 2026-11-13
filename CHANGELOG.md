# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added (2026-11-13, second pass)

- `resources`: RFC 3779 resources read through asn1core (strict or lenient), the RFC 6487 resource profile, and path validation under RFC 6487 section 7 (default) or RFC 8360.
- `roa.parse_roa_content`, `manifest.parse_manifest`, `manifest.check_manifest`, `manifest.check_replay`: RFC 9582, RFC 9286 and RFC 9981 content and replay checks.
- `signedobject.decode_signed_object`, `check_signed_attrs`, `verify_rsa_sha256`: the RFC 6488 profile with RFC 9589, on signeddata, verified through sigwire.
- `validation.check_crl`, `validation.validate_roa`: the CRL profile (RFC 6487 section 5, RFC 9829) and end-to-end ROA validation.
- `findings`: `Finding` and `Severity` for what checks report.
- `tools/fetch_corpus.py`, `tools/corpus.json`: the RIPE NCC RPKI archive for the AFRINIC trust anchor (2026-11-12) and Routinator's VRPs for it, fetched into a cache outside the repository and pinned by SHA-256 and size; `tests/test_signed_object_corpus.py` parses every object, validates every ROA with a chain from the archive, and compares the VRP set with Routinator's.

### Removed

- `manifest.next_manifest_number`: RFC 9981 defines relying party behaviour, which is `manifest.check_replay`; there is no issuer function to build (PORTFOLIO section 9 item 15).

### Changed

- `tests/` is a package, so a sibling checkout on the path cannot shadow it.

### Added

- `anchors.parse_tal` and `anchors.load_trust_anchor`: Trust Anchor Locator parsing under RFC 8630
  section 2.2, tested against the RFC's own example.
- `slurm.parse_slurm`, `slurm.apply_slurm` and `slurm.apply_slurm_router_keys`: RFC 8416 files parsed
  strictly and applied to VRPs and BGPsec router keys.
- `roa.Vrp`, the Validated ROA Payload type.
- ROADMAP rows for the rest of the first three milestones, with the spec spine corrected: RFC 3779,
  RFC 9582, RFC 8630, RFC 8360 and RFC 6811 added; the TAL row no longer cites RFC 9691.

### Changed

- `asn1core` is now a runtime dependency, resolved from the sibling checkout until it publishes.
- The `xml` extra (`defusedxml`) is removed: the portfolio rule is the standard library plus
  `cryptography`.

The remaining public functions are still stubs that raise `NotImplementedError`;
[ROADMAP.md](ROADMAP.md) lists what blocks them.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for rpkit.
- `rpkit.apps` namespace reserved for composition that is not protocol behaviour.
