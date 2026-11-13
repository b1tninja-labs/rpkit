# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

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
