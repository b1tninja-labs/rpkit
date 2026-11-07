# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation rpkit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `anchors.load_trust_anchor()` | RFC 9691 | `[ ]` | `tests/test_obligations.py::test_load_trust_anchor` (to be written) | M4 |
| `repository.open_cache()` | RFC 6480 | `[ ]` | `tests/test_obligations.py::test_open_cache` (to be written) | M2 |
| `rrdp.fetch_notification()` | RFC 8182 | `[ ]` | `tests/test_obligations.py::test_fetch_notification` (to be written) | M2 |
| `rrdp.apply_delta()` | RFC 8182, RFC 9697 | `[ ]` | `tests/test_obligations.py::test_apply_delta` (to be written) | M2 |
| `signedobject.decode_signed_object()` | RFC 6488 | `[ ]` | `tests/test_obligations.py::test_decode_signed_object` (to be written) | M1 |
| `manifest.check_manifest()` | RFC 9286 | `[ ]` | `tests/test_obligations.py::test_check_manifest` (to be written) | M3 |
| `manifest.next_manifest_number()` | RFC 9981 | `[ ]` | `tests/test_obligations.py::test_next_manifest_number` (to be written) | M3 |
| `validation.validate_roa()` | RFC 6487 | `[ ]` | `tests/test_obligations.py::test_validate_roa` (to be written) | M4 |
| `validation.validate_origin()` | RFC 6480 | `[ ]` | `tests/test_obligations.py::test_validate_origin` (to be written) | M4 |
| `slurm.apply_slurm()` | RFC 8416 | `[ ]` | `tests/test_obligations.py::test_apply_slurm` (to be written) | M5 |

## 2. Milestones

- M1 signed objects: RFC 6488 envelope plus RFC 7935 signature verification against live RIR data
- M2 repository: RRDP notification, snapshot and delta, with RFC 9697 desync recovery
- M3 manifests: hash verification, stale detection, RFC 9981 number boundary
- M4 validation: path walk, resource extensions, ROA extraction, ROV result with reason codes
- M5 SLURM filtering and the assertion stream rtrkit consumes
- M6 publication: 0.1.0 on PyPI with a reproducible repository fixture in the sdist

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 8182 carries 1 verified erratum and is updated by RFC 9674 and RFC 9697. Read all three before writing the RRDP client.
- RFC 6487 carries 4 verified errata (algorithm and CRL number details; see also RFC 9829, 2025-07).
- RFC 9286 carries 1 verified erratum. RFC 6486 is OBSOLETE and must never be cited as the manifest specification.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| issuing certificates: this is a relying party, not a CA | `[no]` | a named document requires it |
| talking to routers over RTR, which is rtrkit | `[no]` | a named document requires it |
| IRR database parsing | `[no]` | a named document requires it |
| being the fastest validator; correctness and provenance are the product | `[no]` | a named document requires it |

## 5. Open questions

- rsync or RRDP first: rsync is universal, RRDP is the future and the easier test target
- repository cache format, and whether it is shared with rtrkit on disk

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
