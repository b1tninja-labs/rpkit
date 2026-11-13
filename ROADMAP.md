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
| `anchors.parse_tal()` | RFC 8630 section 2.2 | `[ok]` | `tests/test_tal.py::test_parse_tal_rfc_example`, `tests/test_tal.py::test_parse_tal_rejects_nul_bare_cr_bom_and_invalid_utf8` | M1a |
| `anchors.load_trust_anchor()` | RFC 8630 section 2.2 (the row cited RFC 9691, which is the TAK object) | `[ok]` | `tests/test_tal.py::test_load_trust_anchor_reads_a_file`, `tests/test_tal.py::test_load_trust_anchor_missing_file_is_loud` | M1a |
| `anchors.match_ta_key` | RFC 8630 section 3 step 3: the TAL key equals the retrieved certificate's SPKI (asn1core `subject_public_key_info`) | `[ ]` | `tests/test_anchors_match.py::test_match_ta_key` (to be written) | M4 |
| `anchors.fetch_ta` | RFC 8630 section 3 and section 4: TLS validated for HTTPS URIs, rsync otherwise; ambient proxy and CA-bundle environment ignored | `[ ]` | `tests/test_anchors_fetch.py::test_fetch_ta` (to be written) | M2 |
| `anchors.load_tak` | RFC 9691: the TAK signed object (a CMS object, so it waits on M1c) | `[ ]` | `tests/test_tak.py::test_load_tak` (to be written) | M1c |
| `roa.vrp` | RFC 6811 section 2 (the VRP triple), RFC 9582 section 4.3.2.2 (absent maxLength is the prefix length) | `[ok]` | `tests/test_roa.py::test_vrp_refuses_impossible_fields` | M1a |
| `resources.asn1core-rfc3779` | RFC 3779 sections 2.2 and 3.2 with errata 2537 and 6792; decoding lives in asn1core (`resources.py`, full vectors there) and pkix does the resource-inclusion checks during path validation; rpkit only consumes it | `[part]` | `tests/test_resources_seam.py::test_asn1core_decodes_rfc3779_appendix_c` | M1b |
| `resources.profile-check` | RFC 6487 sections 4.8.10 and 4.8.11: critical, no SAFI, no RDI, non-empty or inherit | `[ ]` | `tests/test_resources_profile.py::test_profile_check` (to be written) | M4 |
| `resources.is_subset` | RFC 3779 sections 2.3 and 3.3 path validation; asn1core `ranges_cover` is the arithmetic, inherit resolution is here; RFC 8360 changes the overclaim outcome | `[ ]` | `tests/test_resources_subset.py::test_is_subset` (to be written) | M4 |
| `repository.open_cache()` | RFC 6480, RFC 6481 (publication point layout and file naming) | `[ ]` | `tests/test_obligations.py::test_open_cache` (to be written) | M2 |
| `repository.fetch_policy` | choose rsync or RRDP per publication point; RFC 9589 explains why signing-time matters when switching; the section 5 question becomes a decision row | `[ ]` | `tests/test_fetch_policy.py::test_fetch_policy` (to be written) | M2 |
| `rrdp.fetch_notification()` | RFC 8182, RFC 9674 (the same-origin check belongs here) | `[ ]` | `tests/test_obligations.py::test_fetch_notification` (to be written) | M2 |
| `rrdp.parse_notification` | RFC 8182 section 3: XML schema and hash fields, separate from the HTTP fetch; parsed with expat refusing DTDs and entities | `[ ]` | `tests/test_rrdp_parse.py::test_parse_notification` (to be written) | M2 |
| `rrdp.parse_snapshot` | RFC 8182 section 3 | `[ ]` | `tests/test_rrdp_parse.py::test_parse_snapshot` (to be written) | M2 |
| `rrdp.parse_delta` | RFC 8182 section 3 | `[ ]` | `tests/test_rrdp_parse.py::test_parse_delta` (to be written) | M2 |
| `rrdp.verify_hashes` | RFC 8182 section 3: SHA-256 of snapshot, delta and published objects | `[ ]` | `tests/test_rrdp_hash.py::test_verify_hashes` (to be written) | M2 |
| `rrdp.apply_delta()` | RFC 8182, RFC 9697 (session and serial desynchronisation) | `[ ]` | `tests/test_obligations.py::test_apply_delta` (to be written) | M2 |
| `signedobject.decode_signed_object()` | RFC 6488, RFC 9589, RFC 5652; CMS comes from signeddata, which is a shell | `[ ]` | `tests/test_obligations.py::test_decode_signed_object` (to be written) | M1c |
| `signedobject.check_signed_attrs` | RFC 6488 (content-type, message-digest, no others) and RFC 9589 (signing-time required) | `[ ]` | `tests/test_signedattrs.py::test_check_signed_attrs` (to be written) | M1c |
| `signedobject.verify_rsa_sha256` | RFC 7935 as updated by RFC 8608; RSA PKCS#1 v1.5 verification through the `sigwire[verify]` seam (`cryptography` underneath), not written here | `[ ]` | `tests/test_signedobject_verify.py::test_verify_rsa_sha256` (to be written) | M1c |
| `signedobject.rsa-seam` | RFC 7935 and RFC 8608: `rpkit/_rsa.py` is the one module that reaches an RSA verifier (`sigwire.verify.rsa.verify_pkcs1v15`, `cryptography` underneath) | `[ok]` | `tests/test_rsa_seam.py::test_seam_accepts_a_good_signature_and_refuses_tampering` | M1c |
| `signedobject.switch-to-sigwire` | sigprim merged into `sigwire[verify]` on 2026-11-13: the single import in `rpkit/_rsa.py`, the `pythonpath` and `mypy_path` entries and the CI checkouts now name sigwire | `[ok]` | `tests/test_rsa_seam.py::test_seam_accepts_a_good_signature_and_refuses_tampering` | M1c |
| `resources.lenient-read` | real-world RPKI certificates: read through asn1core `decode(..., lenient_values=True)`, `Node.defects` and `der_violations()` and report each defect as a finding rather than refusing outright; asn1core's `parse_ip_resources` is strict DER and has no lenient mode, a gap to raise with asn1core | `[ ]` | `tests/test_lenient_certs.py::test_lenient_read` (to be written) | M4 |
| `roa.parse_roa_content` | RFC 9582 section 4 (not RFC 6482, obsolete); DER through asn1core; the canonical ipAddrBlocks form of section 4.3.3 | `[ ]` | `tests/test_roa_content.py::test_parse_roa_content` (to be written) | M1b |
| `manifest.parse_manifest` | RFC 9286 eContent, DER through asn1core | `[ ]` | `tests/test_manifest_parse.py::test_parse_manifest` (to be written) | M1b |
| `manifest.check_manifest()` | RFC 9286 | `[ ]` | `tests/test_obligations.py::test_check_manifest` (to be written) | M3 |
| `manifest.next_manifest_number()` | RFC 9981 | `[ ]` | `tests/test_obligations.py::test_next_manifest_number` (to be written) | M3 |
| `validation.decide-6487-or-8360` | RFC 6487 section 7 rejects an overclaiming certificate; RFC 8360 accepts the intersection when the CA says so; the relying party must choose one and say which in every result | `[ ]` | `docs/strategy.md` decision, then a test per branch (to be written) | M4 |
| `validation.crl_check` | RFC 6487 section 5, RFC 9829 (CRL Number), RFC 8209 where router certificates appear | `[ ]` | `tests/test_crl_check.py::test_crl_check` (to be written) | M4 |
| `validation.validate_roa()` | RFC 9582, RFC 3779, RFC 6487 section 7 or RFC 8360 (per the decision row), RFC 7318 policy qualifiers | `[ ]` | `tests/test_obligations.py::test_validate_roa` (to be written) | M4 |
| `validation.validate_origin()` | RFC 6811, RFC 8481 (was RFC 6480, the architecture document). Home is open owner decision D1: routevalid implements it on plain data and depends on rpkit, so rpkit cannot import it back | `[ ]` | `tests/test_obligations.py::test_validate_origin` (to be written) | M4 |
| `validation.assertions` | the typed VRP stream rtrkit consumes: an iterator of `roa.Vrp` after SLURM, carrying the provenance below | `[ ]` | `tests/test_assertions.py::test_assertions` (to be written) | M5 |
| `validation.provenance` | the README promise: SKI, manifest, object hash, rsync or RRDP URL, session and serial behind every assertion | `[ ]` | `tests/test_provenance.py::test_provenance` (to be written) | M4 |
| `slurm.parse_slurm()` | RFC 8416 sections 3.1 to 3.5 | `[ok]` | `tests/test_slurm.py::test_figure_7_parses_into_typed_members`, `tests/test_slurm.py::test_slurm_rejects_each_deviation` | M5 |
| `slurm.apply_slurm()` | RFC 8416 sections 3.2, 3.3.1, 3.4.1 | `[ok]` | `tests/test_slurm.py::test_figure_3_filters_each_rule`, `tests/test_slurm.py::test_slurm_assertion_survives_matching_filter` | M5 |
| `slurm.apply_slurm_router_keys()` | RFC 8416 sections 3.3.2, 3.4.2 | `[ok]` | `tests/test_slurm.py::test_router_key_filters_and_assertions` | M5 |
| `slurm.merge_slurm` | RFC 8416 section 4.2: several files, union, and the whole set rejected on overlap | `[ ]` | `tests/test_slurm_merge.py::test_merge_slurm` (to be written) | M5 |
| `slurm.atomic_swap` | RFC 8416 section 4.1: the output either ignores the file or reflects all of it, across the VRP and router-key halves | `[ ]` | `tests/test_slurm_atomic.py::test_atomic_swap` (to be written) | M5 |
| `interop.rpki-client-routinator` | the publication checklist wants a non-Python implementation: pin one snapshot and compare VRP sets with rpki-client and Routinator output (an operational corpus, not an RFC vector) | `[ ]` | `docs/interop.md` (to be written) | M6 |
| `plan.depends-on` | `docs/plan.md` names only asn1core; the real set is asn1core, pkix, signeddata, `sigwire[verify]` and `cryptography`. The file is generated from PORTFOLIO.md, so the plan changes, not the file | `[ ]` | `PORTFOLIO.md` section 4 (owner) | - |
| `aspa.profile` | no ASPA RFC is in the library; RFC 9774 cites `draft-ietf-sidrops-aspa-verification`. Check the datatracker; until a profile is published ASPA is a gap, not a row | `[ ]` | `docs/research.md` finding (not committed) | - |

## 2. Milestones

- M1a text and JSON edges that need no cryptography: TAL (RFC 8630), SLURM (RFC 8416), the VRP type. Done 2026-11-13
- M1b DER content through asn1core: RFC 3779 resources (decoder done in asn1core), ROA eContent (RFC 9582), manifest eContent
- M1c signed objects: the RFC 6488 envelope plus RFC 7935 and RFC 8608 signature verification, which needs signeddata (CMS) and the `sigwire[verify]` RSA seam; blocked, not scheduled
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
- RFC 3779 carries 4 verified errata: 836 and 1886 are editorial, 6792 corrects Appendix B (172.16/12 is `ac10`, not `b010`), and 2537 deletes the last paragraph of section 2.2.3.9 (a max address "MUST contain at least one bit whose value is 1"). The asn1core decoder follows 2537 and 6792.
- RFC 8360 carries 2 verified errata and changes the RFC 6487 section 7 outcome for an overclaiming certificate; the row `validation.decide-6487-or-8360` records the choice a relying party must make.
- RFC 8416 has 1 erratum on file, 7080 (held for document update, not verified): a `comment` on a BGPsec assertion. `parse_slurm` accepts it, as the RFC's own Figure 7 shows.
- RFC 6482 is OBSOLETE (RFC 9582 replaces it, with no errata of its own). The ROA rows cite RFC 9582 only.
- RFC 8630 and RFC 9691 are separate documents: 8630 is the TAL file, 9691 is the TAK signed object. 9691 does not update 8630. The row that cited 9691 for TAL parsing is corrected.
- RFC 6488 is updated by RFC 9589, RFC 6487 by 7318, 8209 and 9829, and RFC 7935 by 8608 (8208 is itself obsolete). All are in docs/rfc-map.md and the rows above.
- Stale statements fixed 2026-11-13: the README no longer says every function raises (five do not), the dependency rule names asn1core, and the `defusedxml` extra is removed because the portfolio rule is the standard library plus `cryptography`.

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
- **D1 (owner decision, recommended): where RFC 6811 lives.** It was planned three times (rpkit `validation.validate_origin`, routevalid `check_origin`, asnkit `rov.annotate`). routevalid now implements `origin.rov_state` on plain data with a brute-force oracle test. rpkit cannot import it (routevalid depends on rpkit), and rpkit's job is to emit VRPs, not to classify routes. Recommendation: routevalid is the home; this row becomes `[no]` with a pointer; asnkit imports routevalid or keeps a one-line wrapper. Until decided, the row stays `[ ]` and the stub raises.
- the RFC 8360 or RFC 6487 section 7 validation procedure: which one is the default, and is the other selectable
- XML hardening for RRDP: `xml.parsers.expat` with DTD and entity handlers that refuse, recorded in docs/strategy.md, instead of a third-party parser
- the `sigwire[verify]` seam for RSA verification and signeddata for CMS: neither is wired in because M1c is blocked on signeddata, a shell today

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
