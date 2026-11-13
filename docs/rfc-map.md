# Where every claim in this repository comes from

| Document | Status | Published | Relationship and errata |
|---|---|---|---|
| RFC 3779 | Proposed Standard | 2004-06 | 4 verified errata (836, 1886, 2537, 6792); IP and AS resource extensions; the asn1core decoder follows 2537 and 6792 |
| RFC 6480 | Informational | 2012-02 | architecture; not the spec of any function |
| RFC 6481 | Proposed Standard | 2012-02 | repository structure, file naming; no errata |
| RFC 6487 | Proposed Standard | 2012-02 | updated by 7318, 8209, 9829; 4 verified errata |
| RFC 7318 | Proposed Standard | 2014-07 | updates 6487 (policy qualifiers) |
| RFC 8209 | Proposed Standard | 2017-09 | updates 6487 (BGPsec router certificates); 1 erratum on file, not verified |
| RFC 9829 | Proposed Standard | 2025-07 | updates 6487 (CRL Number handling) |
| RFC 8360 | Proposed Standard | 2018-04 | validation reconsidered (overclaim handling); alternative to the 6487 section 7 procedure; 2 verified errata |
| RFC 6482 | Proposed Standard | 2012-02 | **OBSOLETE**, obsoleted by 9582; 3 verified errata; never cited |
| RFC 9582 | Proposed Standard | 2024-05 | ROA profile; obsoletes 6482; no errata |
| RFC 6488 | Proposed Standard | 2012-02 | signed object template; updated by 9589; 1 verified erratum |
| RFC 9589 | Proposed Standard | 2024-05 | updates 6488 (CMS signing-time attribute) |
| RFC 5652 | Internet Standard | 2009-09 | CMS; updated by 8933, 9629; 2 verified errata; parsing is signeddata's |
| RFC 7935 | Proposed Standard | 2016-08 | algorithms and key sizes; obsoletes 6485; updated by 8208 (itself obsolete) and 8608 |
| RFC 8608 | Proposed Standard | 2019-06 | updates 7935 and obsoletes 8208 (BGPsec algorithms, key formats) |
| RFC 8182 | Proposed Standard | 2017-07 | RRDP; updated by 9674 and 9697; 1 verified erratum |
| RFC 9674 | Proposed Standard | 2024-12 | updates 8182 (same-origin rule) |
| RFC 9697 | Proposed Standard | 2024-12 | updates 8182 (session desynchronisation) |
| RFC 9286 | Proposed Standard | 2022-06 | manifests; obsoletes 6486; updated by 9981; 1 verified erratum |
| RFC 9981 | Proposed Standard | 2026-05 | updates 9286 (manifest number boundary) |
| RFC 8630 | Proposed Standard | 2019-08 | Trust Anchor Locator; obsoletes 7730; no errata; this is the TAL RFC |
| RFC 9691 | Proposed Standard | 2024-12 | Trust Anchor Key (TAK) signed object; a different object from the TAL, and not an update of 8630; no errata |
| RFC 8416 | Proposed Standard | 2018-08 | SLURM; 1 erratum on file (7080, held, not verified) |
| RFC 6811 | Proposed Standard | 2013-01 | origin validation; updated by 8481 and 8893; no errata; routevalid's home, see ROADMAP section 5 |
| RFC 8481 | Proposed Standard | 2018-09 | updates 6811; updated by 9324; no errata |

Every row above was read from `rfclib.info` on 2026-11-13. RFC 6486 is obsolete (RFC 9286 replaces it) and RFC 7730 is obsolete (RFC 8630 replaces it); neither is cited. ASPA has no RFC in the library: the verification procedure is a draft (RFC 9774 cites `draft-ietf-sidrops-aspa-verification`), so ASPA stays a recorded gap in ROADMAP.md and is not a row.

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
