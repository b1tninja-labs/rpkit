# rpkit

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

rpkit -- an RPKI relying party you can import

Python has no RPKI relying-party implementation at all. Validation, RRDP and repository handling live in Rust (Routinator, rcynic) and C (rpki-client), so any Python tool that wants origin validation today shells out to a daemon and parses its output. The specification is also moving: RFC 9981 (2026-05) and RFC 9829 (2025-07) both landed inside the last year and neither has a Python consumer. rpkit is the importable relying party: fetch, verify, validate, with the provenance of every assertion attached to the answer instead of assumed by the caller.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| rov | 0.6.0 | 2025-07-09 | offline batch ROV over IRR and dump files; no validator library, no RRDP, no RTR |
| rpki | - | - | name does not exist on PyPI (checked 2026-11-05) |
| routinator, rpki-client, rcynic | - | - | Rust and C daemons; no embeddable Python API |

What this project intends to add:

- RRDP client with notification, snapshot and delta files, and RFC 9697 desync recovery
- CMS signed-object decode and verification using the RFC 7935 algorithm profile
- manifest enforcement including the RFC 9981 number boundary nobody implements yet
- validation path walk with per-assertion reason codes: stale, revoked, suspended, filtered
- SLURM filtering as a first-class testable step rather than a daemon option

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 6480 | Informational | 2012-02 | the architecture: repositories, RAs, ROAs and relying-party duties |
| RFC 8182 | Proposed Standard | 2017-07 | RRDP: notification, snapshot and delta files over HTTPS |
| RFC 9697 | Proposed Standard | 2024-12 | detecting RRDP session desynchronisation |
| RFC 6488 | Proposed Standard | 2012-02 | the SignedObject CMS wrapper every RPKI file wears |
| RFC 9286 | Proposed Standard | 2022-06 | manifests: the anti-replay view of a publication point |
| RFC 9981 | Proposed Standard | 2026-05 | manifest number behaviour at the 2**32 minus 1 boundary |
| RFC 6487 | Proposed Standard | 2012-02 | resource certificate and CRL profile, relying-party path validation |
| RFC 7935 | Proposed Standard | 2016-08 | the algorithms and key sizes a relying party must speak |
| RFC 9691 | Proposed Standard | 2024-12 | trust anchor key (TAK) profile |
| RFC 8416 | Proposed Standard | 2018-08 | SLURM: local filtering of validated assertions |
| RFC 9674 | Proposed Standard | 2024-12 | same-origin policy for RRDP: delta and snapshot files isolated per repository server |
| RFC 9829 | Proposed Standard | 2025-07 | how the RPKI handles CRL Number extensions, updating the RFC 6487 profile |

### Errata watch

- RFC 8182 carries 1 verified erratum and is updated by RFC 9674 and RFC 9697. Read all three before writing the RRDP client.
- RFC 6487 carries 4 verified errata (algorithm and CRL number details; see also RFC 9829, 2025-07).
- RFC 9286 carries 1 verified erratum. RFC 6486 is OBSOLETE and must never be cited as the manifest specification.

## Module layout

| Module | Responsibility |
|---|---|
| `anchors` | trust anchors and TAKs: load, pin, expire (RFC 9691, RFC 6480) |
| `repository` | publication point model, cache layout, rsync and RRDP selection (RFC 6480) |
| `rrdp` | notification, snapshot and delta fetch plus desync recovery (RFC 8182, RFC 9697) |
| `signedobject` | CMS SignedObject envelope decode and verification (RFC 6488) |
| `manifest` | manifest objects, file hashes and number handling (RFC 9286, RFC 9981) |
| `roa` | route origin authorisation objects: prefix, ASN, max length |
| `validation` | certificate path and resource extension checks (RFC 6487) |
| `slurm` | local exception filtering (RFC 8416) |

## What it does not do

- issuing certificates: this is a relying party, not a CA
- talking to routers over RTR, which is rtrkit
- IRR database parsing
- being the fastest validator; correctness and provenance are the product


## Install

```bash
git clone https://github.com/b1tninja/rpkit.git
cd rpkit
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy rpkit
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
