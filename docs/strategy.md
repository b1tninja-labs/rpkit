# Strategy

The completeness matrix is [../ROADMAP.md](../ROADMAP.md). This document is *why* the rows
are ordered the way they are, and the rules that order has to respect.

## The constitution

1. **The core is the specification implementation.** `rpkit/` holds codecs, state machines
   and the vocabulary of rpkit. New core code appears when a document defines the
   behaviour, or when an ordering rule with no document earns an explicit convention label.
2. **Sans-IO before sockets.** Anything decidable from data plus a clock is implemented
   without touching a socket, so every timeout, retry and rollover is testable without
   sleeping or networking.
3. **Dependency-free by default.** An exception needs a sentence in README.md explaining why
   the rule was broken, and a floor with no ceiling.
4. **Positioning is correctness and legibility, not throughput.** The incumbents in this
   corner are usually stale, untyped, or welded to a product. This is the implementation that
   says how it knows what it claims.
5. **Every answer carries its provenance.** Verified or cached, which document, refused or
   believed. An answer without provenance is a guess with a confident type.

## The three tiers

| Tier | Home | Contents | Rule |
|---|---|---|---|
| Core | `rpkit/` | codecs, state machines, policy objects | RFC-cited or convention-labelled |
| Apps | `rpkit/apps/` | reusable assemblies that compose core | no new protocol surface |
| Examples | `examples/` | one runnable script per use case | configures; never restates logic |

## Interface grammar

One engine, three drives, never parallel implementations:

- **await** -- the native asyncio surface.
- **blocking** -- a facade owning a private loop, so a call from inside a caller's running
  loop works instead of deadlocking.
- **callback** -- plain callables, no third-party promise type.

## Naming

One string everywhere: the distribution, the import and the console script. A name that
means one thing in the installer, in `import` and on `PATH` is the only arrangement that
cannot surprise anyone, and it is also why this project does not sit one edit away from a
project that already exists.

## Dependency decisions (2026-11-13)

- **asn1core is a runtime dependency.** A TAL carries a DER subjectPublicKeyInfo, and a resource
  certificate carries RFC 3779 extensions inside DER; reading either with `struct` and slicing is a
  second ASN.1 codec in the portfolio, and the owner's rule is that ASN.1 and certificate parsing are ours and live in asn1core.
  asn1core keeps the original octets, which a signature check later needs. It resolves from the sibling
  checkout until it publishes.
- **`cryptography` is not declared yet.** RSA PKCS#1 v1.5 verification (RFC 7935) is the only
  primitive the signed-object path needs, and it will come through `sigwire.verify.rsa.verify_pkcs1v15`, which
  owns the encoding comparison. No row calls it yet, so no dependency is declared for it.
- **CMS is signeddata's.** RFC 6488 objects are CMS SignedData. signeddata is a shell, so M1c waits;
  rpkit does not write a parallel CMS reader.
- **XML is expat, not defusedxml.** The `xml` extra was removed. RRDP parsing (RFC 8182) will use
  `xml.parsers.expat` directly with DTD and entity declarations refused, so a billion-laughs document
  is an error and not an allocation.
- **Provenance of the TAL/SLURM choices** (strict base64, bare CR refusal, no host bits in SLURM
  prefixes, `slurmVersion` as the integer 1) is in the module docstrings of `anchors.py` and `slurm.py`,
  which say which are RFC requirements and which are this project's.
