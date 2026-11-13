r"""The one place rpkit reaches an RSA verifier (RFC 7935, as updated by RFC 8608).

RSA PKCS#1 v1.5 with SHA-256 is the only signature algorithm RPKI objects use. The verification is
not written here: it is `sigwire.verify.rsa.verify_pkcs1v15`, from the sibling `D:\code\sigwire` and its
`[verify]` extra (the `cryptography` package does the modular arithmetic underneath). Every rpkit caller
goes through `verify_rsa_sha256`, so the one import below is the whole dependency (ROADMAP row
`signedobject.switch-to-sigwire`).
"""

from __future__ import annotations

from sigwire.verify.rsa import verify_pkcs1v15

__all__ = ["verify_rsa_sha256"]


def verify_rsa_sha256(n: int, e: int, message: bytes, signature: bytes) -> bool:
    """True when ``signature`` is a valid RSASSA-PKCS1-v1_5 SHA-256 signature of ``message``."""
    return verify_pkcs1v15(n, e, message, signature, "sha256")
