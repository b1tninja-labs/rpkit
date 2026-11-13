"""The RSA seam: a signature made by `cryptography` verifies through it, and tampering does not."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from rpkit._rsa import verify_rsa_sha256


def test_seam_accepts_a_good_signature_and_refuses_tampering() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    message = b"rpki signed attributes"
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    assert verify_rsa_sha256(numbers.n, numbers.e, message, signature)
    assert not verify_rsa_sha256(numbers.n, numbers.e, message + b"!", signature)
    assert not verify_rsa_sha256(numbers.n, numbers.e, message, signature[:-1])
