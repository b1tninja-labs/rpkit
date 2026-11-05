"""CMS SignedObject envelope decode and verification (RFC 6488).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    SignedObject = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "decode_signed_object",
]


def decode_signed_object(blob: bytes) -> SignedObject:
    """Pending behaviour defined by RFC 6488.

    Not implemented yet. See the ``signedobject.decode_signed_object()`` row in
    ROADMAP.md; this stub raises on purpose so nothing downstream mistakes it for working
    code.
    """
    raise NotImplementedError("decode_signed_object() is not implemented: RFC 6488")
