"""manifest objects, file hashes and number handling (RFC 9286, RFC 9981).

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
    "check_manifest",
    "next_manifest_number",
]


def check_manifest(manifest: SignedObject, files: dict) -> list[str]:
    """Pending behaviour defined by RFC 9286.

    Not implemented yet. See the ``manifest.check_manifest()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("check_manifest() is not implemented: RFC 9286")


def next_manifest_number(current: int) -> int:
    """Pending behaviour defined by RFC 9981.

    Not implemented yet. See the ``manifest.next_manifest_number()`` row in ROADMAP.md;
    this stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("next_manifest_number() is not implemented: RFC 9981")
