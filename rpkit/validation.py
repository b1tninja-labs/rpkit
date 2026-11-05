"""certificate path and resource extension checks (RFC 6487).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import Any

    Repository = Any  # placeholder: give it a real type in the milestone that needs it
    RovState = Any  # placeholder: give it a real type in the milestone that needs it
    SignedObject = Any  # placeholder: give it a real type in the milestone that needs it
    ValidationResult = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "validate_origin",
    "validate_roa",
]


def validate_roa(roa: SignedObject, store: Repository) -> ValidationResult:
    """Pending behaviour defined by RFC 6487.

    Not implemented yet. See the ``validation.validate_roa()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("validate_roa() is not implemented: RFC 6487")


def validate_origin(prefix: str, asn: int, roas: Iterable) -> RovState:
    """Pending behaviour defined by RFC 6480.

    Not implemented yet. See the ``validation.validate_origin()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("validate_origin() is not implemented: RFC 6480")
