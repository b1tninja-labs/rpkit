"""local exception filtering (RFC 8416).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import Any

    Slurm = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "apply_slurm",
]


def apply_slurm(roas: Iterable, config: Slurm) -> Iterable:
    """Pending behaviour defined by RFC 8416.

    Not implemented yet. See the ``slurm.apply_slurm()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("apply_slurm() is not implemented: RFC 8416")
