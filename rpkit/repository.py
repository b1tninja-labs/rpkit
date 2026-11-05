"""publication point model, cache layout, rsync and RRDP selection (RFC 6480).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

import pathlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Repository = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "open_cache",
]


def open_cache(root: pathlib.Path) -> Repository:
    """Pending behaviour defined by RFC 6480.

    Not implemented yet. See the ``repository.open_cache()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("open_cache() is not implemented: RFC 6480")
