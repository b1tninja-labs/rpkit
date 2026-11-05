"""trust anchors and TAKs: load, pin, expire (RFC 9691, RFC 6480).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

import pathlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    TrustAnchor = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "load_trust_anchor",
]


def load_trust_anchor(path: pathlib.Path) -> TrustAnchor:
    """Pending behaviour defined by RFC 9691.

    Not implemented yet. See the ``anchors.load_trust_anchor()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("load_trust_anchor() is not implemented: RFC 9691")
