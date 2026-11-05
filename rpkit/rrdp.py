"""notification, snapshot and delta fetch plus desync recovery (RFC 8182, RFC 9697).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    DeltaFile = Any  # placeholder: give it a real type in the milestone that needs it
    Notification = Any  # placeholder: give it a real type in the milestone that needs it
    Repository = Any  # placeholder: give it a real type in the milestone that needs it
    SessionState = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "apply_delta",
    "fetch_notification",
]


def fetch_notification(uri: str) -> Notification:
    """Pending behaviour defined by RFC 8182.

    Not implemented yet. See the ``rrdp.fetch_notification()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("fetch_notification() is not implemented: RFC 8182")


def apply_delta(state: SessionState, delta: DeltaFile) -> Repository:
    """Pending behaviour defined by RFC 8182, RFC 9697.

    Not implemented yet. See the ``rrdp.apply_delta()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("apply_delta() is not implemented: RFC 8182, RFC 9697")
