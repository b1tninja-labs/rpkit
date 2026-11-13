"""What an RPKI object check found: an error that makes the object invalid, or a warning.

RFC 6488 section 3, RFC 9582 section 5 and RFC 9286 section 4.4 all end the same way: an object
that fails a MUST is discarded and treated as though it were not there. A relying party still
wants to say why, and to say what it noticed in objects it accepted (a SHOULD that was broken, a
rule the RFC says future relying parties will enforce). A :class:`Finding` is one such line; the
check functions return them, and nothing is hidden by being a warning.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

__all__ = ["Finding", "Severity", "errors", "warnings"]


class Severity(enum.StrEnum):
    """``ERROR``: the object is invalid. ``WARNING``: accepted, but the RFC asked for better."""

    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class Finding:
    """One result of a check: its severity, a stable rule name and the text.

    ``rule`` is short and stable (``"roa.maxlength-superfluous"``) so a caller can count or
    suppress by name. ``spec`` says where the obligation comes from (``"RFC 9582 section
    4.3.2.2"``).
    """

    severity: Severity
    rule: str
    message: str
    spec: str = ""

    def __str__(self) -> str:
        where = f" ({self.spec})" if self.spec else ""
        return f"{self.severity.value}: {self.rule}: {self.message}{where}"


def errors(findings: tuple[Finding, ...] | list[Finding]) -> tuple[Finding, ...]:
    """The findings that make an object invalid."""
    return tuple(f for f in findings if f.severity is Severity.ERROR)


def warnings(findings: tuple[Finding, ...] | list[Finding]) -> tuple[Finding, ...]:
    """The findings that do not."""
    return tuple(f for f in findings if f.severity is Severity.WARNING)
