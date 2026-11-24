"""Three-valued logic for safety decisions.

Boolean logic is unsafe for flashing: "I could not read the rollback index" is not
the same as "the rollback index is safe". Every safety input is TRUE, FALSE, or
UNKNOWN. TRUE passes, FALSE always blocks, and UNKNOWN blocks unless a catalog
entry explicitly marks the rule overridable.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import IntEnum


class Tri(IntEnum):
    """A three-valued fact. Ordered so that the lowest value is the safest."""

    FALSE = 0
    UNKNOWN = 1
    TRUE = 2

    @property
    def is_true(self) -> bool:
        return self is Tri.TRUE

    @property
    def is_false(self) -> bool:
        return self is Tri.FALSE

    @property
    def is_unknown(self) -> bool:
        return self is Tri.UNKNOWN

    @property
    def blocks(self) -> bool:
        """Whether this fact prevents an operation without an override."""
        return self is not Tri.TRUE

    def and_(self, other: Tri) -> Tri:
        """Kleene AND: FALSE dominates, then UNKNOWN, otherwise TRUE."""
        return Tri(min(int(self), int(other)))

    def or_(self, other: Tri) -> Tri:
        """Kleene OR: TRUE dominates, then UNKNOWN, otherwise FALSE."""
        return Tri(max(int(self), int(other)))

    def negate(self) -> Tri:
        if self is Tri.TRUE:
            return Tri.FALSE
        if self is Tri.FALSE:
            return Tri.TRUE
        return Tri.UNKNOWN

    def __bool__(self) -> bool:
        raise TypeError("Tri is not truthy; use .is_true, .is_false, or .blocks")

    @classmethod
    def from_bool(cls, value: bool) -> Tri:
        return Tri.TRUE if value else Tri.FALSE

    @classmethod
    def all_of(cls, values: Iterable[Tri]) -> Tri:
        """Combine facts with Kleene AND. An empty set is vacuously TRUE."""
        result = Tri.TRUE
        for value in values:
            result = result.and_(value)
        return result

    @classmethod
    def any_of(cls, values: Iterable[Tri]) -> Tri:
        """Combine facts with Kleene OR. An empty set is vacuously FALSE."""
        result = Tri.FALSE
        for value in values:
            result = result.or_(value)
        return result
