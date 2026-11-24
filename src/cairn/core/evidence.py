"""Facts with provenance, observation time, and freshness bounds.

A probe taken before a reboot must not satisfy a precondition after the reboot.
Catalog claims and user assertions are weaker evidence than direct probes. Safety
rules consume Evidence, never bare booleans.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import IntEnum

from cairn.core.tristate import Tri


class EvidenceSource(IntEnum):
    """Ordered from weakest to strongest evidence for safety decisions."""

    INFERRED = 0
    USER = 1
    CATALOG = 2
    PACKAGE = 3
    PROBED = 4

    @property
    def is_probe(self) -> bool:
        return self is EvidenceSource.PROBED


@dataclass(frozen=True, slots=True)
class Evidence[T]:
    """A single observed or asserted fact.

    ``state`` describes whether the proposition holds. ``value`` carries optional
    data associated with the observation (a serial number, a version string, etc.).
    """

    state: Tri
    source: EvidenceSource
    observed_at: datetime
    value: T | None = None
    max_age: timedelta | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.max_age is not None and self.max_age <= timedelta(0):
            raise ValueError("max_age must be positive")

    def is_fresh(self, now: datetime) -> bool:
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        if self.max_age is None:
            return True
        return now - self.observed_at <= self.max_age

    def age(self, now: datetime) -> timedelta:
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        return now - self.observed_at

    def is_usable(self, now: datetime) -> bool:
        """Fresh evidence that is not an inference is usable in safety rules."""
        return self.is_fresh(now) and self.source is not EvidenceSource.INFERRED

    @classmethod
    def probed(
        cls,
        state: Tri,
        observed_at: datetime,
        *,
        value: T | None = None,
        max_age: timedelta | None = None,
        detail: str = "",
    ) -> Evidence[T]:
        return cls(
            state=state,
            source=EvidenceSource.PROBED,
            observed_at=observed_at,
            value=value,
            max_age=max_age,
            detail=detail,
        )

    @classmethod
    def unknown(
        cls,
        observed_at: datetime,
        *,
        source: EvidenceSource = EvidenceSource.INFERRED,
        max_age: timedelta | None = None,
        detail: str = "",
    ) -> Evidence[T]:
        return cls(
            state=Tri.UNKNOWN,
            source=source,
            observed_at=observed_at,
            value=None,
            max_age=max_age,
            detail=detail,
        )
