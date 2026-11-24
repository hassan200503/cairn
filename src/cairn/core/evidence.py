"""Facts with provenance, observation time, and freshness bounds.

A probe taken before a reboot must not satisfy a precondition after the reboot.
Catalog claims and user assertions are weaker evidence than direct probes. Safety
rules consume Evidence, never bare booleans.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import IntEnum
from typing import Any

from cairn.core.errors import EvidenceError
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
    boot_id: str | None = None

    def __post_init__(self) -> None:
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.max_age is not None and self.max_age <= timedelta(0):
            raise ValueError("max_age must be positive")

    @property
    def evidence_id(self) -> str:
        """Deterministic ID for journal and report references."""
        payload = json.dumps(
            {
                "state": self.state.name,
                "source": self.source.name,
                "observed_at": self.observed_at.isoformat(),
                "value": self.value,
                "max_age_s": None if self.max_age is None else self.max_age.total_seconds(),
                "detail": self.detail,
                "boot_id": self.boot_id,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=repr,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "state": self.state.name,
            "source": self.source.name,
            "observed_at": self.observed_at.isoformat(),
            "value": self.value,
            "max_age_s": None if self.max_age is None else self.max_age.total_seconds(),
            "detail": self.detail,
            "boot_id": self.boot_id,
        }

    @classmethod
    def from_dict(cls, raw: object) -> Evidence[Any]:
        """Load and verify a serialized evidence record."""
        if not isinstance(raw, dict):
            raise EvidenceError("evidence must be a JSON object")

        try:
            state = Tri[raw["state"]]
        except (KeyError, TypeError) as exc:
            raise EvidenceError("evidence state must be TRUE, FALSE, or UNKNOWN") from exc
        try:
            source = EvidenceSource[raw["source"]]
        except (KeyError, TypeError) as exc:
            raise EvidenceError("evidence source is not a known source") from exc

        observed_raw = raw.get("observed_at")
        if not isinstance(observed_raw, str):
            raise EvidenceError("evidence observed_at must be an ISO-8601 string")
        try:
            observed_at = datetime.fromisoformat(observed_raw)
        except ValueError as exc:
            raise EvidenceError(f"invalid evidence timestamp {observed_raw!r}") from exc
        if observed_at.tzinfo is None:
            raise EvidenceError("evidence timestamp must include a timezone")

        max_age_s = raw.get("max_age_s")
        max_age: timedelta | None
        if max_age_s is None:
            max_age = None
        elif isinstance(max_age_s, bool) or not isinstance(max_age_s, (int, float)):
            raise EvidenceError("evidence max_age_s must be a number or null")
        elif max_age_s <= 0:
            raise EvidenceError("evidence max_age_s must be positive")
        else:
            max_age = timedelta(seconds=float(max_age_s))

        value = raw.get("value")
        try:
            json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise EvidenceError("evidence value must be JSON-serializable") from exc

        detail = raw.get("detail", "")
        if not isinstance(detail, str):
            raise EvidenceError("evidence detail must be a string")
        boot_id = raw.get("boot_id")
        if boot_id is not None and not isinstance(boot_id, str):
            raise EvidenceError("evidence boot_id must be a string or null")

        evidence: Evidence[Any] = cls(
            state=state,
            source=source,
            observed_at=observed_at,
            value=value,
            max_age=max_age,
            detail=detail,
            boot_id=boot_id,
        )

        recorded_id = raw.get("evidence_id")
        if recorded_id is not None:
            if not isinstance(recorded_id, str):
                raise EvidenceError("evidence_id must be a string")
            if recorded_id != evidence.evidence_id:
                raise EvidenceError(
                    f"evidence_id mismatch for {recorded_id!r}; record is corrupted or edited"
                )
        return evidence

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
        boot_id: str | None = None,
    ) -> Evidence[T]:
        return cls(
            state=state,
            source=EvidenceSource.PROBED,
            observed_at=observed_at,
            value=value,
            max_age=max_age,
            detail=detail,
            boot_id=boot_id,
        )

    @classmethod
    def unknown(
        cls,
        observed_at: datetime,
        *,
        source: EvidenceSource = EvidenceSource.INFERRED,
        max_age: timedelta | None = None,
        detail: str = "",
        boot_id: str | None = None,
    ) -> Evidence[T]:
        return cls(
            state=Tri.UNKNOWN,
            source=source,
            observed_at=observed_at,
            value=None,
            max_age=max_age,
            detail=detail,
            boot_id=boot_id,
        )
