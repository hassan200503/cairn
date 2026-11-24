"""Evidence graph with boot-epoch invalidation and JSON persistence.

A probe is only valid for the boot epoch in which it was taken. Recording a new
epoch does not delete history, but every fact from an earlier epoch becomes
unusable. Serialization preserves the epoch so a resumed session cannot silently
reuse pre-reboot evidence.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime
from typing import Any, Final

from cairn.core.errors import EvidenceError
from cairn.core.evidence import Evidence, EvidenceSource

SCHEMA_VERSION: Final = 1


class EvidenceGraph:
    """Latest fact per key, stamped with the device boot epoch."""

    def __init__(self, *, boot_id: str = "boot-0") -> None:
        if not boot_id:
            raise ValueError("boot_id must not be empty")
        self._boot_id = boot_id
        self._facts: dict[str, Evidence[Any]] = {}
        self._order: list[str] = []

    @property
    def boot_id(self) -> str:
        return self._boot_id

    def record(self, key: str, evidence: Evidence[Any]) -> Evidence[Any]:
        """Store a fact under the current epoch, stamping it if necessary."""
        if not key:
            raise EvidenceError("evidence key must not be empty")
        if evidence.boot_id is None:
            evidence = replace(evidence, boot_id=self._boot_id)
        elif evidence.boot_id != self._boot_id:
            raise EvidenceError(
                f"evidence for {key!r} belongs to boot {evidence.boot_id!r}, "
                f"current boot is {self._boot_id!r}"
            )
        self._store(key, evidence)
        return evidence

    def reboot(self, boot_id: str) -> None:
        """Switch epochs. Old facts remain readable but are no longer usable."""
        if not boot_id:
            raise ValueError("boot_id must not be empty")
        if boot_id == self._boot_id:
            raise EvidenceError(f"device is already in boot epoch {boot_id!r}")
        self._boot_id = boot_id

    def get(self, key: str) -> Evidence[Any] | None:
        return self._facts.get(key)

    def is_usable(self, key: str, now: datetime) -> bool:
        evidence = self._facts.get(key)
        if evidence is None:
            return False
        if evidence.boot_id != self._boot_id:
            return False
        return evidence.is_usable(now)

    def require_usable(self, key: str, now: datetime) -> Evidence[Any]:
        evidence = self._facts.get(key)
        if evidence is None:
            raise EvidenceError(f"no evidence for {key!r}")
        if evidence.boot_id != self._boot_id:
            raise EvidenceError(
                f"evidence for {key!r} is from boot {evidence.boot_id!r}, "
                f"current boot is {self._boot_id!r}"
            )
        if evidence.source is EvidenceSource.INFERRED:
            raise EvidenceError(f"evidence for {key!r} is inferred and cannot be used")
        if not evidence.is_fresh(now):
            raise EvidenceError(f"evidence for {key!r} is stale")
        return evidence

    def keys(self) -> tuple[str, ...]:
        return tuple(self._order)

    def facts(self) -> dict[str, Evidence[Any]]:
        return {key: self._facts[key] for key in self._order}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "boot_id": self._boot_id,
            "facts": {key: self._facts[key].to_dict() for key in self._order},
        }

    @classmethod
    def from_dict(cls, raw: object) -> EvidenceGraph:
        if not isinstance(raw, dict):
            raise EvidenceError("evidence graph must be a JSON object")
        if raw.get("schema_version") != SCHEMA_VERSION:
            raise EvidenceError(f"evidence graph schema_version must be {SCHEMA_VERSION}")
        boot_id = raw.get("boot_id")
        if not isinstance(boot_id, str) or not boot_id:
            raise EvidenceError("evidence graph boot_id must be a non-empty string")
        raw_facts = raw.get("facts")
        if not isinstance(raw_facts, dict):
            raise EvidenceError("evidence graph facts must be an object")

        graph = cls(boot_id=boot_id)
        for key, raw_evidence in raw_facts.items():
            if not isinstance(key, str) or not key:
                raise EvidenceError("evidence keys must be non-empty strings")
            graph._store(key, Evidence.from_dict(raw_evidence))
        return graph

    def dumps(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"

    @classmethod
    def loads(cls, text: str) -> EvidenceGraph:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"evidence graph is not valid JSON: {exc}") from exc
        return cls.from_dict(raw)

    def _store(self, key: str, evidence: Evidence[Any]) -> None:
        if key not in self._facts:
            self._order.append(key)
        self._facts[key] = evidence
