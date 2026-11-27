"""Resumable, fail-closed wizard session records.

The session file is canonical JSON. It records what each read-only stage observed
and what the next stage may reuse. It never stores a raw serial number, a device
fingerprint value, or a vendor transcript. ``state_sha256`` is tamper-evident, not
tamper-proof: it detects accidental edits and makes a deliberate edit visible, but
a compromised host can recompute it. The file is written atomically with owner-only
permissions where the host supports them.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from dataclasses import replace as dataclass_replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from cairn.approval.binding import ApprovalError, DeviceBinding, ToolBinding
from cairn.core.errors import CairnError
from cairn.core.tristate import Tri
from cairn.plan.planner import PlanFacts, PlanOptions, SlotPolicy

SESSION_KIND: Final = "cairn.wizard-session"
SESSION_SCHEMA_VERSION: Final = 1
MAX_SESSION_BYTES: Final = 8 * 1024 * 1024
DEFAULT_REUSE_SECONDS: Final = 600.0

STAGE_ORDER: Final[tuple[str, ...]] = (
    "doctor",
    "inspect",
    "provenance",
    "probe",
    "avb",
    "rollback",
    "plan",
    "approval",
)

STAGE_TITLES: Final[Mapping[str, str]] = {
    "doctor": "host and link readiness",
    "inspect": "package structure",
    "provenance": "vendor hash index",
    "probe": "device identity and state",
    "avb": "AVB signature and chain",
    "rollback": "rollback counters",
    "plan": "vendor-order plan and pre-approval safety",
    "approval": "approval binding",
}

_SESSION_ID_RE: Final = re.compile(r"^[0-9a-f]{32}$")
_HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")

_TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "kind",
        "session_id",
        "cairn_version",
        "created_at",
        "updated_at",
        "package_path",
        "index_path",
        "archive_sha256",
        "index_sha256",
        "stages",
        "device",
        "bundle",
        "plan",
        "pre_safety",
        "post_safety",
        "verdict",
        "outcome",
        "warnings",
        "state_sha256",
    }
)


class WizardError(CairnError):
    code = "WIZARD_ERROR"


class StageOutcome(StrEnum):
    PASS = "pass"  # noqa: S105 -- protocol value, not a credential.
    FAIL = "fail"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    SIMULATED = "simulated"


class SessionOutcome(StrEnum):
    CLEARED = "cleared"
    READY = "ready"
    FAILED = "failed"
    BLOCKED = "blocked"
    SIMULATED = "simulated"


@dataclass(frozen=True, slots=True)
class StageRecord:
    stage: str
    title: str
    outcome: StageOutcome
    detail: str
    at: datetime
    duration_ms: int
    input_fingerprint: str | None = None
    evidence_ids: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    payload: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if self.stage not in STAGE_ORDER:
            raise WizardError(f"unknown wizard stage {self.stage!r}")
        if self.title != STAGE_TITLES[self.stage]:
            raise WizardError("stage title does not match the registered wizard stage")
        if not self.detail.strip():
            raise WizardError("stage detail must not be empty")
        if self.at.tzinfo is None:
            raise WizardError("stage timestamp must be timezone-aware")
        if self.duration_ms < 0:
            raise WizardError("stage duration must not be negative")
        if (
            self.input_fingerprint is not None
            and _HEX64_RE.fullmatch(self.input_fingerprint) is None
        ):
            raise WizardError("stage input fingerprint must be 64 lowercase hex characters")
        for evidence_id in self.evidence_ids:
            if not evidence_id.strip():
                raise WizardError("stage evidence ids must not be empty")
        for warning in self.warnings:
            if not warning.strip():
                raise WizardError("stage warnings must not be empty")

    def to_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage,
            "title": self.title,
            "outcome": self.outcome.value,
            "detail": self.detail,
            "at": _timestamp(self.at),
            "duration_ms": self.duration_ms,
            "input_fingerprint": self.input_fingerprint,
            "evidence_ids": list(self.evidence_ids),
            "warnings": list(self.warnings),
            "payload": None if self.payload is None else dict(self.payload),
        }

    @classmethod
    def from_dict(cls, raw: object) -> StageRecord:
        mapping = _mapping(raw, "stage record")
        _exact_keys(
            mapping,
            {
                "stage",
                "title",
                "outcome",
                "detail",
                "at",
                "duration_ms",
                "input_fingerprint",
                "evidence_ids",
                "warnings",
                "payload",
            },
            "stage record",
        )
        try:
            outcome = StageOutcome(_str(mapping["outcome"], "stage outcome"))
        except ValueError as exc:
            raise WizardError(f"unknown stage outcome {mapping['outcome']!r}") from exc
        return cls(
            stage=_str(mapping["stage"], "stage name"),
            title=_str(mapping["title"], "stage title"),
            outcome=outcome,
            detail=_str(mapping["detail"], "stage detail"),
            at=_parse_timestamp(_str(mapping["at"], "stage timestamp")),
            duration_ms=_int(mapping["duration_ms"], "stage duration_ms"),
            input_fingerprint=_optional_str(
                mapping["input_fingerprint"], "stage input_fingerprint"
            ),
            evidence_ids=_str_tuple(mapping["evidence_ids"], "stage evidence_ids"),
            warnings=_str_tuple(mapping["warnings"], "stage warnings"),
            payload=_optional_mapping(mapping["payload"], "stage payload"),
        )


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    """Redacted device facts, never a raw serial or transcript."""

    source: str
    simulated: bool
    nonce: str | None = None
    fingerprint_sha256: str | None = None
    serial_sha256: str | None = None
    probed_at: datetime | None = None
    max_age_s: float | None = None
    facts: Mapping[str, str] | None = None
    identity: Mapping[str, str | None] | None = None
    identity_evidence_ids: tuple[str, ...] = ()
    lock_state: str | None = None
    slot_count: int | None = None
    current_slot: str | None = None

    def __post_init__(self) -> None:
        if self.source not in ("probed", "simulated", "caller", "offline", "none"):
            raise WizardError(f"unknown device source {self.source!r}")
        if self.probed_at is not None and self.probed_at.tzinfo is None:
            raise WizardError("device probed_at must be timezone-aware")
        if self.max_age_s is not None and self.max_age_s <= 0:
            raise WizardError("device max_age_s must be positive")
        for name, value in (("nonce", self.nonce), ("fingerprint", self.fingerprint_sha256)):
            if value is not None and not value:
                raise WizardError(f"device {name} must not be empty")
        if (
            self.fingerprint_sha256 is not None
            and _HEX64_RE.fullmatch(self.fingerprint_sha256) is None
        ):
            raise WizardError("device fingerprint must be 64 lowercase hex characters")
        if self.serial_sha256 is not None and _HEX64_RE.fullmatch(self.serial_sha256) is None:
            raise WizardError("device serial hash must be 64 lowercase hex characters")
        if self.slot_count is not None and self.slot_count <= 0:
            raise WizardError("device slot_count must be positive")

    @property
    def is_probed(self) -> bool:
        return self.source == "probed" and not self.simulated

    def is_fresh(self, now: datetime, max_age_s: float = DEFAULT_REUSE_SECONDS) -> bool:
        if not self.is_probed or self.probed_at is None:
            return False
        if now.tzinfo is None:
            raise WizardError("freshness check time must be timezone-aware")
        bound = self.max_age_s if self.max_age_s is not None else max_age_s
        bound = min(bound, max_age_s)
        age = (now - self.probed_at).total_seconds()
        return 0 <= age <= bound

    def binding(self) -> DeviceBinding | None:
        if self.nonce is None or self.fingerprint_sha256 is None:
            return None
        from cairn.approval.binding import DeviceBindingSource

        source = DeviceBindingSource.PROBED if self.is_probed else DeviceBindingSource.CALLER
        try:
            return DeviceBinding(
                nonce=self.nonce,
                fingerprint_sha256=self.fingerprint_sha256,
                source=source,
            )
        except ApprovalError as exc:
            raise WizardError(f"device record cannot form a binding: {exc}") from exc

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "simulated": self.simulated,
            "nonce": self.nonce,
            "fingerprint_sha256": self.fingerprint_sha256,
            "serial_sha256": self.serial_sha256,
            "probed_at": None if self.probed_at is None else _timestamp(self.probed_at),
            "max_age_s": None if self.max_age_s is None else float(self.max_age_s),
            "facts": None if self.facts is None else dict(sorted(self.facts.items())),
            "identity": None if self.identity is None else dict(self.identity),
            "identity_evidence_ids": list(self.identity_evidence_ids),
            "lock_state": self.lock_state,
            "slot_count": self.slot_count,
            "current_slot": self.current_slot,
        }

    @classmethod
    def from_dict(cls, raw: object) -> DeviceRecord:
        mapping = _mapping(raw, "device record")
        _exact_keys(
            mapping,
            {
                "source",
                "simulated",
                "nonce",
                "fingerprint_sha256",
                "serial_sha256",
                "probed_at",
                "max_age_s",
                "facts",
                "identity",
                "identity_evidence_ids",
                "lock_state",
                "slot_count",
                "current_slot",
            },
            "device record",
        )
        probed_raw = mapping["probed_at"]
        probed_at = (
            None if probed_raw is None else _parse_timestamp(_str(probed_raw, "device probed_at"))
        )
        max_age_raw = mapping["max_age_s"]
        max_age = None if max_age_raw is None else _float(max_age_raw, "device max_age_s")
        facts_raw = mapping["facts"]
        facts = None if facts_raw is None else _str_mapping(facts_raw, "device facts")
        identity_raw = mapping["identity"]
        identity = (
            None if identity_raw is None else _optional_str_mapping(identity_raw, "device identity")
        )
        slot_raw = mapping["slot_count"]
        slot_count = None if slot_raw is None else _int(slot_raw, "device slot_count")
        return cls(
            source=_str(mapping["source"], "device source"),
            simulated=_bool(mapping["simulated"], "device simulated"),
            nonce=_optional_str(mapping["nonce"], "device nonce"),
            fingerprint_sha256=_optional_str(
                mapping["fingerprint_sha256"], "device fingerprint_sha256"
            ),
            serial_sha256=_optional_str(mapping["serial_sha256"], "device serial_sha256"),
            probed_at=probed_at,
            max_age_s=max_age,
            facts=facts,
            identity=identity,
            identity_evidence_ids=_str_tuple(
                mapping["identity_evidence_ids"], "device identity_evidence_ids"
            ),
            lock_state=_optional_str(mapping["lock_state"], "device lock_state"),
            slot_count=slot_count,
            current_slot=_optional_str(mapping["current_slot"], "device current_slot"),
        )


@dataclass(frozen=True, slots=True)
class ApprovalBundle:
    """Everything an approval needs to bind, recorded at the plan stage."""

    plan_sha256: str
    evidence_snapshot_sha256: str
    archive_sha256: str
    package_hashes: tuple[tuple[str, str], ...]
    tools: tuple[ToolBinding, ...]
    pre_safety: Mapping[str, object]
    plan_options: Mapping[str, object]
    plan_facts: Mapping[str, object]

    def __post_init__(self) -> None:
        for name, value in (
            ("plan_sha256", self.plan_sha256),
            ("evidence_snapshot_sha256", self.evidence_snapshot_sha256),
            ("archive_sha256", self.archive_sha256),
        ):
            if _HEX64_RE.fullmatch(value) is None:
                raise WizardError(f"{name} must be 64 lowercase hex characters")
        if not self.package_hashes:
            raise WizardError("approval bundle must bind at least one package entry")
        names = [name for name, _ in self.package_hashes]
        if names != sorted(names):
            raise WizardError("approval bundle package hashes must be sorted by name")
        if len(names) != len(set(names)):
            raise WizardError("approval bundle repeats a package entry name")
        for name, digest in self.package_hashes:
            if not name:
                raise WizardError("approval bundle package entry name must not be empty")
            if _HEX64_RE.fullmatch(digest) is None:
                raise WizardError(f"approval bundle hash for {name!r} is not 64 hex characters")
        tool_names = [tool.name for tool in self.tools]
        if tool_names != sorted(tool_names):
            raise WizardError("approval bundle tools must be sorted by name")
        if len(tool_names) != len(set(tool_names)):
            raise WizardError("approval bundle repeats a tool name")

    def options(self) -> PlanOptions:
        return PlanOptions(
            wipe=_bool(self.plan_options["wipe"], "plan options wipe"),
            slot_policy=SlotPolicy(_str(self.plan_options["slot_policy"], "plan options slot")),
            retrofit_force=_bool(
                self.plan_options["retrofit_force"], "plan options retrofit_force"
            ),
        )

    def facts(self) -> PlanFacts:
        slot_count_raw = self.plan_facts["slot_count"]
        current_slot_raw = self.plan_facts["current_slot"]
        return PlanFacts(
            slot_count=None if slot_count_raw is None else _int(slot_count_raw, "plan slot_count"),
            current_slot=(
                None if current_slot_raw is None else _str(current_slot_raw, "plan current_slot")
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "plan_sha256": self.plan_sha256,
            "evidence_snapshot_sha256": self.evidence_snapshot_sha256,
            "archive_sha256": self.archive_sha256,
            "package_hashes": {name: digest for name, digest in self.package_hashes},
            "tools": [tool.to_dict() for tool in self.tools],
            "pre_safety": dict(self.pre_safety),
            "plan_options": dict(self.plan_options),
            "plan_facts": dict(self.plan_facts),
        }

    @classmethod
    def from_dict(cls, raw: object) -> ApprovalBundle:
        mapping = _mapping(raw, "approval bundle")
        _exact_keys(
            mapping,
            {
                "plan_sha256",
                "evidence_snapshot_sha256",
                "archive_sha256",
                "package_hashes",
                "tools",
                "pre_safety",
                "plan_options",
                "plan_facts",
            },
            "approval bundle",
        )
        hashes_raw = _mapping(mapping["package_hashes"], "approval bundle package_hashes")
        package_hashes: list[tuple[str, str]] = []
        for name, digest in hashes_raw.items():
            package_hashes.append(
                (
                    _str(name, "package entry name"),
                    _str(digest, f"package hash for {name!r}"),
                )
            )
        package_hashes.sort()
        tools_raw = mapping["tools"]
        if not isinstance(tools_raw, list):
            raise WizardError("approval bundle tools must be a list")
        tools: list[ToolBinding] = []
        for item in tools_raw:
            item_mapping = _mapping(item, "tool binding")
            _exact_keys(item_mapping, {"name", "version", "sha256"}, "tool binding")
            try:
                tools.append(
                    ToolBinding(
                        name=_str(item_mapping["name"], "tool name"),
                        version=_optional_str(item_mapping["version"], "tool version"),
                        sha256=_optional_str(item_mapping["sha256"], "tool sha256"),
                    )
                )
            except ApprovalError as exc:
                raise WizardError(f"invalid approval tool binding: {exc}") from exc
        return cls(
            plan_sha256=_str(mapping["plan_sha256"], "plan_sha256"),
            evidence_snapshot_sha256=_str(
                mapping["evidence_snapshot_sha256"], "evidence_snapshot_sha256"
            ),
            archive_sha256=_str(mapping["archive_sha256"], "archive_sha256"),
            package_hashes=tuple(package_hashes),
            tools=tuple(tools),
            pre_safety=_mapping(mapping["pre_safety"], "approval bundle pre_safety"),
            plan_options=_mapping(mapping["plan_options"], "approval bundle plan_options"),
            plan_facts=_mapping(mapping["plan_facts"], "approval bundle plan_facts"),
        )


@dataclass(frozen=True, slots=True)
class WizardSession:
    schema_version: int
    session_id: str
    cairn_version: str
    created_at: datetime
    updated_at: datetime
    package_path: str
    index_path: str
    stages: tuple[StageRecord, ...] = ()
    device: DeviceRecord | None = None
    bundle: ApprovalBundle | None = None
    archive_sha256: str | None = None
    index_sha256: str | None = None
    plan: Mapping[str, object] | None = None
    pre_safety: Mapping[str, object] | None = None
    post_safety: Mapping[str, object] | None = None
    verdict: str | None = None
    outcome: SessionOutcome = SessionOutcome.BLOCKED
    warnings: tuple[str, ...] = ()
    state_sha256: str = ""

    def __post_init__(self) -> None:
        if self.schema_version != SESSION_SCHEMA_VERSION:
            raise WizardError(f"unsupported wizard session schema {self.schema_version}")
        if _SESSION_ID_RE.fullmatch(self.session_id) is None:
            raise WizardError("wizard session id must be 32 lowercase hex characters")
        if not self.cairn_version.strip():
            raise WizardError("wizard session cairn_version must not be empty")
        for name, value in (("package_path", self.package_path), ("index_path", self.index_path)):
            if not value.strip():
                raise WizardError(f"wizard session {name} must not be empty")
        if self.created_at.tzinfo is None or self.updated_at.tzinfo is None:
            raise WizardError("wizard session timestamps must be timezone-aware")
        if self.updated_at < self.created_at:
            raise WizardError("wizard session updated_at is before created_at")
        seen: set[str] = set()
        last = -1
        for record in self.stages:
            if record.stage in seen:
                raise WizardError(f"wizard session repeats stage {record.stage!r}")
            seen.add(record.stage)
            position = STAGE_ORDER.index(record.stage)
            if position <= last:
                raise WizardError("wizard session stages are out of order")
            last = position
        self._validate_outcome()
        hashes: dict[str, str | None] = {
            "archive_sha256": self.archive_sha256,
            "index_sha256": self.index_sha256,
        }
        for hash_name, digest in hashes.items():
            if digest is not None and _HEX64_RE.fullmatch(digest) is None:
                raise WizardError(f"wizard session {hash_name} must be 64 lowercase hex characters")
        if self.verdict is not None and self.verdict not in {state.name for state in Tri}:
            raise WizardError("wizard session verdict must be TRUE, FALSE, UNKNOWN, or null")
        if self.state_sha256 and _HEX64_RE.fullmatch(self.state_sha256) is None:
            raise WizardError("wizard session state hash must be 64 lowercase hex characters")
        for warning in self.warnings:
            if not warning.strip():
                raise WizardError("wizard session warnings must not be empty")

    def _validate_outcome(self) -> None:
        outcomes = {record.stage: record.outcome for record in self.stages}
        if self.outcome is SessionOutcome.READY:
            required = set(STAGE_ORDER) - {"approval"}
            if (
                set(outcomes) != set(STAGE_ORDER)
                or outcomes.get("approval") is not StageOutcome.SKIPPED
                or any(outcomes[name] is not StageOutcome.PASS for name in required)
                or self.pre_safety is None
                or self.pre_safety.get("can_proceed") is not True
            ):
                raise WizardError("READY session does not have a complete passing preflight")
        if self.outcome is SessionOutcome.CLEARED and (
            set(outcomes) != set(STAGE_ORDER)
            or any(outcome is not StageOutcome.PASS for outcome in outcomes.values())
        ):
            raise WizardError("CLEARED session does not have every stage passing")
        if self.outcome is SessionOutcome.SIMULATED and not any(
            outcome is StageOutcome.SIMULATED for outcome in outcomes.values()
        ):
            raise WizardError("SIMULATED session has no simulated stage")
        if self.bundle is None:
            return
        if self.device is None or self.archive_sha256 is None or self.plan is None:
            raise WizardError("approval bundle requires device, archive hash, and plan")
        if self.pre_safety is None:
            raise WizardError("approval bundle requires a pre-approval safety report")
        if self.archive_sha256 != self.bundle.archive_sha256:
            raise WizardError("approval bundle archive hash does not match the session")
        if self.plan.get("plan_sha256") != self.bundle.plan_sha256:
            raise WizardError("approval bundle plan hash does not match the session")
        if self.pre_safety != self.bundle.pre_safety:
            raise WizardError("approval bundle safety report does not match the session")

    @property
    def kind(self) -> str:
        return SESSION_KIND

    @property
    def tri_verdict(self) -> Tri | None:
        return None if self.verdict is None else Tri[self.verdict]

    def stage(self, name: str) -> StageRecord | None:
        for record in self.stages:
            if record.stage == name:
                return record
        return None

    def with_stage(self, record: StageRecord) -> WizardSession:
        remaining = tuple(item for item in self.stages if item.stage != record.stage)
        stages = tuple(sorted((*remaining, record), key=lambda item: STAGE_ORDER.index(item.stage)))
        return self.replace(stages=stages, updated_at=record.at)

    def replace(self, **changes: Any) -> WizardSession:
        if "state_sha256" in changes:
            raise WizardError("wizard session state hash is managed internally")
        candidate = dataclass_replace(self, state_sha256="", **changes)
        return candidate.with_state_hash()

    def with_state_hash(self) -> WizardSession:
        payload = self.to_payload(include_state=False)
        return dataclass_replace(self, state_sha256=_state_hash(payload))

    def to_payload(self, *, include_state: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": self.schema_version,
            "kind": SESSION_KIND,
            "session_id": self.session_id,
            "cairn_version": self.cairn_version,
            "created_at": _timestamp(self.created_at),
            "updated_at": _timestamp(self.updated_at),
            "package_path": self.package_path,
            "index_path": self.index_path,
            "archive_sha256": self.archive_sha256,
            "index_sha256": self.index_sha256,
            "stages": [record.to_dict() for record in self.stages],
            "device": None if self.device is None else self.device.to_dict(),
            "bundle": None if self.bundle is None else self.bundle.to_dict(),
            "plan": None if self.plan is None else dict(self.plan),
            "pre_safety": None if self.pre_safety is None else dict(self.pre_safety),
            "post_safety": None if self.post_safety is None else dict(self.post_safety),
            "verdict": self.verdict,
            "outcome": self.outcome.value,
            "warnings": list(self.warnings),
        }
        if include_state:
            payload["state_sha256"] = self.state_sha256
        return payload

    def to_dict(self) -> dict[str, object]:
        return self.to_payload()

    def to_json(self) -> str:
        return (
            json.dumps(
                self.to_payload(),
                indent=2,
                sort_keys=True,
                ensure_ascii=True,
            )
            + "\n"
        )

    @classmethod
    def from_dict(cls, raw: object) -> WizardSession:
        mapping = _mapping(raw, "wizard session")
        _exact_keys(mapping, _TOP_LEVEL_KEYS, "wizard session")
        if mapping["kind"] != SESSION_KIND:
            raise WizardError("wizard session kind is not cairn.wizard-session")
        stages_raw = mapping["stages"]
        if not isinstance(stages_raw, list):
            raise WizardError("wizard session stages must be a list")
        device_raw = mapping["device"]
        bundle_raw = mapping["bundle"]
        outcome_raw = _str(mapping["outcome"], "wizard session outcome")
        try:
            outcome = SessionOutcome(outcome_raw)
        except ValueError as exc:
            raise WizardError(f"unknown wizard session outcome {outcome_raw!r}") from exc
        session = cls(
            schema_version=_int(mapping["schema_version"], "wizard session schema_version"),
            session_id=_str(mapping["session_id"], "wizard session id"),
            cairn_version=_str(mapping["cairn_version"], "wizard session cairn_version"),
            created_at=_parse_timestamp(_str(mapping["created_at"], "wizard session created_at")),
            updated_at=_parse_timestamp(_str(mapping["updated_at"], "wizard session updated_at")),
            package_path=_str(mapping["package_path"], "wizard session package_path"),
            index_path=_str(mapping["index_path"], "wizard session index_path"),
            stages=tuple(StageRecord.from_dict(item) for item in stages_raw),
            device=None if device_raw is None else DeviceRecord.from_dict(device_raw),
            bundle=None if bundle_raw is None else ApprovalBundle.from_dict(bundle_raw),
            archive_sha256=_optional_str(
                mapping["archive_sha256"], "wizard session archive_sha256"
            ),
            index_sha256=_optional_str(mapping["index_sha256"], "wizard session index_sha256"),
            plan=_optional_mapping(mapping["plan"], "wizard session plan"),
            pre_safety=_optional_mapping(mapping["pre_safety"], "wizard session pre_safety"),
            post_safety=_optional_mapping(mapping["post_safety"], "wizard session post_safety"),
            verdict=_optional_str(mapping["verdict"], "wizard session verdict"),
            outcome=outcome,
            warnings=_str_tuple(mapping["warnings"], "wizard session warnings"),
            state_sha256=_str(mapping["state_sha256"], "wizard session state_sha256"),
        )
        expected = _state_hash(session.to_payload(include_state=False))
        if session.state_sha256 != expected:
            raise WizardError(
                "wizard session state hash does not match its contents; the file was edited"
            )
        return session


def new_session(
    *,
    package_path: Path,
    index_path: Path,
    cairn_version: str,
    now: datetime | None = None,
    session_id: str | None = None,
) -> WizardSession:
    timestamp = now if now is not None else datetime.now(UTC)
    if timestamp.tzinfo is None:
        raise WizardError("session timestamp must be timezone-aware")
    identifier = session_id if session_id is not None else os.urandom(16).hex()
    session = WizardSession(
        schema_version=SESSION_SCHEMA_VERSION,
        session_id=identifier,
        cairn_version=cairn_version,
        created_at=timestamp,
        updated_at=timestamp,
        package_path=str(package_path),
        index_path=str(index_path),
    )
    return session.with_state_hash()


def load_session(path: Path, *, max_bytes: int = MAX_SESSION_BYTES) -> WizardSession:
    if max_bytes <= 0:
        raise WizardError("session byte limit must be positive")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise WizardError(f"cannot stat wizard session {path}: {exc}") from exc
    if size > max_bytes:
        raise WizardError(f"wizard session is {size} bytes, above the {max_bytes}-byte limit")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise WizardError(f"cannot read wizard session {path}: {exc}") from exc
    try:
        document: object = json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise WizardError(f"wizard session is not valid JSON: {exc}") from exc
    except RecursionError as exc:
        raise WizardError("wizard session is nested too deeply") from exc
    return WizardSession.from_dict(document)


def save_session(
    path: Path,
    session: WizardSession,
    *,
    max_bytes: int = MAX_SESSION_BYTES,
) -> None:
    text = session.to_json()
    encoded = text.encode("utf-8")
    if len(encoded) > max_bytes:
        raise WizardError(
            f"wizard session is {len(encoded)} bytes, above the {max_bytes}-byte limit"
        )
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise WizardError(f"cannot create wizard session directory {parent}: {exc}") from exc
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary_path = Path(temporary)
    try:
        with suppress(OSError):
            os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except OSError as exc:
        with suppress(OSError):
            temporary_path.unlink(missing_ok=True)
        raise WizardError(f"cannot write wizard session {path}: {exc}") from exc


def _state_hash(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise WizardError(f"invalid timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        raise WizardError("timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _mapping(value: object, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WizardError(f"{what} must be a JSON object")
    result: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise WizardError(f"{what} keys must be strings")
        result[key] = item
    return result


def _optional_mapping(value: object, what: str) -> Mapping[str, object] | None:
    if value is None:
        return None
    return _mapping(value, what)


def _str_mapping(value: object, what: str) -> Mapping[str, str]:
    mapping = _mapping(value, what)
    result: dict[str, str] = {}
    for key, item in mapping.items():
        result[key] = _str(item, f"{what}[{key!r}]")
    return result


def _optional_str_mapping(value: object, what: str) -> Mapping[str, str | None]:
    mapping = _mapping(value, what)
    result: dict[str, str | None] = {}
    for key, item in mapping.items():
        result[key] = _optional_str(item, f"{what}[{key!r}]")
    return result


def _exact_keys(mapping: Mapping[str, Any], expected: set[str] | frozenset[str], what: str) -> None:
    keys = set(mapping)
    missing = expected - keys
    extra = keys - expected
    if missing:
        raise WizardError(f"{what} is missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise WizardError(f"{what} has unknown keys: {', '.join(sorted(extra))}")


def _str(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise WizardError(f"{what} must be a string")
    return value


def _optional_str(value: object, what: str) -> str | None:
    if value is None:
        return None
    return _str(value, what)


def _str_tuple(value: object, what: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise WizardError(f"{what} must be a list")
    return tuple(_str(item, what) for item in value)


def _int(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WizardError(f"{what} must be an integer")
    return value


def _float(value: object, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise WizardError(f"{what} must be a number")
    return float(value)


def _bool(value: object, what: str) -> bool:
    if not isinstance(value, bool):
        raise WizardError(f"{what} must be a boolean")
    return value


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WizardError(f"wizard session repeats JSON key {key!r}")
        result[key] = value
    return result
