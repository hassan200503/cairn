"""Safety rule engine.

Rules consume evidence-backed checks, never bare booleans. A FALSE result always
blocks and can never be overridden. An UNKNOWN result blocks unless the rule is
explicitly overridable, and an override records a human decision without turning
the UNKNOWN into TRUE.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Final

from cairn.core.errors import ConfigurationError
from cairn.core.evidence import Evidence
from cairn.core.tristate import Tri
from cairn.provenance.hash_index import ProvenanceResult
from cairn.tools.manifest import ToolReport

_RULE_ID_RE: Final = re.compile(r"^SR-\d{3}$")
_APPROVAL_RULE_ID: Final = "SR-018"
_NEVER_OVERRIDABLE: Final[frozenset[str]] = frozenset(
    {"SR-003", "SR-004", "SR-010", "SR-012", "SR-013", "SR-018"}
)


class SafetyError(ConfigurationError):
    code = "SAFETY_ENGINE_ERROR"


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """Static policy for one rule."""

    rule_id: str
    title: str
    unknown_overridable: bool = False
    source_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if _RULE_ID_RE.fullmatch(self.rule_id) is None:
            raise SafetyError(f"invalid rule id {self.rule_id!r}")
        if not self.title.strip():
            raise SafetyError(f"{self.rule_id} must have a title")
        if self.unknown_overridable and self.rule_id in _NEVER_OVERRIDABLE:
            raise SafetyError(f"{self.rule_id} is critical and must not be overridable")


@dataclass(frozen=True, slots=True)
class CheckState:
    """A verified or unverified check supplied by another subsystem."""

    state: Tri
    detail: str
    evidence_ids: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.detail.strip():
            raise SafetyError("check detail must not be empty")
        for evidence_id in self.evidence_ids:
            if not evidence_id.strip():
                raise SafetyError("evidence ids must not be empty")
        for warning in self.warnings:
            if not warning.strip():
                raise SafetyError("check warnings must not be empty")


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    product: str
    variant: str | None = None
    hw_revision: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.product, "device product")
        if self.variant is not None:
            _require_text(self.variant, "device variant")
        if self.hw_revision is not None:
            _require_text(self.hw_revision, "device hw-revision")


@dataclass(frozen=True, slots=True)
class PackageIdentity:
    product: str
    variant: str | None = None
    hw_revision: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.product, "package product")
        if self.variant is not None:
            _require_text(self.variant, "package variant")
        if self.hw_revision is not None:
            _require_text(self.hw_revision, "package hw-revision")


@dataclass(frozen=True, slots=True)
class SafetyContext:
    """Inputs available to the rules for one evaluation."""

    provenance: ProvenanceResult | None = None
    tool: ToolReport | None = None
    expected_tool: str | None = None
    lock_state: Evidence[Any] | None = None
    avb_key: CheckState | None = None
    avb_chain: CheckState | None = None
    rollback_oracle: CheckState | None = None
    device_identity: DeviceIdentity | None = None
    package_identity: PackageIdentity | None = None
    identity_evidence_ids: tuple[str, ...] = ()
    approval: CheckState | None = None
    recovery_readiness: CheckState | None = None
    vault_backup: CheckState | None = None
    merge_state: CheckState | None = None


@dataclass(frozen=True, slots=True)
class RuleResult:
    rule_id: str
    state: Tri
    reason: str
    evidence_ids: tuple[str, ...] = ()
    source_refs: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    overridable: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "state": self.state.name,
            "reason": self.reason,
            "evidence_ids": list(self.evidence_ids),
            "source_refs": list(self.source_refs),
            "warnings": list(self.warnings),
            "overridable": self.overridable,
        }


@dataclass(frozen=True, slots=True)
class OverrideRequest:
    """An operator's request to proceed despite an overridable UNKNOWN."""

    rule_id: str
    operator: str
    reason: str
    timestamp: datetime

    def __post_init__(self) -> None:
        _require_text(self.operator, "override operator")
        _require_text(self.reason, "override reason")
        if len(self.reason.strip()) < 10:
            raise SafetyError("override reason must be at least 10 characters")
        if self.timestamp.tzinfo is None:
            raise SafetyError("override timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class OverrideRecord:
    rule_id: str
    operator: str
    reason: str
    timestamp: str
    evidence_snapshot_sha256: str
    report_text: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "operator": self.operator,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "evidence_snapshot_sha256": self.evidence_snapshot_sha256,
            "report_text": self.report_text,
        }


@dataclass(frozen=True, slots=True)
class SafetyReport:
    rules: tuple[RuleResult, ...]
    overrides: tuple[OverrideRecord, ...]
    verdict: Tri
    can_proceed: bool
    blocking: tuple[str, ...]
    evidence_snapshot_sha256: str
    report_text: str
    snapshot_excludes: tuple[str, ...] = ()

    def rule(self, rule_id: str) -> RuleResult | None:
        for result in self.rules:
            if result.rule_id == rule_id:
                return result
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict.name,
            "can_proceed": self.can_proceed,
            "blocking": list(self.blocking),
            "evidence_snapshot_sha256": self.evidence_snapshot_sha256,
            "snapshot_excludes": list(self.snapshot_excludes),
            "rules": [result.to_dict() for result in self.rules],
            "overrides": [override.to_dict() for override in self.overrides],
            "report_text": self.report_text,
        }


type RuleEvaluator = Callable[[SafetyContext, datetime, RuleSpec], RuleResult]


def _result(
    spec: RuleSpec,
    state: Tri,
    reason: str,
    *,
    evidence_ids: Iterable[str] = (),
    warnings: Iterable[str] = (),
) -> RuleResult:
    return RuleResult(
        rule_id=spec.rule_id,
        state=state,
        reason=reason,
        evidence_ids=tuple(dict.fromkeys(evidence_ids)),
        source_refs=spec.source_refs,
        warnings=tuple(warnings),
        overridable=spec.unknown_overridable,
    )


_SR_001 = RuleSpec(
    "SR-001",
    "device identity matches the package",
    source_refs=("SAFETY_RULES SR-001", "T08 package metadata"),
)
_SR_002 = RuleSpec(
    "SR-002",
    "package matches the vendor hash index",
    unknown_overridable=True,
    source_refs=("SAFETY_RULES SR-002", "T09 local hash index"),
)
_SR_003 = RuleSpec(
    "SR-003",
    "AVB chain and VBMeta digest verify",
    source_refs=("SAFETY_RULES SR-003", "AOSP AVB"),
)
_SR_004 = RuleSpec(
    "SR-004",
    "rollback index is at least the device's stored value",
    source_refs=("SAFETY_RULES SR-004", "AOSP AVB rollback index"),
)
_SR_012 = RuleSpec(
    "SR-012",
    "flash tool identity is pinned and understood",
    source_refs=("SAFETY_RULES SR-012", "T04 tool manifest"),
)
_SR_013 = RuleSpec(
    "SR-013",
    "lock state is known and trusted-key checks pass",
    source_refs=("SAFETY_RULES SR-013", "AOSP AVB public key"),
)
_SR_018 = RuleSpec(
    "SR-018",
    "approval binding matches the current plan and evidence",
    source_refs=("SAFETY_RULES SR-018", "SPEC_V2 2.10", "ADR-025"),
)
_SR_008 = RuleSpec(
    "SR-008",
    "recovery assets verify and a last-resort path is stated",
    source_refs=("SAFETY_RULES SR-008", "SPEC_V2 3.7"),
)
_SR_009 = RuleSpec(
    "SR-009",
    "critical partitions are backed up in a device-bound vault before wipe/relock",
    source_refs=("SAFETY_RULES SR-009", "SPEC_V2 3.7", "ADR-028"),
)
_SR_010 = RuleSpec(
    "SR-010",
    "no Virtual A/B merge is in progress for a normal flash",
    source_refs=("SAFETY_RULES SR-010", "AOSP-FASTBOOTD", "KU-004"),
)


def _sr008_recovery(ctx: SafetyContext, _now: datetime, spec: RuleSpec) -> RuleResult:
    check = ctx.recovery_readiness
    if check is None:
        return _result(spec, Tri.UNKNOWN, "recovery readiness was not evaluated")
    return _result(
        spec,
        check.state,
        check.detail,
        evidence_ids=check.evidence_ids,
        warnings=check.warnings,
    )


def _sr009_vault(ctx: SafetyContext, _now: datetime, spec: RuleSpec) -> RuleResult:
    check = ctx.vault_backup
    if check is None:
        return _result(
            spec,
            Tri.UNKNOWN,
            "no vault backup was supplied for the wipe/relock gate",
        )
    return _result(
        spec,
        check.state,
        check.detail,
        evidence_ids=check.evidence_ids,
        warnings=check.warnings,
    )


def _sr010_merge_state(ctx: SafetyContext, _now: datetime, spec: RuleSpec) -> RuleResult:
    check = ctx.merge_state
    if check is None:
        return _result(
            spec,
            Tri.UNKNOWN,
            "snapshot-update-status was not read; the merge state is unknown",
        )
    return _result(
        spec,
        check.state,
        check.detail,
        evidence_ids=check.evidence_ids,
        warnings=check.warnings,
    )


def _sr001_identity(ctx: SafetyContext, _now: datetime, spec: RuleSpec) -> RuleResult:
    device = ctx.device_identity
    package = ctx.package_identity
    if device is None or package is None:
        return _result(
            spec,
            Tri.UNKNOWN,
            "device or package identity is unavailable",
            evidence_ids=ctx.identity_evidence_ids,
        )

    mismatches: list[str] = []
    unknowns: list[str] = []
    for field, device_value, package_value in (
        ("product", device.product, package.product),
        ("variant", device.variant, package.variant),
        ("hw-revision", device.hw_revision, package.hw_revision),
    ):
        if device_value is None:
            if package_value is not None:
                unknowns.append(f"{field} is not exposed by the device")
            continue
        if package_value is None:
            unknowns.append(f"{field} is not declared by the package")
            continue
        if device_value.casefold() != package_value.casefold():
            mismatches.append(f"{field}: device {device_value!r} != package {package_value!r}")

    if mismatches:
        if not ctx.identity_evidence_ids:
            return _result(
                spec,
                Tri.UNKNOWN,
                "identity mismatch reported without evidence references: " + "; ".join(mismatches),
                warnings=("a non-UNKNOWN identity claim without evidence is treated as UNKNOWN",),
            )
        return _result(
            spec,
            Tri.FALSE,
            "; ".join(mismatches),
            evidence_ids=ctx.identity_evidence_ids,
        )
    if unknowns:
        return _result(
            spec,
            Tri.UNKNOWN,
            "; ".join(unknowns),
            evidence_ids=ctx.identity_evidence_ids,
        )
    if not ctx.identity_evidence_ids:
        return _result(
            spec,
            Tri.UNKNOWN,
            "identities match but no evidence references were supplied",
        )
    return _result(
        spec,
        Tri.TRUE,
        "device product, variant, and hw-revision match the package",
        evidence_ids=ctx.identity_evidence_ids,
        warnings=("build fingerprint is not compared by SR-001",),
    )


def _sr002_provenance(ctx: SafetyContext, _now: datetime, spec: RuleSpec) -> RuleResult:
    provenance = ctx.provenance
    if provenance is None:
        return _result(spec, Tri.UNKNOWN, "no provenance result is available")

    reference = _stable_id(
        "provenance",
        provenance.state.name,
        provenance.package_id or "",
        *provenance.reasons,
    )
    detail = "; ".join(provenance.reasons) or "no provenance detail"
    if provenance.state is Tri.TRUE:
        if provenance.package_id is None:
            return _result(
                spec,
                Tri.UNKNOWN,
                "provenance reported TRUE without a package id",
                evidence_ids=(reference,),
            )
        return _result(
            spec,
            Tri.TRUE,
            detail,
            evidence_ids=(reference,),
            warnings=("a local hash index match is not a signature or authenticity check",),
        )
    if provenance.state is Tri.FALSE:
        return _result(spec, Tri.FALSE, detail, evidence_ids=(reference,))
    return _result(spec, Tri.UNKNOWN, detail, evidence_ids=(reference,))


def _sr003_avb_chain(ctx: SafetyContext, _now: datetime, spec: RuleSpec) -> RuleResult:
    return _declared_check(
        spec,
        ctx.avb_chain,
        "AVB chain verification is unavailable",
    )


def _sr004_rollback(ctx: SafetyContext, _now: datetime, spec: RuleSpec) -> RuleResult:
    return _declared_check(
        spec,
        ctx.rollback_oracle,
        "rollback-index comparison is unavailable",
    )


def _sr012_tool(ctx: SafetyContext, _now: datetime, spec: RuleSpec) -> RuleResult:
    report = ctx.tool
    if report is None:
        return _result(spec, Tri.UNKNOWN, "no flash-tool report is available")
    reference = _stable_id(
        "tool",
        report.name,
        str(report.path),
        report.sha256,
        report.version or "",
    )
    warnings = ("GPL tool: executed as a separate process only",) if report.gpl else ()
    if ctx.expected_tool is not None and report.name != ctx.expected_tool:
        return _result(
            spec,
            Tri.FALSE,
            f"expected tool {ctx.expected_tool!r}, got {report.name!r}",
            evidence_ids=(reference,),
            warnings=warnings,
        )
    if report.sha256_match is False:
        return _result(
            spec,
            Tri.FALSE,
            "tool SHA-256 does not match the pinned artifact",
            evidence_ids=(reference,),
            warnings=warnings,
        )
    if report.meets_minimum is False:
        return _result(
            spec,
            Tri.FALSE,
            f"tool version {report.version or 'unknown'} is below {report.min_version}",
            evidence_ids=(reference,),
            warnings=warnings,
        )
    if report.sha256_match is True:
        return _result(
            spec,
            Tri.TRUE,
            "tool matches the pinned SHA-256",
            evidence_ids=(reference,),
            warnings=warnings,
        )
    if report.min_version is not None and report.meets_minimum is True:
        return _result(
            spec,
            Tri.TRUE,
            f"tool version {report.version} meets the pinned minimum {report.min_version}",
            evidence_ids=(reference,),
            warnings=warnings,
        )
    if report.sha256_pinned:
        return _result(
            spec,
            Tri.UNKNOWN,
            "tool has a pinned SHA-256 but the match was not evaluated",
            evidence_ids=(reference,),
            warnings=warnings,
        )
    if report.min_version is not None:
        return _result(
            spec,
            Tri.UNKNOWN,
            f"could not verify tool version against {report.min_version}",
            evidence_ids=(reference,),
            warnings=warnings,
        )
    if report.version is not None:
        return _result(
            spec,
            Tri.UNKNOWN,
            f"tool version {report.version} is not pinned by hash or minimum version",
            evidence_ids=(reference,),
            warnings=warnings,
        )
    return _result(
        spec,
        Tri.UNKNOWN,
        "tool identity is not pinned by hash or version",
        evidence_ids=(reference,),
        warnings=warnings,
    )


def _sr013_lock_key(ctx: SafetyContext, now: datetime, spec: RuleSpec) -> RuleResult:
    lock = ctx.lock_state
    if lock is None:
        return _result(spec, Tri.UNKNOWN, "bootloader lock state is unavailable")
    if not lock.is_usable(now):
        return _result(
            spec,
            Tri.UNKNOWN,
            "lock-state evidence is stale, inferred, or from another boot",
            evidence_ids=(lock.evidence_id,),
        )

    lock_ids = (lock.evidence_id,)
    if lock.state is Tri.UNKNOWN:
        return _result(
            spec,
            Tri.UNKNOWN,
            "bootloader lock state is unknown",
            evidence_ids=lock_ids,
        )
    if lock.state is Tri.TRUE:
        warnings = ["device is unlocked; AVB key match is not enforced by lock state"]
        if ctx.avb_key is None:
            warnings.append("AVB key match was not checked")
        elif ctx.avb_key.state is Tri.FALSE:
            warnings.append("AVB key does not match the trusted key, but the device is unlocked")
        elif ctx.avb_key.state is Tri.UNKNOWN:
            warnings.append("AVB key match is unknown")
        return _result(
            spec,
            Tri.TRUE,
            "bootloader is unlocked",
            evidence_ids=lock_ids,
            warnings=warnings,
        )

    avb_key = ctx.avb_key
    if avb_key is None:
        return _result(
            spec,
            Tri.UNKNOWN,
            "device is locked and an AVB trusted-key match is unavailable",
            evidence_ids=lock_ids,
        )
    if avb_key.state is Tri.UNKNOWN:
        return _result(
            spec,
            Tri.UNKNOWN,
            avb_key.detail,
            evidence_ids=(*lock_ids, *avb_key.evidence_ids),
        )
    if not avb_key.evidence_ids:
        return _result(
            spec,
            Tri.UNKNOWN,
            f"{avb_key.detail}; no evidence references were supplied",
            evidence_ids=lock_ids,
            warnings=("a non-UNKNOWN key check without evidence is treated as UNKNOWN",),
        )
    if avb_key.state is Tri.FALSE:
        return _result(
            spec,
            Tri.FALSE,
            avb_key.detail,
            evidence_ids=(*lock_ids, *avb_key.evidence_ids),
        )
    return _result(
        spec,
        Tri.TRUE,
        avb_key.detail,
        evidence_ids=(*lock_ids, *avb_key.evidence_ids),
    )


def _sr018_approval(ctx: SafetyContext, _now: datetime, spec: RuleSpec) -> RuleResult:
    return _declared_check(
        spec,
        ctx.approval,
        "approval binding is unavailable",
    )


def _declared_check(
    spec: RuleSpec,
    check: CheckState | None,
    missing_reason: str,
) -> RuleResult:
    if check is None:
        return _result(spec, Tri.UNKNOWN, missing_reason)
    if check.state is Tri.UNKNOWN:
        return _result(
            spec,
            Tri.UNKNOWN,
            check.detail,
            evidence_ids=check.evidence_ids,
            warnings=check.warnings,
        )
    if not check.evidence_ids:
        return _result(
            spec,
            Tri.UNKNOWN,
            f"{check.detail}; no evidence references were supplied",
            warnings=(
                *check.warnings,
                "a non-UNKNOWN check without evidence is treated as UNKNOWN",
            ),
        )
    return _result(
        spec,
        check.state,
        check.detail,
        evidence_ids=check.evidence_ids,
        warnings=check.warnings,
    )


DEFAULT_RULES: Final[tuple[tuple[RuleSpec, RuleEvaluator], ...]] = (
    (_SR_001, _sr001_identity),
    (_SR_002, _sr002_provenance),
    (_SR_003, _sr003_avb_chain),
    (_SR_004, _sr004_rollback),
    (_SR_008, _sr008_recovery),
    (_SR_009, _sr009_vault),
    (_SR_010, _sr010_merge_state),
    (_SR_012, _sr012_tool),
    (_SR_013, _sr013_lock_key),
    (_SR_018, _sr018_approval),
)

PRE_APPROVAL_RULES: Final[tuple[tuple[RuleSpec, RuleEvaluator], ...]] = tuple(
    (spec, evaluator) for spec, evaluator in DEFAULT_RULES if spec.rule_id != _APPROVAL_RULE_ID
)


class SafetyEngine:
    """Evaluate the registered rules and apply explicitly allowed overrides."""

    def __init__(
        self,
        rules: Sequence[tuple[RuleSpec, RuleEvaluator]] = DEFAULT_RULES,
    ) -> None:
        if not rules:
            raise SafetyError("at least one safety rule is required")
        by_id: dict[str, tuple[RuleSpec, RuleEvaluator]] = {}
        for spec, evaluator in rules:
            if spec.rule_id in by_id:
                raise SafetyError(f"duplicate safety rule {spec.rule_id}")
            by_id[spec.rule_id] = (spec, evaluator)
        self._rules = MappingProxyType(by_id)

    @classmethod
    def pre_approval(cls) -> SafetyEngine:
        """An engine that evaluates every rule except the approval binding."""
        return cls(PRE_APPROVAL_RULES)

    def evaluate(
        self,
        context: SafetyContext,
        *,
        overrides: Iterable[OverrideRequest] = (),
        now: datetime | None = None,
    ) -> SafetyReport:
        if now is None:
            now = datetime.now(UTC)
        if now.tzinfo is None:
            raise SafetyError("now must be timezone-aware")

        results = tuple(
            self._evaluate_one(spec, evaluator, context, now)
            for _, (spec, evaluator) in sorted(self._rules.items())
        )
        snapshot = _snapshot_hash(results)
        records = self._validate_overrides(results, tuple(overrides), snapshot)

        verdict = Tri.all_of(result.state for result in results)
        overridden = {record.rule_id for record in records}
        blocking = tuple(
            result.rule_id
            for result in results
            if result.state is Tri.FALSE
            or (result.state is Tri.UNKNOWN and result.rule_id not in overridden)
        )
        can_proceed = not blocking
        snapshot_excludes = (_APPROVAL_RULE_ID,)
        report_text = _render_report(
            results,
            records,
            verdict,
            can_proceed,
            blocking,
            snapshot,
            snapshot_excludes,
        )
        records = tuple(replace(record, report_text=report_text) for record in records)
        return SafetyReport(
            rules=results,
            overrides=records,
            verdict=verdict,
            can_proceed=can_proceed,
            blocking=blocking,
            evidence_snapshot_sha256=snapshot,
            report_text=report_text,
            snapshot_excludes=snapshot_excludes,
        )

    @staticmethod
    def _evaluate_one(
        spec: RuleSpec,
        evaluator: RuleEvaluator,
        context: SafetyContext,
        now: datetime,
    ) -> RuleResult:
        try:
            result = evaluator(context, now, spec)
        except Exception as exc:
            result = _result(
                spec,
                Tri.UNKNOWN,
                f"rule evaluation failed: {type(exc).__name__}: {exc}",
                warnings=("internal rule error; treated as UNKNOWN",),
            )
        if result.rule_id != spec.rule_id:
            raise SafetyError(f"rule {spec.rule_id} returned a result for {result.rule_id}")
        if result.overridable != spec.unknown_overridable:
            raise SafetyError(f"rule {spec.rule_id} returned a mismatched override policy")
        return result

    def _validate_overrides(
        self,
        results: tuple[RuleResult, ...],
        requests: tuple[OverrideRequest, ...],
        snapshot: str,
    ) -> tuple[OverrideRecord, ...]:
        by_id = {result.rule_id: result for result in results}
        seen: set[str] = set()
        records: list[OverrideRecord] = []
        for request in requests:
            result = by_id.get(request.rule_id)
            if result is None:
                raise SafetyError(f"override references unknown rule {request.rule_id}")
            if request.rule_id in seen:
                raise SafetyError(f"duplicate override for {request.rule_id}")
            seen.add(request.rule_id)
            if result.state is Tri.FALSE:
                raise SafetyError(f"{request.rule_id} is FALSE; FALSE may never be overridden")
            if result.state is Tri.TRUE:
                raise SafetyError(f"{request.rule_id} is already TRUE; override is not allowed")
            if not result.overridable:
                raise SafetyError(f"{request.rule_id} does not allow UNKNOWN overrides")
            records.append(
                OverrideRecord(
                    rule_id=request.rule_id,
                    operator=request.operator.strip(),
                    reason=request.reason.strip(),
                    timestamp=request.timestamp.isoformat(),
                    evidence_snapshot_sha256=snapshot,
                    report_text="",
                )
            )
        return tuple(records)


def _snapshot_hash(results: tuple[RuleResult, ...]) -> str:
    payload = json.dumps(
        [result.to_dict() for result in results if result.rule_id != _APPROVAL_RULE_ID],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _render_report(
    results: tuple[RuleResult, ...],
    overrides: tuple[OverrideRecord, ...],
    verdict: Tri,
    can_proceed: bool,
    blocking: tuple[str, ...],
    snapshot: str,
    snapshot_excludes: tuple[str, ...],
) -> str:
    lines = [
        "Cairn safety report",
        f"verdict: {verdict.name}",
        f"proceed: {'yes' if can_proceed else 'no'}",
        "blocking: " + (", ".join(blocking) if blocking else "none"),
        f"evidence snapshot: {snapshot}",
        "snapshot excludes: " + (", ".join(snapshot_excludes) if snapshot_excludes else "none"),
    ]
    for result in results:
        lines.append(f"{result.rule_id} {result.state.name}: {result.reason}")
        for warning in result.warnings:
            lines.append(f"  warning: {warning}")
        if result.evidence_ids:
            lines.append("  evidence: " + ", ".join(result.evidence_ids))
    if overrides:
        lines.append("overrides:")
        for override in overrides:
            lines.append(
                f"- {override.rule_id} by {override.operator} at "
                f"{override.timestamp}: {override.reason}"
            )
        lines.append("note: an override records a decision; it does not turn UNKNOWN into TRUE.")
    return "\n".join(lines)


def _stable_id(*parts: str) -> str:
    payload = json.dumps(parts, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _require_text(value: str, what: str) -> None:
    if not value.strip():
        raise SafetyError(f"{what} must not be empty")
