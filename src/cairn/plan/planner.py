"""Read-only planner v0.

The planner preserves the vendor ``fastboot-info.txt`` order. It never reorders,
resolves slots, or invents recovery steps. A plan is executable only when provenance
is TRUE, the package structure is understood, and every requested option is modeled.
Anything else is emitted as a dry run with ``executable = FALSE``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Final

from cairn.core.errors import ConfigurationError
from cairn.core.tristate import Tri
from cairn.package.archive import (
    PackageError,
    PackageKind,
    PackageManifest,
    validate_entry_name,
)
from cairn.package.fastboot_info import (
    EraseCommand,
    FastbootCommand,
    FlashCommand,
    RebootCommand,
    UpdateSuperCommand,
)
from cairn.provenance.hash_index import ProvenanceResult

PLAN_SCHEMA_VERSION: Final = 1
_CRITICAL_PARTITIONS: Final[frozenset[str]] = frozenset({"bootloader", "radio", "super", "vbmeta"})
_PARTITION_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class PlanError(ConfigurationError):
    code = "PLAN_ERROR"


class PlanAction(StrEnum):
    FLASH = "flash"
    ERASE = "erase"
    REBOOT = "reboot"
    UPDATE_SUPER = "update-super"
    # Only the modeled snapshot flows (cairn.vab) build this action; the
    # planner itself never emits it.
    SNAPSHOT_UPDATE = "snapshot-update"


class SlotPolicy(StrEnum):
    CURRENT = "current"
    OTHER = "other"
    ALL = "all"


@dataclass(frozen=True, slots=True)
class PlanOptions:
    wipe: bool = False
    slot_policy: SlotPolicy = SlotPolicy.CURRENT
    retrofit_force: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "wipe": self.wipe,
            "slot_policy": self.slot_policy.value,
            "retrofit_force": self.retrofit_force,
        }


@dataclass(frozen=True, slots=True)
class PlanFacts:
    slot_count: int | None = None
    current_slot: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "slot_count": self.slot_count,
            "current_slot": self.current_slot,
        }


@dataclass(frozen=True, slots=True)
class PlanStep:
    number: int
    action: PlanAction
    source_line: int
    partition: str | None = None
    image: str | None = None
    target: str | None = None
    if_wipe: bool = False
    apply_vbmeta: bool = False
    slot_other: bool = False
    annotations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "number": self.number,
            "action": self.action.value,
            "source_line": self.source_line,
            "partition": self.partition,
            "image": self.image,
            "target": self.target,
            "if_wipe": self.if_wipe,
            "apply_vbmeta": self.apply_vbmeta,
            "slot_other": self.slot_other,
            "annotations": list(self.annotations),
        }


@dataclass(frozen=True, slots=True)
class FallbackPlan:
    action: str
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {"action": self.action, "detail": self.detail}


DEFAULT_FALLBACK: Final = FallbackPlan(
    action="stop-and-reprobe",
    detail=(
        "On any failure, stop; do not retry blindly. Reboot to bootloader and "
        "re-probe before resuming."
    ),
)


@dataclass(frozen=True, slots=True)
class Plan:
    schema_version: int
    package_sha256: str
    fastboot_info_version: int
    provenance: ProvenanceResult
    options: PlanOptions
    facts: PlanFacts
    steps: tuple[PlanStep, ...]
    deviations: tuple[str, ...]
    warnings: tuple[str, ...]
    fallback: FallbackPlan
    executable: bool
    plan_sha256: str

    def to_dict(self) -> dict[str, object]:
        return plan_payload(self) | {"plan_sha256": self.plan_sha256}


def build_plan(
    manifest: PackageManifest,
    provenance: ProvenanceResult,
    *,
    options: PlanOptions | None = None,
    facts: PlanFacts | None = None,
) -> Plan:
    """Build a dry-run plan in vendor order."""
    options = options or PlanOptions()
    facts = facts or PlanFacts()
    info = manifest.fastboot_info
    if info is None:
        raise PlanError("package has no fastboot-info.txt; planner v0 cannot plan it")
    if manifest.archive_sha256 is None:
        raise PlanError("package archive sha256 is required for a plan")
    if info.version != 1:
        version = "absent" if info.version is None else str(info.version)
        raise PlanError(f"fastboot-info version is {version}; planner v0 requires version 1")

    executable = provenance.state is Tri.TRUE
    warnings: list[str] = []
    deviations: list[str] = []

    if provenance.state is not Tri.TRUE:
        warnings.append(f"package provenance is {provenance.state.name}; plan is not executable")
    if manifest.kind is PackageKind.UNKNOWN:
        warnings.append("package kind is UNKNOWN; plan is not executable")
        executable = False
    if options.slot_policy is not SlotPolicy.CURRENT and (
        facts.slot_count is None or facts.slot_count < 2
    ):
        warnings.append(
            f"slot policy {options.slot_policy.value} requires verified slot facts; "
            "plan is not executable"
        )
        executable = False
    if options.retrofit_force:
        warnings.append("retrofit force mode requires catalog data; plan is not executable")
        deviations.append("retrofit force mode changes update-super semantics; not modeled")
        executable = False

    names = {entry.name for entry in manifest.entries}
    basenames = {name.rsplit("/", 1)[-1] for name in names}
    steps: list[PlanStep] = []
    for command in info.commands:
        if command.if_wipe and not options.wipe:
            deviations.append(f"skipped if-wipe command at line {command.line} (wipe disabled)")
            continue
        step, step_ok = _build_step(
            command,
            number=len(steps) + 1,
            options=options,
            facts=facts,
            names=names,
            basenames=basenames,
        )
        if not step_ok:
            executable = False
        steps.append(step)

    if not steps:
        warnings.append("plan has no steps; plan is not executable")
        executable = False

    plan = Plan(
        schema_version=PLAN_SCHEMA_VERSION,
        package_sha256=manifest.archive_sha256.lower(),
        fastboot_info_version=1,
        provenance=provenance,
        options=options,
        facts=facts,
        steps=tuple(steps),
        deviations=tuple(deviations),
        warnings=tuple(warnings),
        fallback=DEFAULT_FALLBACK,
        executable=executable,
        plan_sha256="",
    )
    return replace(plan, plan_sha256=compute_plan_hash(plan))


def plan_payload(plan: Plan) -> dict[str, object]:
    """The canonical payload that the plan hash covers."""
    return {
        "schema_version": plan.schema_version,
        "package_sha256": plan.package_sha256,
        "fastboot_info_version": plan.fastboot_info_version,
        "provenance": plan.provenance.to_dict(),
        "options": plan.options.to_dict(),
        "facts": plan.facts.to_dict(),
        "steps": [step.to_dict() for step in plan.steps],
        "deviations": list(plan.deviations),
        "warnings": list(plan.warnings),
        "fallback": plan.fallback.to_dict(),
        "executable": plan.executable,
    }


def compute_plan_hash(plan: Plan) -> str:
    encoded = json.dumps(
        plan_payload(plan),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_plan_hash(plan: Plan) -> bool:
    return compute_plan_hash(plan) == plan.plan_sha256


def _build_step(
    command: FastbootCommand,
    *,
    number: int,
    options: PlanOptions,
    facts: PlanFacts,
    names: set[str],
    basenames: set[str],
) -> tuple[PlanStep, bool]:
    annotations: list[str] = []
    executable = True

    if command.if_wipe:
        annotations.append("included because wipe is enabled")

    if isinstance(command, FlashCommand):
        _validate_partition(command.partition)
        image = command.image_name
        _validate_image(image)
        if image not in names and image.rsplit("/", 1)[-1] not in basenames:
            annotations.append(f"image not found in inspected archive: {image}")
            executable = False
        if command.partition in _CRITICAL_PARTITIONS:
            annotations.append(f"critical partition write: {command.partition}")
        if command.apply_vbmeta:
            annotations.append("vendor requests --apply-vbmeta")
        if command.slot_other:
            annotations.append("vendor requests --slot-other")
        _annotate_slot(annotations, options, facts)
        return (
            PlanStep(
                number=number,
                action=PlanAction.FLASH,
                source_line=command.line,
                partition=command.partition,
                image=image,
                if_wipe=command.if_wipe,
                apply_vbmeta=command.apply_vbmeta,
                slot_other=command.slot_other,
                annotations=tuple(annotations),
            ),
            executable,
        )

    if isinstance(command, EraseCommand):
        _validate_partition(command.partition)
        annotations.append("erase is destructive")
        _annotate_slot(annotations, options, facts)
        return (
            PlanStep(
                number=number,
                action=PlanAction.ERASE,
                source_line=command.line,
                partition=command.partition,
                if_wipe=command.if_wipe,
                annotations=tuple(annotations),
            ),
            executable,
        )

    if isinstance(command, RebootCommand):
        annotations.append(f"reboot target {command.target_name}; evidence freshness resets")
        return (
            PlanStep(
                number=number,
                action=PlanAction.REBOOT,
                source_line=command.line,
                target=command.target_name,
                if_wipe=command.if_wipe,
                annotations=tuple(annotations),
            ),
            executable,
        )

    if isinstance(command, UpdateSuperCommand):
        annotations.append("update-super requires a valid super image; executor must verify")
        if options.wipe:
            annotations.append("wipe: update-super may delete logical partitions")
        if options.retrofit_force:
            annotations.append("retrofit force mode is not modeled")
        return (
            PlanStep(
                number=number,
                action=PlanAction.UPDATE_SUPER,
                source_line=command.line,
                if_wipe=command.if_wipe,
                annotations=tuple(annotations),
            ),
            executable,
        )

    raise PlanError(f"unsupported fastboot command type: {type(command)!r}")


def _annotate_slot(
    annotations: list[str],
    options: PlanOptions,
    facts: PlanFacts,
) -> None:
    if options.slot_policy is SlotPolicy.CURRENT:
        return
    if facts.slot_count is None or facts.slot_count < 2:
        annotations.append(
            f"slot policy {options.slot_policy.value} unresolved; verified slot facts required"
        )
        return
    annotations.append(f"slot policy: {options.slot_policy.value}")


def _validate_partition(partition: str) -> None:
    if _PARTITION_RE.fullmatch(partition) is None:
        raise PlanError(f"unsafe partition name {partition!r}")


def _validate_image(image: str) -> None:
    if image.endswith("/"):
        raise PlanError(f"unsafe image path {image!r}")
    try:
        validate_entry_name(image)
    except PackageError as exc:
        raise PlanError(f"unsafe image path {image!r}: {exc}") from exc
