"""Simulator-gated plan executor with a write-ahead journal.

This is the first module in Cairn that can issue write verbs (flash, erase,
reboot, update-super). It is deliberately impossible to point at a real device:
the only transport it accepts is the transcript simulator, so every execution is
labelled ``SIMULATED`` and is never device evidence. The write path to real
hardware stays gated behind T15 (Recovery Kit) and the M6 gate.

Execution is fail-closed in three layers:

1. **Pre-flight gates** — the plan hash must verify, the plan must be
   structurally executable, the pre-approval safety report must allow proceeding,
   and the approval token must have verified TRUE against the same plan, package,
   and device binding. Any refusal records an ``aborted`` journal entry.
2. **Image re-verification** — every flashed image is extracted from the package
   and hashed again; a byte mismatch against the approval bundle refuses the run
   (TOCTOU guard, closing the T13 follow-up).
3. **Journal reconcile on resume** — completed steps are skipped, an interrupted
   idempotent step is re-run, an interrupted non-idempotent step (reboot) or a
   previously failed step stops the run and demands the plan's stop-and-reprobe
   fallback instead of a blind retry.
"""

from __future__ import annotations

import hashlib
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol

from cairn.adapters.prepare import PreparedFastboot
from cairn.approval.token import ApprovalVerdict
from cairn.core.errors import CairnError, ToolError
from cairn.core.tristate import Tri
from cairn.executor.journal import (
    ROTATE_THRESHOLD_BYTES,
    Journal,
    JournalCorruptError,
    JournalKind,
    JournalRecord,
)
from cairn.plan.planner import Plan, PlanAction, PlanStep, verify_plan_hash
from cairn.tools.runner import ToolResult, ToolRunner

DEFAULT_STEP_TIMEOUT_S: Final = 600.0
_MAX_STDERR_JOURNAL_CHARS: Final = 2000


class ExecutorError(CairnError):
    code = "EXECUTOR_ERROR"


class ExecutorRefused(ExecutorError):
    code = "EXECUTOR_REFUSED"


class SimulatedCrash(BaseException):
    """Injected by the crash harness to kill the executor at a journal point.

    Derives from ``BaseException`` on purpose: a test crash must not be caught by
    ordinary ``except Exception`` error handling in the executor.
    """


class IdempotencyError(ExecutorError):
    code = "EXECUTOR_IDEMPOTENCY_ERROR"


class Idempotency(StrEnum):
    IDEMPOTENT = "idempotent"
    NON_IDEMPOTENT = "non-idempotent"


class WriteTransport(Protocol):
    """The single seam through which the executor may issue a write verb."""

    def run_write(
        self,
        step: PlanStep,
        *,
        image_path: Path | None,
        timeout_s: float,
    ) -> ToolResult: ...


class ReadTransport(Protocol):
    """Optional read-only seam used for pre-write state reconciliation.

    The executor only ever issues ``getvar`` through this; a transport without
    ``read_var`` simply skips reconciliation, which is then recorded as
    UNKNOWN in the journal.
    """

    def read_var(self, name: str, *, timeout_s: float) -> ToolResult: ...


def idempotency_of(step: PlanStep) -> Idempotency:
    """Classify a plan step's re-run safety.

    FLASH and ERASE are idempotent: re-writing the same verified bytes or erasing
    an erased partition converges. UPDATE-SUPER is treated as idempotent only in
    the simulator; a real run must re-verify super state first. REBOOT is never
    re-run blindly: it invalidates pre-reboot evidence (the evidence graph
    invalidates earlier boot epochs), so resume after an interrupted reboot
    requires a fresh preflight.
    """
    if step.action in (PlanAction.FLASH, PlanAction.ERASE, PlanAction.UPDATE_SUPER):
        return Idempotency.IDEMPOTENT
    if step.action is PlanAction.REBOOT:
        return Idempotency.NON_IDEMPOTENT
    raise IdempotencyError(f"plan step {step.number} has an unclassifiable action")


@dataclass(frozen=True, slots=True)
class StepOutcome:
    number: int
    action: str
    partition: str | None
    state: str
    detail: str
    exit_code: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "number": self.number,
            "action": self.action,
            "partition": self.partition,
            "state": self.state,
            "detail": self.detail,
            "exit_code": self.exit_code,
        }


@dataclass(frozen=True, slots=True)
class ExecuteResult:
    verdict: Tri
    simulated: bool
    completed: bool
    reason: str
    steps: tuple[StepOutcome, ...]
    aborted_step: int | None = None
    crash_consistent: bool = True
    journal_path: Path | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict.name,
            "simulated": self.simulated,
            "completed": self.completed,
            "reason": self.reason,
            "aborted_step": self.aborted_step,
            "journal_path": str(self.journal_path) if self.journal_path is not None else None,
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass(frozen=True, slots=True)
class SafetyGate:
    """The pre-approval safety verdict the executor must respect.

    ``verdict`` is the tri-state overall of the safety report: FALSE refuses
    always; UNKNOWN is executable only because the only transport is the
    simulator and the whole run stays labelled SIMULATED; TRUE (a real READY
    session) is the case a future real-device transport will require.
    """

    verdict: Tri
    blocking: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    plan: Plan
    package_path: Path
    """The factory/OTA zip the images are extracted from."""
    expected_entry_hashes: Mapping[str, str]
    """Entry-name to SHA-256 mapping from the approval bundle."""
    safety: SafetyGate
    approval: ApprovalVerdict
    transport: WriteTransport
    staging_dir: Path
    timeout_s: float = DEFAULT_STEP_TIMEOUT_S


CrashHook = Callable[[JournalRecord], None]


def staged_image_path(staging_dir: Path, image: str) -> Path:
    """Deterministic staging path so journal records and transcripts agree."""
    return staging_dir / image.replace("/", "_")


def _resolve_tip(path: Path) -> Path:
    """Follow rotation successors (.r1, .r2, ...) to the journal's live tip."""
    tip = path
    for index in range(1, 1000):
        successor = path.with_name(f"{path.stem}.r{index}{path.suffix}")
        if not successor.exists():
            return tip
        tip = successor
    return tip


def _open_journal(
    path: Path,
    request: ExecutionRequest,
    crash_hook: CrashHook | None,
) -> Journal:
    path = _resolve_tip(path)
    session_payload: dict[str, object] = {
        "journal_kind": "cairn.executor-journal",
        "schema_version": 1,
        "plan_sha256": request.plan.plan_sha256,
        "package_sha256": request.plan.package_sha256,
        "simulated": True,
        "steps": [step.number for step in request.plan.steps],
    }
    if path.exists():
        loaded = Journal.load(path)
        if not loaded.records:
            # A crash landed between file creation and the first durable record;
            # no step can have started, so the journal is safe to start over.
            try:
                path.unlink()
            except OSError as exc:
                raise ExecutorRefused(f"cannot reset an empty journal {path}: {exc}") from exc
        else:
            journal = Journal.resume_chain(path)
            last_session = journal.records[0]
            if last_session.kind is not JournalKind.SESSION:
                raise ExecutorRefused(f"journal {path} does not start with a session record")
            recorded = last_session.payload.get("plan_sha256")
            if recorded != request.plan.plan_sha256:
                raise ExecutorRefused(
                    "journal was recorded for a different plan; start a new execution"
                )
            if last_session.payload.get("package_sha256") != request.plan.package_sha256:
                raise ExecutorRefused(
                    "journal was recorded for a different package; start a new execution"
                )
            return _maybe_rotate(journal)
    journal = Journal.create(path, session_payload)
    _crash_point(crash_hook, journal.last)
    return journal


def _maybe_rotate(journal: Journal) -> Journal:
    """Growth policy: rotate a journal nearing its byte limit at resume time.

    The successor file continues the chain (``Journal.rotate``); appends land
    in the successor and the predecessor stays on disk as evidence.
    """
    if journal.size_bytes() < ROTATE_THRESHOLD_BYTES:
        return journal
    stem = journal.path.stem
    for index in range(1, 1000):
        successor = journal.path.with_name(f"{stem}.r{index}{journal.path.suffix}")
        if not successor.exists():
            return journal.rotate(successor)
    raise ExecutorRefused(
        f"journal {journal.path} needs rotation but every successor name .r1-.r999 exists"
    )


def _getvar_value(result: ToolResult, name: str) -> str | None:
    """Extract a value from fastboot getvar output ('(bootloader) name: value')."""
    for line in (result.stdout + "\n" + result.stderr).splitlines():
        stripped = line.strip()
        if stripped.startswith("(") and ") " in stripped:
            stripped = stripped.split(") ", 1)[1].strip()
        prefix = f"{name}:"
        if stripped.startswith(prefix) or stripped.startswith(f"{name} :"):
            value = (
                stripped[len(prefix) :].strip()
                if stripped.startswith(prefix)
                else stripped.split(":", 1)[1].strip()
            )
            if value:
                return value
    return None


def _reconcile_vab(transport: object, journal: Journal, timeout_s: float) -> ExecuteResult | None:
    """Read-only pre-write reconciliation of slot and merge state (SR-010).

    Runs only when the transport exposes ``read_var``. A mid-merge
    ``snapshot-update-status`` is a never-overridable FALSE and aborts before
    the first write; an unreadable or unrecognized value is UNKNOWN, which in
    the simulator-only executor is journaled as a warning and does not block
    (consistent with the SafetyGate semantics).
    """
    read_var = getattr(transport, "read_var", None)
    payload: dict[str, object] = {"checks": {}}
    checks: dict[str, object] = {}
    if read_var is None:
        checks["transport"] = "transport exposes no read seam; reconciliation skipped (UNKNOWN)"
        payload["checks"] = checks
        journal.append(JournalKind.RECONCILED, payload)
        return None
    if not callable(read_var):
        raise ExecutorRefused("transport read seam is not callable")
    # Imported here: cairn.vab.flows imports this module, so a module-level
    # import of the cairn.vab package would be a circular import.
    from cairn.vab.merge_state import classify_snapshot_status

    slot_result = read_var("current-slot", timeout_s=timeout_s)
    merge_result = read_var("snapshot-update-status", timeout_s=timeout_s)
    slot_value = _getvar_value(slot_result, "current-slot") if slot_result.ok else None
    merge_value = _getvar_value(merge_result, "snapshot-update-status") if merge_result.ok else None
    merge_read = classify_snapshot_status(merge_value, simulated=True)
    checks["current-slot"] = {"ok": slot_result.ok, "value": slot_value}
    checks["snapshot-update-status"] = merge_read.to_dict()
    payload["checks"] = checks
    journal.append(JournalKind.RECONCILED, payload)

    if merge_read.state is Tri.FALSE:
        journal.append(
            JournalKind.ABORTED,
            {"reason": f"SR-010 mid-merge state: {merge_read.detail}"},
        )
        return ExecuteResult(
            verdict=Tri.FALSE,
            simulated=True,
            completed=False,
            reason=f"refused before the first write: {merge_read.detail}",
            steps=(),
        )
    return None


def _check_gates(request: ExecutionRequest) -> None:
    if not verify_plan_hash(request.plan):
        raise ExecutorRefused("plan hash does not verify against the plan payload")
    if not request.plan.executable:
        raise ExecutorRefused("plan is not executable; the structural gate refused it")
    if request.safety.verdict is Tri.FALSE:
        blocking = ", ".join(request.safety.blocking) or "no detail"
        raise ExecutorRefused(f"safety verdict is FALSE and is never overridable: {blocking}")
    if request.approval.state is not Tri.TRUE:
        reasons = "; ".join(request.approval.reasons) or "no detail"
        raise ExecutorRefused(f"approval token did not verify: {reasons}")


def _step_journal_state(journal: Journal) -> dict[int, str]:
    states: dict[int, str] = {}
    step_kinds = (JournalKind.STEP_STARTED, JournalKind.STEP_DONE, JournalKind.STEP_FAILED)
    for record in journal.records:
        if record.kind in step_kinds:
            number_raw = record.payload.get("number")
            if isinstance(number_raw, bool) or not isinstance(number_raw, int):
                raise JournalCorruptError("journal step record has no integer step number")
            if record.kind is JournalKind.STEP_STARTED:
                states.setdefault(number_raw, "started")
            elif record.kind is JournalKind.STEP_DONE:
                states[number_raw] = "done"
            else:
                states[number_raw] = "failed"
    return states


def _extract_and_verify_image(request: ExecutionRequest, step: PlanStep) -> Path:
    image = step.image
    if image is None:
        raise ExecutorRefused(f"plan step {step.number} flashes nothing")
    expected = request.expected_entry_hashes.get(image)
    if expected is None:
        matches = [
            name for name in request.expected_entry_hashes if name.rsplit("/", 1)[-1] == image
        ]
        if len(matches) == 1:
            expected = request.expected_entry_hashes[matches[0]]
        elif len(matches) > 1:
            raise ExecutorRefused(
                f"package entry name {image!r} is ambiguous in the approval bundle"
            )
    if expected is None:
        raise ExecutorRefused(
            f"image {image!r} is not covered by the approval binding; refusing to stage it"
        )
    if step.partition is None:
        raise ExecutorRefused(f"plan step {step.number} has no target partition")

    target = staged_image_path(request.staging_dir, image)
    try:
        request.staging_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(request.package_path) as archive:
            candidates = [
                name
                for name in archive.namelist()
                if name == image or name.rsplit("/", 1)[-1] == image
            ]
            if len(candidates) != 1:
                raise ExecutorRefused(
                    f"package contains {len(candidates)} entries matching {image!r}; refusing"
                )
            with archive.open(candidates[0]) as source, target.open("wb") as sink:
                hasher = hashlib.sha256()
                while chunk := source.read(1024 * 1024):
                    hasher.update(chunk)
                    sink.write(chunk)
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise ExecutorRefused(f"cannot stage image {image!r}: {exc}") from exc
    staged = hashlib.sha256(target.read_bytes()).hexdigest()
    if staged != expected.lower():
        target.unlink(missing_ok=True)
        raise ExecutorRefused(
            f"staged image {image!r} hash does not match the approval binding "
            f"({staged} != {expected.lower()}); the package changed after approval"
        )
    return target


def _build_step_argv(step: PlanStep, image_path: Path | None) -> tuple[str, ...]:
    """Executor-defined fastboot argv; the simulator transcript must match it."""
    if step.action is PlanAction.FLASH:
        assert step.partition is not None
        assert image_path is not None
        argv = ["flash"]
        if step.apply_vbmeta:
            argv.append("--apply-vbmeta")
        if step.slot_other:
            argv.append("--slot-other")
        argv.extend((step.partition, str(image_path)))
        return tuple(argv)
    if step.action is PlanAction.ERASE:
        assert step.partition is not None
        return ("erase", step.partition)
    if step.action is PlanAction.REBOOT:
        assert step.target is not None
        return ("reboot", step.target)
    if step.action is PlanAction.UPDATE_SUPER:
        return ("update-super",)
    if step.action is PlanAction.SNAPSHOT_UPDATE:
        if step.target not in ("cancel", "merge"):
            raise ExecutorRefused(
                f"plan step {step.number} snapshot-update target must be cancel or merge"
            )
        return ("snapshot-update", step.target)
    raise ExecutorRefused(f"plan step {step.number} has an unsupported action")


def _journal_step_payload(step: PlanStep, image_path: Path | None) -> dict[str, object]:
    payload: dict[str, object] = {
        "number": step.number,
        "action": step.action.value,
        "partition": step.partition,
        "image": step.image,
    }
    if image_path is not None:
        payload["image_sha256"] = hashlib.sha256(image_path.read_bytes()).hexdigest()
    return payload


def execute_plan(
    request: ExecutionRequest,
    journal_path: Path,
    *,
    crash_hook: CrashHook | None = None,
) -> ExecuteResult:
    """Run the plan against the simulator with journal-guarded resume."""
    _check_gates(request)
    journal = _open_journal(journal_path, request, crash_hook)
    step_states = _step_journal_state(journal)
    outcomes: list[StepOutcome] = []

    refused = _reconcile_vab(request.transport, journal, timeout_s=request.timeout_s)
    _crash_point(crash_hook, journal.last)
    if refused is not None:
        return ExecuteResult(
            verdict=refused.verdict,
            simulated=True,
            completed=False,
            reason=refused.reason,
            steps=refused.steps,
            aborted_step=refused.aborted_step,
            journal_path=journal.path,
        )

    for step in request.plan.steps:
        state = step_states.get(step.number)
        if state == "done":
            outcomes.append(
                StepOutcome(
                    number=step.number,
                    action=step.action.value,
                    partition=step.partition,
                    state="skipped",
                    detail="already recorded as done in the journal",
                )
            )
            journal.append(
                JournalKind.STEP_SKIPPED,
                {"number": step.number, "detail": "already done in a previous run"},
            )
            _crash_point(crash_hook, journal.last)
            continue
        if state == "failed":
            journal.append(
                JournalKind.ABORTED,
                {
                    "number": step.number,
                    "reason": "a previous run recorded a failure for this step",
                },
            )
            _crash_point(crash_hook, journal.last)
            return ExecuteResult(
                verdict=Tri.UNKNOWN,
                simulated=True,
                completed=False,
                reason=(
                    f"step {step.number} failed in a previous run; the fallback is "
                    f"{request.plan.fallback.action}: {request.plan.fallback.detail}"
                ),
                steps=tuple(outcomes),
                journal_path=journal.path,
                aborted_step=step.number,
            )
        if state == "started" and idempotency_of(step) is Idempotency.NON_IDEMPOTENT:
            journal.append(
                JournalKind.ABORTED,
                {
                    "number": step.number,
                    "reason": "non-idempotent step was interrupted and must not be re-run blindly",
                },
            )
            _crash_point(crash_hook, journal.last)
            return ExecuteResult(
                verdict=Tri.UNKNOWN,
                simulated=True,
                completed=False,
                reason=(
                    f"step {step.number} ({step.action.value}) was interrupted mid-run; it is "
                    f"non-idempotent, so the fallback is {request.plan.fallback.action}: "
                    f"{request.plan.fallback.detail} and a fresh preflight"
                ),
                steps=tuple(outcomes),
                journal_path=journal.path,
                aborted_step=step.number,
            )

        image_path = None
        if step.action is PlanAction.FLASH:
            image_path = _extract_and_verify_image(request, step)
        payload = _journal_step_payload(step, image_path)
        journal.append(JournalKind.STEP_STARTED, payload)
        _crash_point(crash_hook, journal.last)

        try:
            result = request.transport.run_write(
                step, image_path=image_path, timeout_s=request.timeout_s
            )
        except ToolError as exc:
            journal.append(
                JournalKind.STEP_FAILED,
                {"number": step.number, "detail": str(exc)[:_MAX_STDERR_JOURNAL_CHARS]},
            )
            _crash_point(crash_hook, journal.last)
            return ExecuteResult(
                verdict=Tri.FALSE,
                simulated=True,
                completed=False,
                reason=(
                    f"step {step.number} ({step.action.value}) raised a tool error: {exc}; "
                    f"the fallback is {request.plan.fallback.action}"
                ),
                steps=tuple(outcomes),
                journal_path=journal.path,
                aborted_step=step.number,
            )

        if not result.ok:
            detail = result.stderr.strip() or result.stdout.strip()
            journal.append(
                JournalKind.STEP_FAILED,
                {
                    "number": step.number,
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                    "cancelled": result.cancelled,
                    "stderr": detail[:_MAX_STDERR_JOURNAL_CHARS],
                },
            )
            _crash_point(crash_hook, journal.last)
            return ExecuteResult(
                verdict=Tri.FALSE,
                simulated=True,
                completed=False,
                reason=(
                    f"step {step.number} ({step.action.value}) failed with exit code "
                    f"{result.exit_code}; the fallback is {request.plan.fallback.action}: "
                    f"{request.plan.fallback.detail}"
                ),
                steps=tuple(outcomes),
                journal_path=journal.path,
                aborted_step=step.number,
            )

        journal.append(
            JournalKind.STEP_DONE,
            {"number": step.number, "exit_code": result.exit_code},
        )
        _crash_point(crash_hook, journal.last)
        outcomes.append(
            StepOutcome(
                number=step.number,
                action=step.action.value,
                partition=step.partition,
                state="done",
                detail="simulated write completed",
                exit_code=result.exit_code,
            )
        )

    journal.append(
        JournalKind.COMPLETED,
        {"steps_done": len(request.plan.steps), "steps_total": len(request.plan.steps)},
    )
    _crash_point(crash_hook, journal.last)
    return ExecuteResult(
        verdict=Tri.TRUE,
        simulated=True,
        completed=True,
        reason="every plan step completed in the simulator; this run is SIMULATED, "
        "not device evidence",
        steps=tuple(outcomes),
        journal_path=journal.path,
    )


def _crash_point(hook: CrashHook | None, record: JournalRecord | None) -> None:
    if hook is not None and record is not None:
        hook(record)


class SimulatedFastbootTransport:
    """The only transport that can issue write verbs.

    It is constructed exclusively from a prepared *simulated* fastboot
    invocation; a resolved real fastboot binary raises ``ExecutorRefused``. There
    is no code path from a real tool to a write verb anywhere in this module.
    """

    def __init__(
        self,
        prepared_argv_prefix: tuple[str, ...],
        *,
        simulated: bool,
        extra_env: Mapping[str, str] | None = None,
        runner: ToolRunner | None = None,
    ) -> None:
        if not simulated:
            raise ExecutorRefused(
                "real-device writes are refused: the recovery drill and the M6 gate "
                "must pass first (T15); use the transcript simulator"
            )
        if not prepared_argv_prefix:
            raise ExecutorRefused("simulated transport requires an argv prefix")
        self._prefix = tuple(prepared_argv_prefix)
        self._extra_env = dict(extra_env) if extra_env is not None else None
        self._runner = runner if runner is not None else ToolRunner()

    @classmethod
    def from_prepared(cls, prepared: PreparedFastboot) -> SimulatedFastbootTransport:
        if not prepared.simulated or prepared.prefix is None:
            raise ExecutorRefused(
                "real-device writes are refused: the recovery drill and the M6 gate "
                "must pass first (T15); use the transcript simulator"
            )
        return cls(
            prepared.prefix,
            simulated=True,
            extra_env=prepared.extra_env,
        )

    def run_write(
        self,
        step: PlanStep,
        *,
        image_path: Path | None,
        timeout_s: float,
    ) -> ToolResult:
        argv = (*self._prefix, *_build_step_argv(step, image_path))
        return self._runner.run(argv, timeout_s=timeout_s, extra_env=self._extra_env)

    def read_var(self, name: str, *, timeout_s: float) -> ToolResult:
        # Read-only getvar through the same simulated prefix; the executor uses
        # this for pre-write merge-state and slot reconciliation (SR-010).
        if any(ch in name for ch in (" ", ";", "&", "|", "$", "`", "\n")):
            raise ExecutorRefused(f"invalid getvar name {name!r}")
        argv = (*self._prefix, "getvar", name)
        return self._runner.run(argv, timeout_s=timeout_s, extra_env=self._extra_env)
