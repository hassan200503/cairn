"""Wizard orchestration: ordering, reuse, stopping, and persistence."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cairn.core.evidence import Evidence, EvidenceSource
from cairn.core.tristate import Tri
from cairn.safety.engine import CheckState
from cairn.tools.runner import ToolRunner
from cairn.wizard.session import (
    DEFAULT_REUSE_SECONDS,
    STAGE_ORDER,
    STAGE_TITLES,
    DeviceRecord,
    SessionOutcome,
    StageOutcome,
    StageRecord,
    WizardError,
    WizardSession,
    load_session,
    save_session,
)
from cairn.wizard.stages import (
    StageResult,
    WizardOptions,
    WizardRun,
    doctor_fingerprint,
    new_wizard_session,
    probe_fingerprint,
    rollback_fingerprint,
    stage_approval,
    stage_avb,
    stage_doctor,
    stage_inspect,
    stage_plan,
    stage_probe,
    stage_provenance,
    stage_rollback,
)


def run_wizard(
    options: WizardOptions,
    *,
    runner: ToolRunner | None = None,
    now: datetime | None = None,
) -> WizardSession:
    if now is None:
        now = datetime.now(UTC)
    if now.tzinfo is None:
        raise WizardError("wizard time must be timezone-aware")
    tool_runner = runner if runner is not None else ToolRunner()

    existing: WizardSession | None = None
    if options.state.exists():
        if options.force:
            existing = None
        elif options.resume:
            existing = load_session(options.state)
        else:
            raise WizardError(
                f"wizard session already exists at {options.state}; pass --resume or --force"
            )
    elif options.resume:
        raise WizardError(f"no wizard session to resume at {options.state}")

    run = WizardRun(options)
    if existing is None:
        session = new_wizard_session(options, now=now)
    else:
        if Path(existing.package_path).resolve() != options.package.resolve():
            raise WizardError("the existing session was recorded for a different package")
        if Path(existing.index_path).resolve() != options.index.resolve():
            raise WizardError("the existing session was recorded for a different hash index")
        if existing.cairn_version != new_wizard_session(options, now=now).cairn_version:
            raise WizardError(
                "the existing session was recorded by a different Cairn version; use --force"
            )
        reused = _reuse(existing, options, run, now)
        session = existing.replace(
            stages=reused,
            device=run.device,
            archive_sha256=None,
            index_sha256=None,
            bundle=None,
            plan=None,
            pre_safety=None,
            post_safety=None,
            verdict=None,
            outcome=SessionOutcome.BLOCKED,
            warnings=(),
            updated_at=now,
        )

    save_session(options.state, session)
    stop = False
    skip_rollback = False

    for name in STAGE_ORDER:
        if stop:
            break
        if name == "approval":
            plan_record = session.stage("plan")
            if plan_record is None or plan_record.outcome is not StageOutcome.PASS:
                break
        if name == "rollback" and skip_rollback:
            session = _record_skip(
                session,
                run,
                options,
                now,
                "rollback",
                "device probe did not produce usable evidence; rollback was skipped",
            )
            continue
        if _reused(session, name):
            continue

        started_at = datetime.now(UTC)
        started = time.perf_counter()
        result = _run_stage(name, run, tool_runner, started_at)
        record = _to_record(result, started_at, started)
        session = session.with_stage(record)
        session = _sync(session, run, now)
        save_session(options.state, session)

        if name in ("doctor", "inspect", "provenance") and result.outcome is StageOutcome.FAIL:
            stop = True
        elif name == "probe" and result.outcome in (StageOutcome.FAIL, StageOutcome.BLOCKED):
            if not options.stored:
                skip_rollback = True
        elif (name in ("avb", "rollback") and result.outcome is StageOutcome.FAIL) or (
            name == "plan" and result.outcome is not StageOutcome.PASS
        ):
            stop = True

    session = _sync(session, run, now)
    outcome = _derive_outcome(session)
    verdict = _derive_verdict(session)
    warnings = tuple(warning for record in session.stages for warning in record.warnings)
    session = session.replace(
        outcome=outcome,
        verdict=None if verdict is None else verdict.name,
        warnings=warnings,
        updated_at=now,
    )
    save_session(options.state, session)
    return session


def _run_stage(
    name: str,
    run: WizardRun,
    runner: ToolRunner,
    now: datetime,
) -> StageResult:
    if name == "doctor":
        return stage_doctor(run, runner=runner, now=now)
    if name == "inspect":
        return stage_inspect(run, now=now)
    if name == "provenance":
        return stage_provenance(run, now=now)
    if name == "probe":
        return stage_probe(run, runner=runner, now=now)
    if name == "avb":
        return stage_avb(run, now=now)
    if name == "rollback":
        return stage_rollback(run, runner=runner, now=now)
    if name == "plan":
        return stage_plan(run, runner=runner, now=now)
    if name == "approval":
        return stage_approval(run, now=now)
    raise WizardError(f"unknown wizard stage {name!r}")


def _to_record(result: StageResult, started_at: datetime, started: float) -> StageRecord:
    return StageRecord(
        stage=result.stage,
        title=STAGE_TITLES[result.stage],
        outcome=result.outcome,
        detail=result.detail,
        at=started_at,
        duration_ms=max(0, int((time.perf_counter() - started) * 1000)),
        input_fingerprint=result.input_fingerprint,
        evidence_ids=result.evidence_ids,
        warnings=result.warnings,
        payload=result.payload,
    )


def _sync(session: WizardSession, run: WizardRun, now: datetime) -> WizardSession:
    return session.replace(
        device=run.device,
        archive_sha256=(None if run.manifest is None else run.manifest.archive_sha256),
        index_sha256=run.index_sha256,
        bundle=run.bundle,
        plan=None if run.plan is None else run.plan.to_dict(),
        pre_safety=None if run.pre_safety is None else run.pre_safety.to_dict(),
        post_safety=None if run.post_safety is None else run.post_safety.to_dict(),
        updated_at=now,
    )


def _record_skip(
    session: WizardSession,
    run: WizardRun,
    options: WizardOptions,
    now: datetime,
    stage: str,
    detail: str,
) -> WizardSession:
    record = StageRecord(
        stage=stage,
        title=STAGE_TITLES[stage],
        outcome=StageOutcome.SKIPPED,
        detail=detail,
        at=now,
        duration_ms=0,
        input_fingerprint=rollback_fingerprint(options) if stage == "rollback" else None,
    )
    updated = session.with_stage(record)
    save_session(options.state, updated)
    return _sync(updated, run, now)


def _reuse(
    session: WizardSession,
    options: WizardOptions,
    run: WizardRun,
    now: datetime,
) -> tuple[StageRecord, ...]:
    reused: list[StageRecord] = []
    for name in ("doctor", "probe", "rollback"):
        record = session.stage(name)
        if record is None or record.outcome is not StageOutcome.PASS:
            continue
        age = (now - record.at).total_seconds()
        if age < 0 or age > DEFAULT_REUSE_SECONDS:
            continue
        if name == "doctor" and record.input_fingerprint != doctor_fingerprint(options):
            continue
        if name == "probe":
            if record.input_fingerprint != probe_fingerprint(options):
                continue
            device = session.device
            if device is None or not device.is_fresh(now):
                continue
            run.device = device
            run.lock_evidence = _lock_from_device(device)
        if name == "rollback":
            if record.input_fingerprint != rollback_fingerprint(options):
                continue
            check = _check_from_record(record)
            if check is None:
                continue
            run.rollback_check = check
        reused.append(record)
    return tuple(reused)


def _reused(session: WizardSession, name: str) -> bool:
    record = session.stage(name)
    return (
        record is not None
        and record.outcome is StageOutcome.PASS
        and name
        in (
            "doctor",
            "probe",
            "rollback",
        )
    )


def _lock_from_device(device: DeviceRecord) -> Evidence[str] | None:
    if device.lock_state is None or device.probed_at is None:
        return None
    state = Tri.TRUE if device.lock_state == "unlocked" else Tri.FALSE
    max_age = None if device.max_age_s is None else timedelta(seconds=device.max_age_s)
    return Evidence(
        state=state,
        source=EvidenceSource.PROBED,
        observed_at=device.probed_at,
        value=device.lock_state,
        max_age=max_age,
        detail="reused fresh probe lock state",
    )


def _check_from_record(record: StageRecord) -> CheckState | None:
    if record.payload is None:
        return None
    state_name = record.payload.get("state")
    if not isinstance(state_name, str) or state_name not in {state.name for state in Tri}:
        return None
    return CheckState(
        state=Tri[state_name],
        detail=record.detail,
        evidence_ids=record.evidence_ids,
        warnings=record.warnings,
    )


def _derive_outcome(session: WizardSession) -> SessionOutcome:
    outcomes = {record.stage: record.outcome for record in session.stages}
    if any(outcome is StageOutcome.FAIL for outcome in outcomes.values()):
        return SessionOutcome.FAILED
    if any(outcome is StageOutcome.SIMULATED for outcome in outcomes.values()):
        return SessionOutcome.SIMULATED
    if any(outcome is StageOutcome.BLOCKED for outcome in outcomes.values()):
        return SessionOutcome.BLOCKED
    required = set(STAGE_ORDER) - {"approval"}
    non_approval = {name: outcome for name, outcome in outcomes.items() if name != "approval"}
    approval = outcomes.get("approval")
    if approval is StageOutcome.PASS and set(outcomes) == set(STAGE_ORDER):
        if all(outcome is StageOutcome.PASS for outcome in outcomes.values()):
            return SessionOutcome.CLEARED
        return SessionOutcome.BLOCKED
    if (
        approval is StageOutcome.SKIPPED
        and set(non_approval) == required
        and all(outcome is StageOutcome.PASS for outcome in non_approval.values())
        and _pre_can_proceed(session)
    ):
        return SessionOutcome.READY
    return SessionOutcome.BLOCKED


def _derive_verdict(session: WizardSession) -> Tri | None:
    if not session.stages:
        return None
    mapping = {
        StageOutcome.PASS: Tri.TRUE,
        StageOutcome.FAIL: Tri.FALSE,
        StageOutcome.BLOCKED: Tri.UNKNOWN,
        StageOutcome.SKIPPED: Tri.UNKNOWN,
        StageOutcome.SIMULATED: Tri.UNKNOWN,
    }
    return Tri.all_of(mapping[record.outcome] for record in session.stages)


def _pre_can_proceed(session: WizardSession) -> bool:
    if session.pre_safety is None:
        return False
    value = session.pre_safety.get("can_proceed")
    return value is True
