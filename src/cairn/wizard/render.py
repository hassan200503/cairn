"""Human-readable wizard output."""

from __future__ import annotations

from cairn.wizard.session import SessionOutcome, StageOutcome, WizardSession

EXIT_CLEARED = 0
EXIT_FAILED = 1
EXIT_NOT_CLEARED = 3

_OUTCOME_LABELS = {
    SessionOutcome.CLEARED: "CLEARED",
    SessionOutcome.READY: "READY",
    SessionOutcome.FAILED: "FAILED",
    SessionOutcome.BLOCKED: "BLOCKED",
    SessionOutcome.SIMULATED: "SIMULATED",
}

_STAGE_LABELS = {
    StageOutcome.PASS: "PASS",
    StageOutcome.FAIL: "FAIL",
    StageOutcome.BLOCKED: "BLOCKED",
    StageOutcome.SKIPPED: "SKIPPED",
    StageOutcome.SIMULATED: "SIMULATED",
}


def session_exit_code(session: WizardSession) -> int:
    if session.outcome is SessionOutcome.CLEARED:
        return EXIT_CLEARED
    if session.outcome is SessionOutcome.FAILED:
        return EXIT_FAILED
    return EXIT_NOT_CLEARED


def render_session(session: WizardSession) -> str:
    lines = [
        f"cairn wizard session: {session.session_id}",
        f"state file: {session.package_path} -> {session.index_path}",
        f"package: {session.package_path}",
        f"index: {session.index_path}",
        f"outcome: {_OUTCOME_LABELS[session.outcome]}",
        f"verdict: {session.verdict or 'not evaluated'}",
        "verification level: read-only; V0-V3 describe writes and are not claimed",
    ]
    if session.archive_sha256 is not None:
        lines.append(f"archive sha256: {session.archive_sha256}")
    if session.index_sha256 is not None:
        lines.append(f"index sha256: {session.index_sha256}")
    if session.device is not None:
        device = session.device
        source = device.source + (" (simulated)" if device.simulated else "")
        lines.append(f"device source: {source}")
        if device.fingerprint_sha256 is not None:
            lines.append(f"device fingerprint: {device.fingerprint_sha256}")
        if device.serial_sha256 is not None:
            lines.append(f"serial sha256: {device.serial_sha256}")
        if device.lock_state is not None:
            lines.append(f"lock state: {device.lock_state}")
    lines.append("stages:")
    for record in session.stages:
        lines.append(f"  {record.stage}: {_STAGE_LABELS[record.outcome]} - {record.detail}")
        for warning in record.warnings:
            lines.append(f"    warning: {warning}")
    if session.plan is not None:
        plan_sha = session.plan.get("plan_sha256")
        if isinstance(plan_sha, str):
            lines.append(f"plan sha256: {plan_sha}")
        lines.append(
            "structurally executable: "
            + ("TRUE" if session.plan.get("executable") is True else "FALSE")
        )
    if session.pre_safety is not None:
        lines.append(
            "pre-approval safety: "
            + str(session.pre_safety.get("verdict", "UNKNOWN"))
            + " (can_proceed="
            + ("TRUE" if session.pre_safety.get("can_proceed") is True else "FALSE")
            + ")"
        )
    if session.post_safety is not None and session.post_safety is not session.pre_safety:
        lines.append(
            "post-approval safety: "
            + str(session.post_safety.get("verdict", "UNKNOWN"))
            + " (can_proceed="
            + ("TRUE" if session.post_safety.get("can_proceed") is True else "FALSE")
            + ")"
        )
    if session.outcome is SessionOutcome.READY:
        lines.append("next: issue an approval token with `cairn approval issue --session <state>`")
    for warning in session.warnings:
        lines.append(f"warning: {warning}")
    lines.append("read-only: no device writes were performed")
    return "\n".join(lines)
