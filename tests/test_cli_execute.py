"""CLI tests for `cairn execute`: approved plans run in the simulator, refuse real hardware."""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cairn.approval import (
    ApprovalInputs,
    DeviceBinding,
    DeviceBindingSource,
    issue_approval,
    write_approval_key,
)
from cairn.cli import EXIT_FAILED, EXIT_OK, EXIT_UNKNOWN, main
from cairn.core.tristate import Tri
from cairn.executor import Journal, JournalKind, staged_image_path
from cairn.package.archive import load_package
from cairn.plan.planner import PlanFacts, PlanOptions, build_plan
from cairn.provenance.hash_index import load_hash_index, verify_manifest
from cairn.sim.transcript import Transcript, TranscriptStep, dump_transcript
from cairn.wizard.session import (
    STAGE_TITLES,
    ApprovalBundle,
    DeviceRecord,
    SessionOutcome,
    StageOutcome,
    StageRecord,
    load_session,
    new_session,
    save_session,
)

INFO_TEXT = """\
version 1
flash boot boot.img
erase cache
reboot bootloader
"""

_BOOT_BYTES = b"boot-image-bytes"
_NONCE = "a" * 32
_FINGERPRINT = hashlib.sha256(b"device").hexdigest()


def _hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _package(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("boot.img", _BOOT_BYTES)
        archive.writestr("fastboot-info.txt", INFO_TEXT)
    return path


def _index(path: Path, package: Path) -> Path:
    manifest = load_package(package, hash_files=True, hash_archive=True)
    payload = {
        "schema_version": 1,
        "packages": [
            {
                "id": "cli-execute-test",
                "archive_sha256": manifest.archive_sha256,
                "entries": {entry.name: entry.sha256 for entry in manifest.entries},
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _plan(package: Path, index: Path):
    manifest = load_package(package, hash_files=True, hash_archive=True)
    provenance = verify_manifest(load_hash_index(index), manifest)
    return build_plan(manifest, provenance, options=PlanOptions(), facts=PlanFacts())


def _ready_session(path: Path, package: Path, index: Path) -> Path:
    manifest = load_package(package, hash_files=True, hash_archive=True)
    plan = _plan(package, index)
    snapshot = _hex("snapshot")
    pre_safety = {
        "can_proceed": True,
        "evidence_snapshot_sha256": snapshot,
        "verdict": "TRUE",
        "blocking": [],
    }
    now = datetime.now(UTC)
    device = DeviceRecord(
        source="probed",
        simulated=False,
        nonce=_NONCE,
        fingerprint_sha256=_FINGERPRINT,
        probed_at=now,
        max_age_s=600,
    )
    bundle = ApprovalBundle(
        plan_sha256=plan.plan_sha256,
        evidence_snapshot_sha256=snapshot,
        archive_sha256=manifest.archive_sha256,
        package_hashes=tuple(sorted((entry.name, entry.sha256) for entry in manifest.entries)),
        tools=(),
        pre_safety=pre_safety,
        plan_options=plan.options.to_dict(),
        plan_facts=plan.facts.to_dict(),
    )
    stages = (
        *(
            StageRecord(
                stage=name,
                title=STAGE_TITLES[name],
                outcome=StageOutcome.PASS,
                detail="test pass",
                at=now,
                duration_ms=0,
            )
            for name in ("doctor", "inspect", "provenance", "probe", "avb", "rollback", "plan")
        ),
        StageRecord(
            stage="approval",
            title=STAGE_TITLES["approval"],
            outcome=StageOutcome.SKIPPED,
            detail="awaiting approval token",
            at=now,
            duration_ms=0,
        ),
    )
    session = new_session(
        package_path=package,
        index_path=index,
        cairn_version="test",
        now=now,
        session_id="b" * 32,
    ).replace(
        stages=stages,
        device=device,
        bundle=bundle,
        archive_sha256=manifest.archive_sha256,
        index_sha256=hashlib.sha256(index.read_bytes()).hexdigest(),
        plan=plan.to_dict(),
        pre_safety=pre_safety,
        outcome=SessionOutcome.READY,
    )
    save_session(path, session)
    return path


def _issue_token(package: Path, index: Path, key_path: Path, token_path: Path) -> None:
    manifest = load_package(package, hash_files=True, hash_archive=True)
    plan = _plan(package, index)
    from cairn.safety.engine import SafetyReport

    safety = SafetyReport(
        rules=(),
        overrides=(),
        verdict=Tri.TRUE,
        can_proceed=True,
        blocking=(),
        evidence_snapshot_sha256=_hex("snapshot"),
        report_text="test",
    )
    key = hashlib.sha256(b"approval-key").digest()
    write_approval_key(key_path, key)
    inputs = ApprovalInputs.from_manifest(
        manifest,
        plan,
        safety,
        DeviceBinding(
            nonce=_NONCE,
            fingerprint_sha256=_FINGERPRINT,
            source=DeviceBindingSource.PROBED,
        ),
    )
    token = issue_approval(inputs, key, operator="op", reason="executor test run")
    token_path.write_text(token.to_json(), encoding="utf-8", newline="\n")


def _write_transcript(package: Path, index: Path, staging: Path, path: Path) -> Path:
    del package, index  # the transcript is fixed; staging paths must match the executor
    transcript = Transcript(
        schema_version=1,
        device={"product": "cli-execute-test"},
        steps=(
            TranscriptStep(
                argv=("flash", "boot", str(staged_image_path(staging, "boot.img"))),
                stdout="OKAY",
            ),
            TranscriptStep(argv=("erase", "cache"), stdout="OKAY"),
            TranscriptStep(argv=("reboot", "bootloader"), stdout="OKAY"),
        ),
    )
    dump_transcript(transcript, path)
    return path


def _run(args: list[str]) -> int:
    return main(args)


def test_execute_runs_an_approved_plan_in_the_simulator(tmp_path: Path, capsys) -> None:
    package = _package(tmp_path / "factory.zip")
    index = _index(tmp_path / "index.json", package)
    state = _ready_session(tmp_path / "wizard.json", package, index)
    key_path = tmp_path / "approval.key"
    token_path = tmp_path / "token.json"
    _issue_token(package, index, key_path, token_path)
    staging = tmp_path / "stage"
    transcript = _write_transcript(package, index, staging, tmp_path / "writes.json")

    exit_code = _run(
        [
            "execute",
            "--state",
            str(state),
            "--simulate",
            str(transcript),
            "--token",
            str(token_path),
            "--key",
            str(key_path),
            "--nonce",
            _NONCE,
            "--device-fingerprint",
            _FINGERPRINT,
            "--staging-dir",
            str(staging),
            "--json",
        ]
    )

    assert exit_code == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "TRUE"
    assert payload["completed"] is True
    assert payload["simulated"] is True
    journal = load_session(state).replace()  # state hash still valid
    assert journal.state_sha256
    records = Journal.load(Path(f"{state}.journal")).records
    assert records[-1].kind is JournalKind.COMPLETED
    assert [record.kind for record in records].count(JournalKind.STEP_DONE) == 3


def test_execute_refuses_when_the_package_changed_after_approval(tmp_path: Path) -> None:
    package = _package(tmp_path / "factory.zip")
    index = _index(tmp_path / "index.json", package)
    state = _ready_session(tmp_path / "wizard.json", package, index)
    key_path = tmp_path / "approval.key"
    token_path = tmp_path / "token.json"
    _issue_token(package, index, key_path, token_path)
    transcript = _write_transcript(package, index, tmp_path / "stage", tmp_path / "writes.json")
    # Rewrite the package with different bytes after approval.
    with zipfile.ZipFile(package, "a", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("extra.txt", b"unexpected")

    exit_code = _run(
        [
            "execute",
            "--state",
            str(state),
            "--simulate",
            str(transcript),
            "--token",
            str(token_path),
            "--key",
            str(key_path),
            "--nonce",
            _NONCE,
            "--device-fingerprint",
            _FINGERPRINT,
            "--staging-dir",
            str(tmp_path / "stage"),
        ]
    )
    assert exit_code == EXIT_FAILED


def test_execute_stops_on_a_failed_step_and_blocks_the_resume(tmp_path: Path) -> None:
    package = _package(tmp_path / "factory.zip")
    index = _index(tmp_path / "index.json", package)
    state = _ready_session(tmp_path / "wizard.json", package, index)
    key_path = tmp_path / "approval.key"
    token_path = tmp_path / "token.json"
    _issue_token(package, index, key_path, token_path)
    staging = tmp_path / "stage"
    transcript = Transcript(
        schema_version=1,
        device={"product": "cli-execute-test"},
        steps=(
            TranscriptStep(
                argv=("flash", "boot", str(staged_image_path(staging, "boot.img"))),
                stdout="OKAY",
            ),
            TranscriptStep(
                argv=("erase", "cache"),
                fault="fail",
                exit_code=1,
                stderr="FAILED (remote: 'simulated failure')",
            ),
            TranscriptStep(argv=("reboot", "bootloader"), stdout="OKAY"),
        ),
    )
    transcript_path = tmp_path / "writes.json"
    dump_transcript(transcript, transcript_path)

    base = [
        "execute",
        "--state",
        str(state),
        "--simulate",
        str(transcript_path),
        "--token",
        str(token_path),
        "--key",
        str(key_path),
        "--nonce",
        _NONCE,
        "--device-fingerprint",
        _FINGERPRINT,
        "--staging-dir",
        str(staging),
    ]
    assert _run(base) == EXIT_FAILED
    # A resume must not retry the failed step: blocked, and the reboot never ran.
    assert _run(base) == EXIT_UNKNOWN
    records = Journal.load(Path(f"{state}.journal")).records
    kinds = [record.kind for record in records]
    assert kinds.count(JournalKind.ABORTED) == 1  # the resume refused the failed step
    assert kinds.count(JournalKind.STEP_DONE) == 1
    assert kinds.count(JournalKind.STEP_SKIPPED) == 1
    assert kinds.count(JournalKind.STEP_FAILED) == 1


def test_execute_refuses_a_blocked_session(tmp_path: Path, capsys) -> None:
    package = _package(tmp_path / "factory.zip")
    index = _index(tmp_path / "index.json", package)
    state = _ready_session(tmp_path / "wizard.json", package, index)
    session = load_session(state)
    blocked = session.replace(outcome=SessionOutcome.BLOCKED)
    save_session(state, blocked)

    exit_code = _run(
        [
            "execute",
            "--state",
            str(state),
            "--simulate",
            str(tmp_path / "writes.json"),
            "--token",
            str(tmp_path / "token.json"),
            "--key",
            str(tmp_path / "approval.key"),
            "--nonce",
            _NONCE,
            "--device-fingerprint",
            _FINGERPRINT,
        ]
    )
    assert exit_code == EXIT_UNKNOWN
    assert "blocked" in capsys.readouterr().err


@pytest.mark.parametrize("simulated", [False])
def test_transport_refuses_real_fastboot(simulated: bool) -> None:
    from cairn.executor import ExecutorRefused, SimulatedFastbootTransport

    with pytest.raises(ExecutorRefused, match="M6 gate"):
        SimulatedFastbootTransport(("fastboot",), simulated=simulated)
