"""Tests for the modeled snapshot flows: operator-approved cancel and merge."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from cairn.adapters.fastboot import FastbootClient
from cairn.cli import EXIT_FAILED, EXIT_OK, main
from cairn.sim.transcript import TRANSCRIPT_ENV, Transcript, TranscriptStep, dump_transcript
from cairn.vab import (
    FlowRefused,
    SnapshotFlowInputs,
    expected_acknowledgment,
    run_snapshot_flow,
)

_RECOVERY = b"recovery-image-bytes"


def _transcript(tmp_path: Path, name: str, status: str, *, flow: bool = True) -> Path:
    steps = [
        TranscriptStep(
            argv=("getvar", "snapshot-update-status"),
            stderr=f"(bootloader) snapshot-update-status:{status}\n",
        ),
    ]
    if flow:
        steps.append(
            TranscriptStep(argv=("snapshot-update", name), stdout="OKAY"),
        )
    transcript = Transcript(schema_version=1, device={"product": "pixel-test"}, steps=tuple(steps))
    path = tmp_path / f"{name}-{status}.json"
    dump_transcript(transcript, path)
    return path


def _inputs(
    tmp_path: Path, transcript: Path, action: str, *, ack: str | None = None
) -> SnapshotFlowInputs:
    asset = tmp_path / "recovery.img"
    asset.write_bytes(_RECOVERY)
    import hashlib

    return SnapshotFlowInputs(
        action=action,
        transcript=transcript,
        acknowledgment=ack if ack is not None else expected_acknowledgment(action),
        recovery_asset=asset,
        recovery_sha256=hashlib.sha256(_RECOVERY).hexdigest(),
        last_resort="EDL 9008 entry via test point, service only",
    )


def _factory(transcript: Path) -> FastbootClient:
    return FastbootClient(
        (sys.executable, "-m", "cairn.sim.fastboot_sim"),
        extra_env={TRANSCRIPT_ENV: str(transcript)},
        timeout_s=5.0,
    )


def test_cancel_flow_runs_in_the_simulator(tmp_path: Path) -> None:
    transcript = _transcript(tmp_path, "cancel", "snapshotted")

    report = run_snapshot_flow(
        lambda: _factory(transcript), _inputs(tmp_path, transcript, "cancel")
    )

    assert report.ok is True
    assert report.exit_code == 0
    assert report.merge_state_seen == "snapshotted"
    assert report.simulated is True


def test_merge_flow_requires_a_merging_device(tmp_path: Path) -> None:
    transcript = _transcript(tmp_path, "merge", "merging")

    report = run_snapshot_flow(lambda: _factory(transcript), _inputs(tmp_path, transcript, "merge"))

    assert report.ok is True
    assert report.merge_state_seen == "merging"


def test_merge_is_refused_when_the_device_is_only_snapshotted(tmp_path: Path) -> None:
    transcript = _transcript(tmp_path, "merge", "snapshotted")

    with pytest.raises(FlowRefused, match="requires snapshot-update-status 'merging'"):
        run_snapshot_flow(lambda: _factory(transcript), _inputs(tmp_path, transcript, "merge"))


def test_flow_is_refused_when_nothing_is_in_progress(tmp_path: Path) -> None:
    transcript = _transcript(tmp_path, "cancel", "none")

    with pytest.raises(FlowRefused, match="nothing to cancel"):
        run_snapshot_flow(lambda: _factory(transcript), _inputs(tmp_path, transcript, "cancel"))


def test_acknowledgment_must_be_typed_exactly(tmp_path: Path) -> None:
    transcript = _transcript(tmp_path, "cancel", "snapshotted")

    with pytest.raises(FlowRefused, match="typed exactly"):
        run_snapshot_flow(
            lambda: _factory(transcript),
            _inputs(tmp_path, transcript, "cancel", ack="yes I agree"),
        )


def test_flow_requires_verified_recovery_assets(tmp_path: Path) -> None:
    transcript = _transcript(tmp_path, "cancel", "snapshotted")
    bad_asset = tmp_path / "tampered.img"
    bad_asset.write_bytes(b"different bytes")

    inputs = _inputs(tmp_path, transcript, "cancel")
    inputs = SnapshotFlowInputs(
        action=inputs.action,
        transcript=inputs.transcript,
        acknowledgment=inputs.acknowledgment,
        recovery_asset=bad_asset,
        recovery_sha256=inputs.recovery_sha256,
        last_resort=inputs.last_resort,
    )

    with pytest.raises(FlowRefused, match="recovery assets are not verified"):
        run_snapshot_flow(lambda: _factory(transcript), inputs)


def test_flow_requires_a_stated_last_resort(tmp_path: Path) -> None:
    with pytest.raises(FlowRefused, match="last-resort"):
        SnapshotFlowInputs(
            action="cancel",
            transcript=tmp_path / "t.json",
            acknowledgment=expected_acknowledgment("cancel"),
            recovery_asset=tmp_path / "recovery.img",
            recovery_sha256="0" * 64,
            last_resort="   ",
        )


def test_flow_refuses_an_unknown_action(tmp_path: Path) -> None:
    with pytest.raises(FlowRefused, match="unknown snapshot flow"):
        SnapshotFlowInputs(
            action="sideload",
            transcript=tmp_path / "t.json",
            acknowledgment="x",
            recovery_asset=tmp_path / "recovery.img",
            recovery_sha256="0" * 64,
            last_resort="EDL",
        )


def test_flow_refuses_a_transcript_without_the_snapshot_step(tmp_path: Path) -> None:
    transcript = _transcript(tmp_path, "cancel", "snapshotted", flow=False)

    report = run_snapshot_flow(
        lambda: _factory(transcript), _inputs(tmp_path, transcript, "cancel")
    )
    assert report.ok is False
    assert report.exit_code != 0


def test_cli_cancel_happy_path(tmp_path, capsys) -> None:
    transcript = _transcript(tmp_path, "cancel", "snapshotted")
    import hashlib

    asset = tmp_path / "recovery.img"
    asset.write_bytes(_RECOVERY)

    exit_code = main(
        [
            "vab",
            "cancel",
            "--simulate",
            str(transcript),
            "--acknowledgment",
            expected_acknowledgment("cancel"),
            "--recovery-asset",
            str(asset),
            "--recovery-sha256",
            hashlib.sha256(_RECOVERY).hexdigest(),
            "--last-resort",
            "EDL 9008 entry via test point, service only",
        ]
    )
    assert exit_code == EXIT_OK
    assert "SIMULATED" in capsys.readouterr().out


def test_cli_merge_with_wrong_acknowledgment_is_refused(tmp_path, capsys) -> None:
    transcript = _transcript(tmp_path, "merge", "merging")
    import hashlib

    asset = tmp_path / "recovery.img"
    asset.write_bytes(_RECOVERY)

    exit_code = main(
        [
            "vab",
            "merge",
            "--simulate",
            str(transcript),
            "--acknowledgment",
            "ok fine do it",
            "--recovery-asset",
            str(asset),
            "--recovery-sha256",
            hashlib.sha256(_RECOVERY).hexdigest(),
            "--last-resort",
            "EDL",
        ]
    )
    assert exit_code == EXIT_FAILED
    err = capsys.readouterr().err
    assert "REFUSED" in err
    assert expected_acknowledgment("merge") in err
