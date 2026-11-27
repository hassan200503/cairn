"""Tests for the Virtual A/B merge-state read and the SR-010 gate."""

from __future__ import annotations

import sys
from pathlib import Path

from cairn.adapters.fastboot import FastbootClient
from cairn.cli import EXIT_FAILED, EXIT_OK, main
from cairn.core.tristate import Tri
from cairn.sim.transcript import TRANSCRIPT_ENV
from cairn.tools.runner import ToolResult
from cairn.vab import classify_snapshot_status, read_merge_state

FIXTURE = Path(__file__).parent / "fixtures" / "fastboot" / "pixel8_getvar_all.json"


class _FakeFastboot:
    def __init__(self, result: ToolResult) -> None:
        self._result = result
        self.serial: str | None = None

    def getvar(self, name: str, *, serial: str | None = None) -> ToolResult:
        self.serial = serial
        return self._result


def _result(
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> ToolResult:
    return ToolResult(
        argv=("fastboot", "getvar", "snapshot-update-status"),
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_s=0.01,
    )


def test_none_is_true() -> None:
    read = classify_snapshot_status("none")
    assert read.state is Tri.TRUE
    assert read.value == "none"


def test_mid_merge_states_are_false_and_never_overridable() -> None:
    for value in ("snapshotted", "merging", "merge_pending"):
        read = classify_snapshot_status(value)
        assert read.state is Tri.FALSE
        assert "never overridable" in read.detail


def test_unknown_and_vendor_values_are_unknown() -> None:
    assert classify_snapshot_status(None).state is Tri.UNKNOWN
    assert classify_snapshot_status("").state is Tri.UNKNOWN
    read = classify_snapshot_status("vendor-custom-state")
    assert read.state is Tri.UNKNOWN
    assert "KU-004" in read.detail


def test_read_parses_bootloader_prefixed_value() -> None:
    client = _FakeFastboot(_result(stderr="(bootloader) snapshot-update-status:merging\n"))

    read = read_merge_state(client, serial="SIM123")

    assert client.serial == "SIM123"
    assert read.state is Tri.FALSE
    assert read.value == "merging"


def test_read_fails_closed_on_tool_failure() -> None:
    client = _FakeFastboot(_result(exit_code=1, stderr="fastboot: error: FAILED (remote)"))

    read = read_merge_state(client)

    assert read.state is Tri.UNKNOWN
    assert read.value is None
    assert any("FAIL" in warning for warning in read.warnings)


def test_read_against_the_recorded_transcript() -> None:
    client = FastbootClient(
        (sys.executable, "-m", "cairn.sim.fastboot_sim"),
        extra_env={TRANSCRIPT_ENV: str(FIXTURE)},
        timeout_s=5.0,
    )

    read = read_merge_state(client, serial="SIM123", simulated=True)

    assert read.state is Tri.TRUE
    assert read.value == "none"
    assert read.simulated is True


def test_cli_vab_status_simulated(tmp_path, capsys) -> None:
    assert (
        main(["vab", "status", "--simulate", str(FIXTURE), "--serial", "SIM123", "--json"])
        == EXIT_OK
    )
    import json

    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "TRUE"
    assert payload["value"] == "none"
    assert payload["simulated"] is True


def test_cli_vab_status_reports_false_for_a_merging_transcript(tmp_path, capsys) -> None:
    from cairn.sim.transcript import Transcript, TranscriptStep, dump_transcript

    transcript = Transcript(
        schema_version=1,
        device={"product": "pixel-test"},
        steps=(
            TranscriptStep(
                argv=("getvar", "snapshot-update-status"),
                stderr="(bootloader) snapshot-update-status:merging\n",
            ),
        ),
    )
    path = tmp_path / "merging.json"
    dump_transcript(transcript, path)

    assert main(["vab", "status", "--simulate", str(path)]) == EXIT_FAILED
    err = capsys.readouterr().out
    assert "FALSE" in err
    assert "never overridable" in err
