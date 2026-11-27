"""Tests for the dynamic-partition mode gate (SR-011)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from cairn.adapters.fastboot import FastbootClient
from cairn.cli import EXIT_FAILED, EXIT_UNKNOWN, EXIT_USAGE, main
from cairn.core.errors import CairnError
from cairn.core.tristate import Tri
from cairn.sim.transcript import TRANSCRIPT_ENV, Transcript, TranscriptStep, dump_transcript
from cairn.tools.runner import ToolResult
from cairn.vab import classify_dynpart_mode, read_dynpart

FIXTURE = Path(__file__).parent / "fixtures" / "fastboot" / "pixel8_getvar_all.json"


class _FakeFastboot:
    def __init__(self, results: dict[str, ToolResult]) -> None:
        self._results = results
        self.serial: str | None = None

    def getvar(self, name: str, *, serial: str | None = None) -> ToolResult:
        self.serial = serial
        return self._results[name]


def _result(*, exit_code: int = 0, stderr: str = "") -> ToolResult:
    return ToolResult(
        argv=("fastboot", "getvar"),
        exit_code=exit_code,
        stdout="",
        stderr=stderr,
        duration_s=0.01,
    )


def _fastbootd_device() -> dict[str, ToolResult]:
    return {
        "is-userspace": _result(stderr="(bootloader) is-userspace:yes\n"),
        "dynamic-partition": _result(stderr="(bootloader) dynamic-partition:yes\n"),
        "super-partition-name": _result(stderr="(bootloader) super-partition-name:super\n"),
    }


def test_fastbootd_job_in_fastbootd_passes() -> None:
    read = classify_dynpart_mode(job_mode="fastbootd", is_userspace=True, dynamic_partition=True)
    assert read.state is Tri.TRUE
    assert read.detail


def test_fastbootd_job_from_bootloader_is_false() -> None:
    read = classify_dynpart_mode(job_mode="fastbootd", is_userspace=False, dynamic_partition=True)
    assert read.state is Tri.FALSE
    assert "fastbootd" in read.detail


def test_unreadable_facts_block_as_unknown() -> None:
    for userspace, dynamic in ((None, True), (True, None), (None, None)):
        read = classify_dynpart_mode(
            job_mode="fastbootd", is_userspace=userspace, dynamic_partition=dynamic
        )
        assert read.state is Tri.UNKNOWN


def test_non_dynamic_device_accepts_bootloader_flash() -> None:
    read = classify_dynpart_mode(job_mode="bootloader", is_userspace=False, dynamic_partition=False)
    assert read.state is Tri.TRUE


def test_bootloader_job_on_dynamic_device_is_unknown_and_warns() -> None:
    read = classify_dynpart_mode(job_mode="bootloader", is_userspace=False, dynamic_partition=True)
    assert read.state is Tri.UNKNOWN
    assert read.warnings


def test_invalid_job_mode_is_refused() -> None:
    with pytest.raises(CairnError):
        classify_dynpart_mode(job_mode="sideload", is_userspace=True, dynamic_partition=True)


def test_read_collects_all_three_getvars() -> None:
    client = _FakeFastboot(_fastbootd_device())

    read = read_dynpart(client, job_mode="fastbootd", serial="SIM123")

    assert client.serial == "SIM123"
    assert read.is_userspace is True
    assert read.dynamic_partition is True
    assert read.super_partition_name == "super"
    assert read.state is Tri.TRUE


def test_read_fails_closed_when_a_getvar_fails() -> None:
    results = _fastbootd_device()
    results["dynamic-partition"] = _result(exit_code=1, stderr="FAILED (remote)")
    client = _FakeFastboot(results)

    read = read_dynpart(client, job_mode="fastbootd")

    assert read.state is Tri.UNKNOWN
    assert read.dynamic_partition is None


def test_read_against_a_recorded_transcript(tmp_path) -> None:
    transcript = Transcript(
        schema_version=1,
        device={"product": "pixel-test"},
        steps=(
            TranscriptStep(
                argv=("getvar", "is-userspace"), stderr="(bootloader) is-userspace:no\n"
            ),
            TranscriptStep(
                argv=("getvar", "dynamic-partition"), stderr="(bootloader) dynamic-partition:yes\n"
            ),
            TranscriptStep(
                argv=("getvar", "super-partition-name"),
                stderr="(bootloader) super-partition-name:super\n",
            ),
        ),
    )
    path = tmp_path / "bootloader-dynamic.json"
    dump_transcript(transcript, path)
    client = FastbootClient(
        (sys.executable, "-m", "cairn.sim.fastboot_sim"),
        extra_env={TRANSCRIPT_ENV: str(path)},
        timeout_s=5.0,
    )

    # No serial: the recorded steps match the bare getvar argv exactly.
    read = read_dynpart(client, job_mode="bootloader", simulated=True)

    # A bootloader-mode job on a dynamic-partition device is not provably
    # right: retrofit force and logical targeting are unmodeled, so the gate
    # is UNKNOWN with warnings, never a silent pass.
    assert read.state is Tri.UNKNOWN
    assert read.simulated is True
    assert read.dynamic_partition is True
    assert read.is_userspace is False
    assert read.warnings


def test_cli_dynpart_false_in_bootloader_mode(tmp_path, capsys) -> None:
    transcript = Transcript(
        schema_version=1,
        device={"product": "pixel-test"},
        steps=(
            TranscriptStep(
                argv=("getvar", "is-userspace"), stderr="(bootloader) is-userspace:no\n"
            ),
            TranscriptStep(
                argv=("getvar", "dynamic-partition"), stderr="(bootloader) dynamic-partition:yes\n"
            ),
            TranscriptStep(
                argv=("getvar", "super-partition-name"),
                stderr="(bootloader) super-partition-name:super\n",
            ),
        ),
    )
    path = tmp_path / "dynpart.json"
    dump_transcript(transcript, path)

    assert main(["vab", "dynpart", "--mode", "fastbootd", "--simulate", str(path)]) == EXIT_FAILED
    out = capsys.readouterr().out
    assert "FALSE" in out
    assert "reboot to fastbootd" in out


def test_cli_dynpart_unknown_and_rejects_bogus_mode(tmp_path, capsys) -> None:
    assert (
        main(["vab", "dynpart", "--mode", "fastbootd", "--simulate", str(FIXTURE)]) == EXIT_UNKNOWN
    )
    with pytest.raises(SystemExit) as excinfo:
        main(["vab", "dynpart", "--mode", "bogus", "--simulate", str(FIXTURE)])
    assert excinfo.value.code == EXIT_USAGE
