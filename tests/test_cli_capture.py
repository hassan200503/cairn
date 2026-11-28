"""CLI wiring tests for `cairn probe --capture` (T23).

Real-device capture cannot run in CI (no USB); these tests pin the wiring:
the --simulate refusal, the output contract through monkeypatched capture
functions, and a full end-to-end run against a platform-appropriate fake
fastboot executable that only answers getvar.
"""

from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cairn.adapters.capture import CaptureFiles, CaptureResult
from cairn.cli import EXIT_OK, EXIT_USAGE, main
from cairn.sim.transcript import Transcript


def test_capture_refuses_simulation(tmp_path: Path) -> None:
    transcript = tmp_path / "t.json"
    transcript.write_text(
        json.dumps({"schema_version": 1, "device": {}, "steps": []}), encoding="utf-8"
    )
    exit_code = main(["probe", "--simulate", str(transcript), "--capture", str(tmp_path / "out")])
    assert exit_code == EXIT_USAGE


def _capture_result(tmp_path: Path) -> CaptureResult:
    from cairn.adapters.capture import SCRUB_PLACEHOLDER

    transcript = Transcript(
        schema_version=1,
        device={"serial_scrubbed": True, "note": "test"},
        steps=(),
    )
    findings = f'id: "HF-TODO"\nserial: "{SCRUB_PLACEHOLDER}"\n'
    return CaptureResult(
        transcript=transcript,
        replacements=2,
        serial_scrubbed=True,
        warnings=("review before committing",),
        findings_yaml=findings,
        tool_ok=True,
        detail="3 invocations recorded; 2 serial occurrence(s) scrubbed",
    )


def test_capture_cli_reports_files_and_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out_dir = tmp_path / "out"
    result = _capture_result(tmp_path)

    def fake_run_capture(client, *, serial, observed_at=None):
        return result

    def fake_write_capture(res, out_dir):
        return CaptureFiles(
            transcript_path=out_dir / "transcript.json",
            findings_path=out_dir / "finding.yaml",
            transcript_sha256="a" * 64,
        )

    monkeypatch.setattr("cairn.cli.run_capture", fake_run_capture)
    monkeypatch.setattr("cairn.cli.write_capture", fake_write_capture)
    # The capture CLI verifies the fastboot binary against the pinned manifest
    # before recording; the fake binary is not in the manifest.
    fake = _write_fake_fastboot(tmp_path / "fastboot")

    def fake_verify(tool_name: str, path: Path, runner: Any) -> SimpleNamespace:
        return SimpleNamespace(
            path=path,
            version="test",
            sha256="0" * 64,
            license="unknown",
            ok=False,
            detail="test double",
        )

    monkeypatch.setattr("cairn.cli.TOOL_MANIFEST.verify", fake_verify)

    exit_code = main(["probe", "--fastboot", str(fake), "--capture", str(out_dir)])
    assert exit_code == EXIT_OK
    text = capsys.readouterr().out
    assert "sha256: " + "a" * 64 in text
    assert "warning: review before committing" in text
    assert "3 invocations recorded" in text


def _write_fake_fastboot(path: Path) -> Path:
    """A stand-in fastboot answering getvar; refuses everything else."""
    if sys.platform == "win32":
        script = path.with_suffix(".cmd")
        script.write_text(
            "@echo off\r\n"
            'if not "%1"=="getvar" exit /b 1\r\n'
            "shift\r\n"
            'if "%~1"=="all" goto all\r\n'
            "echo (bootloader) %~1: simulated-value\r\n"
            "exit /b 0\r\n"
            ":all\r\n"
            "echo (bootloader) product: shiba\r\n"
            "echo (bootloader) serialno: 0A9B8C7D6E5F\r\n"
            "echo (bootloader) unlocked: no\r\n"
            "exit /b 0\r\n",
            encoding="utf-8",
        )
        return script
    script = path
    script.write_text(
        "#!/bin/sh\n"
        'case "$1 $2" in\n'
        '  "getvar all")\n'
        '    echo "(bootloader) product: shiba"\n'
        '    echo "(bootloader) serialno: 0A9B8C7D6E5F"\n'
        '    echo "(bootloader) unlocked: no"\n'
        "    exit 0 ;;\n"
        "esac\n"
        "exit 1\n",
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


@pytest.mark.skipif(
    sys.platform != "linux" and sys.platform != "win32",
    reason="fake fastboot only defined for linux and windows",
)
def test_capture_end_to_end_against_fake_fastboot(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _write_fake_fastboot(tmp_path / "fastboot")
    out_dir = tmp_path / "capture"
    exit_code = main(["probe", "--fastboot", str(fake), "--capture", str(out_dir)])
    assert exit_code == EXIT_OK
    transcript_path = out_dir / "transcript.json"
    assert transcript_path.exists()
    text = transcript_path.read_text(encoding="utf-8")
    assert "0A9B8C7D6E5F" not in text
    assert "CAIRN-SCRUBBED-SERIAL" in text
    loaded = json.loads(text)
    # getvar all + the checklist, every argv a read-only getvar
    assert loaded["steps"][0]["argv"][-2:] == ["getvar", "all"]
    for step in loaded["steps"]:
        assert "getvar" in step["argv"]
        assert not ({"flash", "erase", "reboot", "download"} & set(step["argv"]))
    assert "sha256: " in capsys.readouterr().out


@pytest.mark.skipif(sys.platform != "linux", reason="exec-bit check is POSIX-only")
def test_fake_fastboot_helper_is_executable(tmp_path: Path) -> None:
    fake = _write_fake_fastboot(tmp_path / "fastboot")
    assert subprocess.run([str(fake), "getvar", "all"], capture_output=True).returncode == 0
