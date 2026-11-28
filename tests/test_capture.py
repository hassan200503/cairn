"""Read-only probe capture tests (T23).

The capture path must work without hardware: it is exercised with a fabricated
``FastbootClient``-shaped double whose ``getvar``/``getvar_all`` return fixed
``ToolResult`` objects, exactly like the other adapter tests. No test here
touches a real device; the real-device run is a hardware finding, not a test.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cairn.adapters.capture import (
    CHECKLIST_VARS,
    SCRUB_PLACEHOLDER,
    run_capture,
    scrub_transcript,
    write_capture,
)
from cairn.core.errors import ToolError
from cairn.sim.transcript import load_transcript
from cairn.tools.runner import ToolResult

NOW = datetime(2026, 11, 28, tzinfo=UTC)
SERIAL = "0A9B8C7D6E5F"


class FakeClient:
    """FastbootClient stand-in returning canned ToolResults."""

    def __init__(self, all_output: str) -> None:
        self._all_output = all_output
        self.getvar_names: list[str] = []

    def getvar_all(self, *, serial: str | None = None) -> ToolResult:
        argv = ("fastboot", "getvar", "all")
        if serial is not None:
            argv = ("fastboot", "-s", serial, "getvar", "all")
        return ToolResult(
            argv=argv, exit_code=0, stdout=self._all_output, stderr="", duration_s=0.01
        )

    def getvar(self, name: str, *, serial: str | None = None) -> ToolResult:
        self.getvar_names.append(name)
        argv = ("fastboot", "getvar", name)
        if serial is not None:
            argv = ("fastboot", "-s", serial, "getvar", name)
        return ToolResult(
            argv=argv,
            exit_code=0,
            stdout=f"(bootloader) {name}: yes\n",
            stderr="",
            duration_s=0.01,
        )


ALL_OUTPUT = (
    "(bootloader) product: shiba\n"
    "(bootloader) serialno: 0A9B8C7D6E5F\n"
    "(bootloader) unlocked: no\n"
    "(bootloader) current-slot: a\n"
    "(bootloader) slot-count: 2\n"
    "(bootloader) dynamic-partition: yes\n"
    "(bootloader) snapshot-update-status: none\n"
)


def test_capture_records_the_read_only_checklist() -> None:
    client = FakeClient(ALL_OUTPUT)
    result = run_capture(client, serial=None, observed_at=NOW)
    # getvar all + every checklist variable, one invocation each
    assert len(result.transcript.steps) == 1 + len(CHECKLIST_VARS)
    assert client.getvar_names == list(CHECKLIST_VARS)
    assert all(step.argv[1:3] != ("flash", "boot") for step in result.transcript.steps)


def test_capture_scrubs_the_serial_everywhere() -> None:
    client = FakeClient(ALL_OUTPUT)
    result = run_capture(client, serial=SERIAL, observed_at=NOW)
    text = json.dumps(
        {
            "device": dict(result.transcript.device),
            "steps": [step.to_dict() for step in result.transcript.steps],
        }
    )
    assert SERIAL not in text
    assert SCRUB_PLACEHOLDER in text
    assert result.replacements >= 2
    assert result.serial_scrubbed is True
    assert result.warnings == ()


def test_capture_without_a_serial_warns_instead_of_scrubbing() -> None:
    client = FakeClient("(bootloader) product: shiba\n")
    result = run_capture(client, serial=None, observed_at=NOW)
    assert result.serial_scrubbed is False
    assert result.replacements == 0
    assert any("did not report serialno" in warning for warning in result.warnings)


def test_scrub_removes_serials_embedded_in_argv_and_output() -> None:
    from cairn.sim.transcript import Transcript, TranscriptStep

    transcript = Transcript(
        schema_version=1,
        device={},
        steps=(
            TranscriptStep(
                argv=("fastboot", "-s", SERIAL, "getvar", "all"),
                stdout=f"serialno: {SERIAL}\n(bootloader) x: {SERIAL} tail\n",
                stderr=f"error for {SERIAL}\n",
            ),
        ),
    )
    scrubbed, replacements = scrub_transcript(transcript, [SERIAL])
    text = json.dumps({"steps": [step.to_dict() for step in scrubbed.steps]})
    assert SERIAL not in text
    assert replacements == 4
    assert SCRUB_PLACEHOLDER in text


def test_write_capture_emits_replayable_transcript_and_findings(tmp_path: Path) -> None:
    client = FakeClient(ALL_OUTPUT)
    result = run_capture(client, serial=SERIAL, observed_at=NOW)
    files = write_capture(result, tmp_path / "capture")
    assert files.transcript_path.exists()
    assert files.findings_path.exists()
    # the written transcript must round-trip through the simulator loader
    loaded = load_transcript(files.transcript_path)
    assert loaded.device["serial_scrubbed"] is True
    assert len(loaded.steps) == 1 + len(CHECKLIST_VARS)
    text = files.transcript_path.read_text(encoding="utf-8")
    assert SERIAL not in text
    findings = result.findings_yaml
    assert SERIAL not in findings
    assert '"shiba"' in findings
    assert 'writes_performed: "none"' in findings
    assert len(files.transcript_sha256) == 64


def test_findings_yaml_flags_unanswered_vars() -> None:
    client = FakeClient(ALL_OUTPUT)
    result = run_capture(client, serial=None, observed_at=NOW)
    # battery-status is not in ALL_OUTPUT's getvar all; the per-var getvars
    # always answer "yes" in the fake, so nothing is missing here. Sanity:
    assert "Checklist vars not answered" in result.findings_yaml


def test_capture_never_records_a_write_verb() -> None:
    client = FakeClient(ALL_OUTPUT)
    result = run_capture(client, serial=None, observed_at=NOW)
    write_verbs = {"flash", "erase", "reboot", "download", "boot", "update-super"}
    for step in result.transcript.steps:
        assert not (set(step.argv) & write_verbs)


def test_tool_error_propagates_as_capture_failure() -> None:
    class BrokenClient(FakeClient):
        def getvar(self, name: str, *, serial: str | None = None) -> ToolResult:
            raise ToolError(f"broken getvar {name}")

    with pytest.raises(ToolError):
        run_capture(BrokenClient(ALL_OUTPUT), serial=None, observed_at=NOW)
