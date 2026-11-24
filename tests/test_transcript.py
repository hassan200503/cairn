from __future__ import annotations

import json
from pathlib import Path

import pytest

from cairn.sim.transcript import (
    SCHEMA_VERSION,
    Transcript,
    TranscriptError,
    TranscriptRecorder,
    TranscriptStep,
    dump_transcript,
    load_transcript,
)
from cairn.tools.runner import ToolResult


def make_transcript() -> Transcript:
    return Transcript(
        schema_version=SCHEMA_VERSION,
        device={"name": "synthetic"},
        steps=(
            TranscriptStep(
                argv=("-s", "SIM123", "getvar", "all"),
                stderr="(bootloader) product:shiba\n",
            ),
            TranscriptStep(
                argv=("-s", "BAD", "getvar", "all"),
                exit_code=255,
                stderr="no devices",
                fault="disconnect",
            ),
        ),
    )


def test_transcript_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "transcript.json"
    dump_transcript(make_transcript(), path)
    loaded = load_transcript(path)
    assert loaded.schema_version == SCHEMA_VERSION
    assert loaded.device["name"] == "synthetic"
    assert loaded.steps == make_transcript().steps


def test_find_requires_exact_argv() -> None:
    transcript = make_transcript()
    assert transcript.find(("-s", "SIM123", "getvar", "all")) is not None
    assert transcript.find(("getvar", "all")) is None


def test_dump_omits_default_fields(tmp_path: Path) -> None:
    path = tmp_path / "transcript.json"
    dump_transcript(make_transcript(), path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    first = payload["steps"][0]
    assert "delay_s" not in first
    assert "fault" not in first


def test_load_rejects_unknown_schema(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"schema_version": 99, "device": {}, "steps": []}), encoding="utf-8")
    with pytest.raises(TranscriptError, match="schema_version"):
        load_transcript(path)


def test_load_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(TranscriptError, match="not valid JSON"):
        load_transcript(path)


@pytest.mark.parametrize(
    "step",
    [
        {"argv": []},
        {"argv": "getvar all"},
        {"argv": ["x"], "exit_code": True},
        {"argv": ["x"], "stdout": 3},
        {"argv": ["x"], "delay_s": -1},
        {"argv": ["x"], "fault": "explode"},
    ],
)
def test_step_validation_rejects_bad_data(step: dict[str, object]) -> None:
    with pytest.raises(TranscriptError):
        TranscriptStep.from_dict(step, index=0)


def test_recorder_captures_a_result() -> None:
    recorder = TranscriptRecorder()
    result = ToolResult(
        argv=("fastboot", "--version"),
        exit_code=0,
        stdout="fastboot version 37.0.3-1\n",
        stderr="",
        duration_s=0.1236,
    )
    recorder.record(result)
    transcript = recorder.transcript({"name": "captured"})
    assert transcript.steps[0].argv == ("fastboot", "--version")
    assert transcript.steps[0].delay_s == 0.124
