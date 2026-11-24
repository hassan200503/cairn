"""Recorded fastboot transcripts and a replayable simulator.

A transcript is test data only. It is never evidence about a real device: the
adapter tests use it to exercise parsing and fault classification, and the CLI
``probe --simulate`` path labels its output as simulated.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal, get_args

from cairn.core.errors import ProtocolError
from cairn.tools.runner import ToolResult

SCHEMA_VERSION: Final = 1
TRANSCRIPT_ENV: Final = "CAIRN_SIM_TRANSCRIPT"

SimFault = Literal["timeout", "truncated", "disconnect", "fail", "garbage"]
SIM_FAULTS: Final[frozenset[str]] = frozenset(get_args(SimFault))


class TranscriptError(ProtocolError):
    code = "TRANSCRIPT_ERROR"


@dataclass(frozen=True, slots=True)
class TranscriptStep:
    """One recorded tool invocation and its simulated behavior."""

    argv: tuple[str, ...]
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    delay_s: float = 0.0
    fault: SimFault | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }
        if self.delay_s != 0.0:
            payload["delay_s"] = self.delay_s
        if self.fault is not None:
            payload["fault"] = self.fault
        return payload

    @classmethod
    def from_dict(cls, raw: object, *, index: int) -> TranscriptStep:
        if not isinstance(raw, dict):
            raise TranscriptError(f"step {index} must be an object")
        argv = raw.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(item, str) for item in argv)
        ):
            raise TranscriptError(f"step {index} argv must be a non-empty string list")
        exit_code = raw.get("exit_code", 0)
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise TranscriptError(f"step {index} exit_code must be an integer")
        stdout = raw.get("stdout", "")
        stderr = raw.get("stderr", "")
        if not isinstance(stdout, str) or not isinstance(stderr, str):
            raise TranscriptError(f"step {index} stdout/stderr must be strings")
        delay = raw.get("delay_s", 0.0)
        if isinstance(delay, bool) or not isinstance(delay, (int, float)):
            raise TranscriptError(f"step {index} delay_s must be a number")
        delay_s = float(delay)
        if not math.isfinite(delay_s) or delay_s < 0:
            raise TranscriptError(f"step {index} delay_s must be finite and non-negative")
        fault = raw.get("fault")
        if fault is not None and (not isinstance(fault, str) or fault not in SIM_FAULTS):
            raise TranscriptError(f"step {index} has unknown fault {fault!r}")
        return cls(
            argv=tuple(argv),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            delay_s=delay_s,
            fault=fault,  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class Transcript:
    """A named, versioned set of simulated invocations."""

    schema_version: int
    device: Mapping[str, Any]
    steps: tuple[TranscriptStep, ...]

    def find(self, argv: Sequence[str]) -> TranscriptStep | None:
        """Return the first recorded step matching ``argv`` exactly."""
        wanted = tuple(argv)
        for step in self.steps:
            if step.argv == wanted:
                return step
        return None


@dataclass(slots=True)
class TranscriptRecorder:
    """Collect real tool results into a transcript for later replay."""

    steps: list[TranscriptStep] = field(default_factory=list)

    def record(self, result: ToolResult) -> None:
        self.steps.append(
            TranscriptStep(
                argv=result.argv,
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
                delay_s=round(result.duration_s, 3),
            )
        )

    def transcript(self, device: Mapping[str, Any]) -> Transcript:
        return Transcript(
            schema_version=SCHEMA_VERSION,
            device=dict(device),
            steps=tuple(self.steps),
        )


def load_transcript(path: Path) -> Transcript:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TranscriptError(f"cannot read transcript {path}: {exc}") from exc
    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise TranscriptError(f"transcript {path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise TranscriptError(f"transcript {path} must be a JSON object")

    schema_version = raw.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise TranscriptError(
            f"transcript schema_version must be {SCHEMA_VERSION}, got {schema_version!r}"
        )
    device = raw.get("device")
    if not isinstance(device, dict):
        raise TranscriptError("transcript device must be an object")
    raw_steps = raw.get("steps")
    if not isinstance(raw_steps, list):
        raise TranscriptError("transcript steps must be a list")
    steps = tuple(
        TranscriptStep.from_dict(item, index=index) for index, item in enumerate(raw_steps)
    )
    return Transcript(schema_version=SCHEMA_VERSION, device=device, steps=steps)


def dump_transcript(transcript: Transcript, path: Path) -> None:
    payload = {
        "schema_version": transcript.schema_version,
        "device": dict(transcript.device),
        "steps": [step.to_dict() for step in transcript.steps],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
