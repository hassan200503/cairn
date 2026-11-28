"""Read-only probe capture: real device observations into scrubbed fixtures.

Implements the ``HARDWARE_FINDINGS.md`` section-5 read-only checklist in one
run: every observation is a separate ``getvar`` invocation, all of them are
recorded into a replayable transcript, and the transcript is scrubbed of the
device's serial before it is written. Capture is read-only by construction —
it only ever issues ``getvar`` verbs — and it refuses to write a file that
still contains the observed serial (AGENTS.md rule 10).

A capture is one observation. Per the promotion rule in
``docs/HARDWARE_FINDINGS.md`` it must be reproduced on a second run or a
second device of the same model before it can feed a catalog entry, and a
safety rule may cite it only as a warning until then.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from cairn.adapters.fastboot import FastbootClient, parse_getvar_output
from cairn.core.errors import CairnError
from cairn.sim.transcript import (
    Transcript,
    TranscriptRecorder,
    TranscriptStep,
    dump_transcript,
)

SCRUB_PLACEHOLDER: Final = "CAIRN-SCRUBBED-SERIAL"

# docs/HARDWARE_FINDINGS.md section 5 checklist (read-only getvar verbs only;
# fetch is deliberately absent — the doc says to record the refusal rather
# than run it on locked devices).
CHECKLIST_VARS: Final[tuple[str, ...]] = (
    "current-slot",
    "slot-count",
    "unlocked",
    "secure",
    "max-download-size",
    "max-fetch-size",
    "battery-voltage",
    "battery-soc",
    "battery-soc-ok",
    "battery-status",
    "is-userspace",
    "dynamic-partition",
    "super-partition-name",
    "snapshot-update-status",
    "product",
    "variant",
    "version-bootloader",
    "version-baseband",
    "system-fingerprint",
    "vendor-fingerprint",
    "first-api-level",
    "partition-size:boot_a",
    "partition-size:boot_b",
    "partition-size:system_a",
    "partition-size:system_b",
    "partition-size:vendor_a",
    "partition-size:vendor_b",
    "slot-successful:a",
    "slot-successful:b",
    "slot-unbootable:a",
    "slot-unbootable:b",
    "slot-retry-count:a",
    "slot-retry-count:b",
)

_SERIAL_TOKEN_RE: Final = re.compile(r"\b[0-9A-Fa-f]{8,}\b")


class CaptureError(CairnError):
    code = "CAPTURE_ERROR"


@dataclass(frozen=True, slots=True)
class CaptureResult:
    """A scrubbed capture bundle, ready to be written."""

    transcript: Transcript
    replacements: int
    serial_scrubbed: bool
    warnings: tuple[str, ...]
    findings_yaml: str
    tool_ok: bool
    detail: str


@dataclass(frozen=True, slots=True)
class CaptureFiles:
    transcript_path: Path
    findings_path: Path
    transcript_sha256: str


def run_capture(
    client: FastbootClient,
    *,
    serial: str | None,
    observed_at: datetime | None = None,
) -> CaptureResult:
    """Run the read-only checklist against a device and record everything."""
    if observed_at is None:
        observed_at = datetime.now(UTC)
    recorder = TranscriptRecorder()

    # getvar all first: the primary observation and the source of the serial
    # used for scrubbing.
    all_result = client.getvar_all(serial=serial)
    recorder.record(all_result)

    facts = parse_getvar_output(f"{all_result.stdout}\n{all_result.stderr}")
    observed_serial = facts.get("serialno")

    failures: list[str] = []
    for name in CHECKLIST_VARS:
        result = client.getvar(name, serial=serial)
        recorder.record(result)
        if not result.ok:
            failures.append(name)

    scrub_serials = sorted({s for s in (observed_serial, serial) if s})
    transcript = recorder.transcript(
        device={
            "name": "Scrubbed real-device capture",
            "note": (
                "Captured read-only via `cairn probe --capture` (getvar verbs "
                f"only, never writes). Serial numbers replaced with "
                f"{SCRUB_PLACEHOLDER}. One observation; reproduce before citing "
                "(docs/HARDWARE_FINDINGS.md promotion rule)."
            ),
            "captured": observed_at.date().isoformat(),
            "serial_scrubbed": bool(scrub_serials),
        }
    )
    scrubbed, replacements = scrub_transcript(transcript, scrub_serials)

    warnings: list[str] = []
    if not scrub_serials:
        warnings.append(
            "the device did not report serialno and no --serial was given; "
            "nothing was scrubbed — review the transcript for identifiers "
            "before committing it"
        )
    shaped = [
        token
        for token in _SERIAL_TOKEN_RE.findall(_transcript_text(scrubbed))
        if token not in scrub_serials
    ]
    if shaped:
        warnings.append(
            f"{len(shaped)} serial-shaped token(s) remain (e.g. "
            f"{shaped[0][:4]}...); confirm they are not device identifiers"
        )
    if failures:
        warnings.append(
            f"{len(failures)} checklist variables were not answered; they are "
            "UNKNOWN findings, not gaps in the capture"
        )

    findings = _findings_yaml(scrubbed, facts, failures, observed_at)
    detail = (
        f"{len(scrubbed.steps)} invocations recorded; {replacements} serial occurrence(s) scrubbed"
    )
    return CaptureResult(
        transcript=scrubbed,
        replacements=replacements,
        serial_scrubbed=bool(scrub_serials),
        warnings=tuple(warnings),
        findings_yaml=findings,
        tool_ok=all_result.ok,
        detail=detail,
    )


def scrub_transcript(transcript: Transcript, serials: list[str]) -> tuple[Transcript, int]:
    """Replace every occurrence of the serials in argv/stdout/stderr."""
    replacements = 0
    steps: list[TranscriptStep] = []
    for step in transcript.steps:
        argv = list(step.argv)
        stdout = step.stdout
        stderr = step.stderr
        for serial in serials:
            if not serial:
                continue
            for index, item in enumerate(argv):
                if serial in item:
                    replacements += item.count(serial)
                    argv[index] = item.replace(serial, SCRUB_PLACEHOLDER)
            replacements += stdout.count(serial) + stderr.count(serial)
            stdout = stdout.replace(serial, SCRUB_PLACEHOLDER)
            stderr = stderr.replace(serial, SCRUB_PLACEHOLDER)
        steps.append(
            TranscriptStep(
                argv=tuple(argv),
                exit_code=step.exit_code,
                stdout=stdout,
                stderr=stderr,
                delay_s=step.delay_s,
                fault=step.fault,
            )
        )
    scrubbed = Transcript(
        schema_version=transcript.schema_version,
        device=dict(transcript.device),
        steps=tuple(steps),
    )
    if serials:
        remaining = any(serial in _transcript_text(scrubbed) for serial in serials if serial)
        if remaining:
            raise CaptureError("scrub incomplete: a serial still appears in the transcript")
    return scrubbed, replacements


def write_capture(result: CaptureResult, out_dir: Path) -> CaptureFiles:
    """Write the scrubbed transcript and finding template into ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    transcript_path = out_dir / "transcript.json"
    findings_path = out_dir / "finding.yaml"
    dump_transcript(result.transcript, transcript_path)
    findings_path.write_text(result.findings_yaml, encoding="utf-8")
    sha = hashlib.sha256(transcript_path.read_bytes()).hexdigest()
    return CaptureFiles(
        transcript_path=transcript_path,
        findings_path=findings_path,
        transcript_sha256=sha,
    )


def _transcript_text(transcript: Transcript) -> str:
    return json.dumps(
        {
            "schema_version": transcript.schema_version,
            "device": dict(transcript.device),
            "steps": [step.to_dict() for step in transcript.steps],
        }
    )


def _findings_yaml(
    transcript: Transcript,
    facts: dict[str, str],
    failures: list[str],
    observed_at: datetime,
) -> str:
    """Fill the docs/HARDWARE_FINDINGS.md section-2 template from probe facts."""

    def fact(name: str) -> str:
        value = facts.get(name)
        return value if value else "unknown"

    commands: list[dict[str, object]] = []
    for step in transcript.steps:
        commands.append({"cmd": " ".join(step.argv), "exit_code": step.exit_code})

    unlocked = facts.get("unlocked")
    lock_state = (
        "unknown"
        if unlocked not in ("yes", "no")
        else ("unlocked" if unlocked == "yes" else "locked")
    )
    payload = {
        "id": "HF-TODO",
        "date": observed_at.date().isoformat(),
        "status": "observed",
        "category": "identity",
        "device": {
            "model": fact("product"),
            "codename": fact("product"),
            "region": "unknown",
            "firmware_build": fact("system-fingerprint"),
            "bootloader_lock": lock_state,
            "slots": fact("slot-count"),
            "dynamic_partitions": facts.get("dynamic-partition", "unknown"),
        },
        "host": {
            "os": "fill-me",
            "platform_tools": "fill-me (record the pinned fastboot version)",
            "cable_port": "fill-me",
        },
        "commands": commands,
        "result": {
            "max_verification_level": "V1",
            "writes_performed": "none",
            "artifacts": ["transcript.json (scrubbed; sha256 printed by the capture run)"],
        },
        "safety_impact": (
            "TODO: state what this changes for the catalog or a safety rule. "
            "Checklist vars not answered: " + json.dumps(failures)
        ),
        "source_refs": ["AOSP-FASTBOOT"],
        "notes": (
            "Generated by `cairn probe --capture`. One observation: reproduce "
            "on a second run or device before promotion (status must move to "
            "reproduced, then confirmed)."
        ),
    }
    return _emit_yaml(payload, 0) + "\n"


def _emit_yaml(value: object, indent: int) -> str:
    pad = "  " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}{key}:")
                lines.append(_emit_yaml(item, indent + 1))
            elif isinstance(item, list):
                lines.append(f"{pad}{key}: []")
            else:
                lines.append(f"{pad}{key}: {_yaml_scalar(item)}")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, dict):
                inner = _emit_yaml(item, indent + 1).lstrip()
                lines.append(f"{pad}- {inner}")
            else:
                lines.append(f"{pad}- {_yaml_scalar(item)}")
        return "\n".join(lines)
    return f"{pad}{_yaml_scalar(value)}"


def _yaml_scalar(value: object) -> str:
    if isinstance(value, str):
        return json.dumps(value)
    return str(value)
