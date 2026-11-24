"""Command-line entry point for Cairn."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from cairn import __version__
from cairn.adapters.fastboot import FastbootClient, ProbedFact, ProbeResult
from cairn.core.errors import ToolError
from cairn.core.evidence import EvidenceSource
from cairn.core.verification import VerificationLevel
from cairn.sim.transcript import TRANSCRIPT_ENV
from cairn.tools.manifest import TOOL_MANIFEST
from cairn.tools.runner import ToolRunner

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_NOT_IMPLEMENTED = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cairn",
        description="Fail-safe Android flashing with verified, resumable steps.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="command")

    subparsers.add_parser("version", help="print the Cairn version")

    subparsers.add_parser(
        "levels",
        help="print the verification levels used in every report",
    )

    doctor = subparsers.add_parser(
        "doctor",
        help="inspect the host, cable, drivers, and link quality",
    )
    doctor.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )

    probe = subparsers.add_parser(
        "probe",
        help="read-only fastboot device probe (never writes)",
    )
    probe.add_argument(
        "--fastboot",
        type=Path,
        help="path to the official fastboot executable (default: CAIRN_FASTBOOT or PATH)",
    )
    probe.add_argument(
        "--serial",
        help="target device serial; omit to let fastboot choose",
    )
    probe.add_argument(
        "--simulate",
        type=Path,
        metavar="TRANSCRIPT",
        help="replay a recorded transcript instead of touching hardware",
    )
    probe.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return EXIT_OK

    if args.command == "version":
        print(f"cairn {__version__}")
        return EXIT_OK

    if args.command == "levels":
        for level in VerificationLevel:
            print(f"{level.name}: {level.label}")
        return EXIT_OK

    if args.command == "doctor":
        payload = {
            "status": "not_implemented",
            "milestone": "M1",
            "checks_run": 0,
            "message": "Host Doctor is not implemented. No device checks were performed.",
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("cairn doctor: NOT RUN (scheduled for M1)")
            print(payload["message"])
        return EXIT_NOT_IMPLEMENTED

    if args.command == "probe":
        return _run_probe(args)

    parser.error(f"unknown command: {args.command}")


def _run_probe(args: argparse.Namespace) -> int:
    runner = ToolRunner()
    simulated = args.simulate is not None
    prefix: tuple[str, ...]
    tool: dict[str, object]

    if simulated:
        prefix = (sys.executable, "-m", "cairn.sim.fastboot_sim")
        extra_env = {TRANSCRIPT_ENV: str(args.simulate)}
        source = EvidenceSource.INFERRED
        tool = {
            "kind": "simulated",
            "transcript": str(args.simulate),
            "manifest_ok": None,
            "simulated": True,
        }
    else:
        fastboot = _resolve_fastboot(args.fastboot)
        if fastboot is None:
            print(
                "cairn probe: fastboot not found; pass --fastboot or set CAIRN_FASTBOOT",
                file=sys.stderr,
            )
            return EXIT_USAGE
        try:
            report = TOOL_MANIFEST.verify("fastboot", fastboot, runner)
        except ToolError as exc:
            print(f"cairn probe: {exc}", file=sys.stderr)
            return EXIT_USAGE
        prefix = (str(fastboot),)
        extra_env = None
        source = EvidenceSource.PROBED
        tool = {
            "kind": "fastboot",
            "path": str(report.path),
            "version": report.version,
            "sha256": report.sha256,
            "license": report.license,
            "manifest_ok": report.ok,
            "manifest_detail": report.detail,
            "simulated": False,
        }

    client = FastbootClient(prefix, runner=runner, extra_env=extra_env)
    result = client.probe(
        serial=args.serial,
        expected_serial=args.serial,
        source=source,
    )

    payload = {
        "tool": tool,
        "serial": result.serial,
        "tool_ok": result.tool_ok,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "cancelled": result.cancelled,
        "detail": result.detail,
        "facts": [_fact_payload(fact) for fact in result.facts],
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        _print_probe(payload, result, simulated=simulated)

    return EXIT_OK if result.tool_ok else EXIT_FAILED


def _resolve_fastboot(explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit
    env_value = os.environ.get("CAIRN_FASTBOOT")
    if env_value:
        return Path(env_value)
    found = shutil.which("fastboot")
    return Path(found) if found is not None else None


def _fact_payload(fact: ProbedFact) -> dict[str, object]:
    evidence = fact.evidence
    max_age = evidence.max_age
    return {
        "name": fact.name,
        "state": evidence.state.name,
        "value": evidence.value,
        "source": evidence.source.name,
        "observed_at": evidence.observed_at.isoformat(),
        "max_age_s": None if max_age is None else max_age.total_seconds(),
        "detail": evidence.detail,
    }


def _print_probe(
    payload: Mapping[str, object],
    result: ProbeResult,
    *,
    simulated: bool,
) -> None:
    tool = payload["tool"]
    if isinstance(tool, dict):
        if simulated:
            print("probe: SIMULATED transcript replay; this is not device evidence")
        else:
            version = tool.get("version") or "unknown version"
            print(f"probe: fastboot {version} ({tool.get('path')})")
            if tool.get("manifest_ok") is not True:
                print(f"warning: tool manifest check failed: {tool.get('manifest_detail')}")
    print(f"serial: {result.serial or '(fastboot chooses)'}")
    status = "ok" if result.tool_ok else "FAILED"
    print(f"tool status: {status} ({result.detail})")
    for fact in result.facts:
        evidence = fact.evidence
        value = "" if evidence.value is None else f" {evidence.value}"
        print(f"{fact.name}: {evidence.state.name}{value} - {evidence.detail}")
    unknown = sum(1 for fact in result.facts if fact.evidence.state.is_unknown)
    print(f"{len(result.facts)} facts, {unknown} unknown; read-only probe, no device writes")


if __name__ == "__main__":
    raise SystemExit(main())
