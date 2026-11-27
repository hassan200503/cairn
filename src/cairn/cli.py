"""Command-line entry point for Cairn."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from cairn import __version__
from cairn.adapters.fastboot import FastbootClient, ProbedFact, ProbeResult
from cairn.approval import (
    MAX_TOKEN_BYTES,
    ApprovalError,
    ApprovalInputs,
    ApprovalToken,
    ApprovalVerdict,
    DeviceBinding,
    ToolBinding,
    build_device_binding,
    caller_device_binding,
    device_fingerprint,
    generate_approval_key,
    issue_approval,
    key_id,
    load_approval_key,
    parse_approval_token,
    verify_approval,
    write_approval_key,
)
from cairn.core.errors import ToolError
from cairn.core.evidence import EvidenceSource
from cairn.core.tristate import Tri
from cairn.core.verification import VerificationLevel
from cairn.host.doctor import SOAK_ATTEMPTS_DEFAULT, HostDoctor, HostReport
from cairn.package.archive import PackageError, PackageManifest, load_package
from cairn.plan.planner import (
    PlanError,
    PlanOptions,
    PlanStep,
    SlotPolicy,
    build_plan,
)
from cairn.plan.safety import PlanAssessment, assess_plan
from cairn.provenance.avb import (
    AvbChainPartition,
    AvbChainReport,
    AvbError,
    AvbHashDescriptor,
    AvbHashtreeDescriptor,
    AvbKernelCmdline,
    AvbProperty,
    AvbSignature,
    AvbUnknownDescriptor,
    VbmetaImage,
    calculate_vbmeta_digest,
    load_vbmeta,
    verify_vbmeta_chain,
    verify_vbmeta_signature,
)
from cairn.provenance.hash_index import (
    HashIndexError,
    ProvenanceResult,
    load_hash_index,
    verify_manifest,
)
from cairn.provenance.trust import LockKeyCheck, LockState, evaluate_lock_key
from cairn.rollback.device import (
    DeviceRollbackRead,
    read_stored_rollback_indexes,
)
from cairn.rollback.oracle import (
    MAX_ROLLBACK_INDEX,
    RollbackError,
    RollbackReport,
    evaluate_avb_rollback,
)
from cairn.safety.engine import SafetyContext, SafetyEngine
from cairn.sim.transcript import TRANSCRIPT_ENV
from cairn.tools.manifest import TOOL_MANIFEST
from cairn.tools.runner import ToolRunner
from cairn.wizard.render import render_session, session_exit_code
from cairn.wizard.runner import run_wizard
from cairn.wizard.session import (
    SessionOutcome,
    WizardError,
    load_session,
)
from cairn.wizard.stages import (
    WizardOptions,
    reload_session_plan,
)

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_UNKNOWN = 3


def _add_plan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--wipe",
        action="store_true",
        help="include vendor if-wipe commands",
    )
    parser.add_argument(
        "--slot",
        choices=[policy.value for policy in SlotPolicy],
        default=SlotPolicy.CURRENT.value,
        help="slot policy",
    )
    parser.add_argument(
        "--retrofit-force",
        action="store_true",
        help="request the unmodeled retrofit force case",
    )


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
    doctor.add_argument(
        "--fastboot",
        type=Path,
        help="path to the official fastboot executable (default: CAIRN_FASTBOOT or PATH)",
    )
    doctor.add_argument(
        "--adb",
        type=Path,
        help="path to the official adb executable (default: CAIRN_ADB or PATH)",
    )
    doctor.add_argument("--serial", help="target device serial for the link soak")
    doctor.add_argument(
        "--simulate",
        type=Path,
        metavar="TRANSCRIPT",
        help="replay a transcript for the link soak instead of touching hardware",
    )
    doctor.add_argument(
        "--soak",
        type=int,
        default=SOAK_ATTEMPTS_DEFAULT,
        metavar="N",
        help=f"link soak probe count (default {SOAK_ATTEMPTS_DEFAULT}; 0 disables)",
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

    inspect = subparsers.add_parser(
        "inspect",
        help="read-only package inspection (no extraction, no device access)",
    )
    inspect.add_argument("package", type=Path, help="factory or OTA zip")
    inspect.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )
    inspect.add_argument(
        "--hash",
        action="store_true",
        help="hash every entry and the archive (reads all data)",
    )

    provenance = subparsers.add_parser(
        "provenance",
        help="match a package against a local hash index (read-only)",
    )
    provenance.add_argument("package", type=Path, help="factory or OTA zip")
    provenance.add_argument(
        "--index",
        type=Path,
        required=True,
        help="local hash-index JSON",
    )
    provenance.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )

    plan = subparsers.add_parser(
        "plan",
        help="build a read-only vendor-order flash plan (dry run)",
    )
    plan.add_argument("package", type=Path, help="factory or OTA zip")
    plan.add_argument(
        "--index",
        type=Path,
        required=True,
        help="local hash-index JSON",
    )
    plan.add_argument(
        "--wipe",
        action="store_true",
        help="include vendor if-wipe commands",
    )
    plan.add_argument(
        "--slot",
        choices=[policy.value for policy in SlotPolicy],
        default=SlotPolicy.CURRENT.value,
        help="slot policy (non-current policies need verified slot facts)",
    )
    plan.add_argument(
        "--retrofit-force",
        action="store_true",
        help="request the unmodeled retrofit force case (plan will not be executable)",
    )
    plan.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )
    plan.add_argument(
        "--approval",
        type=Path,
        metavar="TOKEN",
        help="signed approval token to verify before deciding",
    )
    plan.add_argument(
        "--approval-key",
        type=Path,
        help="approval key file (requires --approval)",
    )
    plan.add_argument(
        "--nonce",
        help="session nonce, 32-128 lowercase hex (requires --approval)",
    )
    plan.add_argument(
        "--device-fingerprint",
        help="caller-supplied 64-hex device fingerprint (requires --approval)",
    )
    plan.add_argument(
        "--tool",
        action="append",
        default=[],
        metavar="NAME=VERSION[@SHA256]",
        help="tool identity bound in the approval; repeat as needed",
    )

    wizard = subparsers.add_parser(
        "wizard",
        help="run the read-only, resumable preflight wizard",
    )
    wizard.add_argument("package", type=Path, help="factory or OTA zip")
    wizard.add_argument(
        "--index",
        type=Path,
        required=True,
        help="local hash-index JSON",
    )
    wizard.add_argument(
        "--state",
        type=Path,
        required=True,
        help="wizard session JSON path",
    )
    state_mode = wizard.add_mutually_exclusive_group()
    state_mode.add_argument(
        "--resume",
        action="store_true",
        help="reuse fresh doctor, probe, and rollback stages from --state",
    )
    state_mode.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing session and ignore prior stages",
    )
    wizard.add_argument(
        "--fastboot",
        type=Path,
        help="path to the official fastboot executable (default: CAIRN_FASTBOOT or PATH)",
    )
    wizard.add_argument("--serial", help="target device serial")
    wizard.add_argument(
        "--soak",
        type=int,
        default=SOAK_ATTEMPTS_DEFAULT,
        metavar="N",
        help=f"link soak probe count (default {SOAK_ATTEMPTS_DEFAULT}; 0 disables)",
    )
    wizard_source = wizard.add_mutually_exclusive_group()
    wizard_source.add_argument(
        "--simulate",
        type=Path,
        metavar="TRANSCRIPT",
        help="replay a transcript instead of touching hardware",
    )
    wizard_source.add_argument(
        "--device-fingerprint",
        help="caller-supplied 64-hex fingerprint; weaker than a probe",
    )
    wizard.add_argument("--vbmeta", type=Path, help="VBMeta image for AVB and rollback checks")
    wizard.add_argument(
        "--chain",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="chained partition image; repeat for multiple chains",
    )
    wizard.add_argument(
        "--key",
        type=Path,
        metavar="AVBPUBKEY",
        help="expected raw AVB public key",
    )
    wizard.add_argument(
        "--lock-state",
        choices=("locked", "unlocked", "unknown"),
        help="caller lock state; not device evidence and does not satisfy SR-013",
    )
    wizard.add_argument(
        "--stored",
        action="append",
        default=[],
        metavar="LOCATION=VALUE",
        help="caller-supplied stored rollback index; requires --device-fingerprint",
    )
    wizard.add_argument(
        "--slot",
        choices=[policy.value for policy in SlotPolicy],
        default=SlotPolicy.CURRENT.value,
        help="slot policy",
    )
    wizard.add_argument("--rollback-slot", default=None, help="slot for rollback counters")
    wizard.add_argument("--wipe", action="store_true", help="include vendor if-wipe commands")
    wizard.add_argument(
        "--retrofit-force",
        action="store_true",
        help="request the unmodeled retrofit force case",
    )
    wizard.add_argument(
        "--tool",
        action="append",
        default=[],
        metavar="NAME=VERSION[@SHA256]",
        help="bind another tool identity; repeat as needed",
    )
    wizard.add_argument("--approval", type=Path, metavar="TOKEN", help="approval token to verify")
    wizard.add_argument(
        "--approval-key",
        type=Path,
        help="approval key file (requires --approval)",
    )
    wizard.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )

    approval = subparsers.add_parser(
        "approval",
        help="issue and verify signed approval bindings (no device writes)",
    )
    approval_sub = approval.add_subparsers(
        dest="approval_command",
        metavar="subcommand",
    )
    approval_keygen = approval_sub.add_parser(
        "keygen",
        help="generate a 32-byte approval consistency key",
    )
    approval_keygen.add_argument(
        "--out",
        type=Path,
        required=True,
        help="key file to create",
    )
    approval_keygen.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing key file",
    )
    approval_keygen.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )

    approval_inspect = approval_sub.add_parser(
        "inspect",
        help="verify and print a signed approval token",
    )
    approval_inspect.add_argument("token", type=Path, help="approval token JSON")
    approval_inspect.add_argument(
        "--key",
        type=Path,
        required=True,
        help="approval key file",
    )
    approval_inspect.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )

    approval_issue = approval_sub.add_parser(
        "issue",
        help="issue a token after the pre-approval safety report passes",
    )
    approval_issue.add_argument("package", type=Path, nargs="?", help="factory or OTA zip")
    approval_issue.add_argument(
        "--index",
        type=Path,
        help="local hash-index JSON",
    )
    approval_issue.add_argument(
        "--session",
        type=Path,
        help="issue from a READY wizard session instead of a package",
    )
    approval_issue.add_argument(
        "--key",
        type=Path,
        required=True,
        help="approval key file",
    )
    approval_issue.add_argument(
        "--operator",
        required=True,
        help="operator name recorded in the token",
    )
    approval_issue.add_argument(
        "--reason",
        required=True,
        help="typed reason, at least 10 characters",
    )
    approval_issue.add_argument(
        "--nonce",
        help="session nonce, 32-128 lowercase hex (without --session)",
    )
    issue_source = approval_issue.add_mutually_exclusive_group()
    issue_source.add_argument(
        "--device-fingerprint",
        help="caller-supplied 64-hex fingerprint; weaker than a probe",
    )
    issue_source.add_argument(
        "--fastboot",
        type=Path,
        help="probe the device with official fastboot",
    )
    approval_issue.add_argument("--serial", help="target device serial with --fastboot")
    approval_issue.add_argument(
        "--tool",
        action="append",
        default=[],
        metavar="NAME=VERSION[@SHA256]",
        help="bind another tool identity; repeat as needed",
    )
    _add_plan_options(approval_issue)
    approval_issue.add_argument(
        "--out",
        type=Path,
        help="write the token here; omit for stdout",
    )
    approval_issue.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )

    approval_verify = approval_sub.add_parser(
        "verify",
        help="verify a token against the current plan and evidence",
    )
    approval_verify.add_argument("token", type=Path, help="approval token JSON")
    approval_verify.add_argument("package", type=Path, nargs="?", help="factory or OTA zip")
    approval_verify.add_argument(
        "--index",
        type=Path,
        help="local hash-index JSON",
    )
    approval_verify.add_argument(
        "--session",
        type=Path,
        help="verify against a wizard session instead of a package",
    )
    approval_verify.add_argument(
        "--key",
        type=Path,
        required=True,
        help="approval key file",
    )
    approval_verify.add_argument(
        "--nonce",
        help="session nonce, 32-128 lowercase hex (without --session)",
    )
    verify_source = approval_verify.add_mutually_exclusive_group()
    verify_source.add_argument(
        "--device-fingerprint",
        help="caller-supplied 64-hex fingerprint; weaker than a probe",
    )
    verify_source.add_argument(
        "--fastboot",
        type=Path,
        help="probe the device with official fastboot",
    )
    approval_verify.add_argument("--serial", help="target device serial with --fastboot")
    approval_verify.add_argument(
        "--tool",
        action="append",
        default=[],
        metavar="NAME=VERSION[@SHA256]",
        help="bind another tool identity; repeat as needed",
    )
    _add_plan_options(approval_verify)
    approval_verify.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )

    avb = subparsers.add_parser(
        "avb",
        help="read-only AVB inspection, verification, and key checks",
    )
    avb_sub = avb.add_subparsers(dest="avb_command", metavar="subcommand")
    avb_info = avb_sub.add_parser(
        "info",
        help="print the VBMeta header and descriptors",
    )
    avb_info.add_argument("image", type=Path, help="VBMeta image")
    avb_info.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )
    avb_digest = avb_sub.add_parser(
        "digest",
        help="compute the AOSP VBMeta digest",
    )
    avb_digest.add_argument("image", type=Path, help="VBMeta image")
    avb_digest.add_argument(
        "--hash",
        choices=("sha256", "sha512"),
        default="sha256",
        help="digest hash algorithm (default sha256)",
    )
    avb_digest.add_argument(
        "--chain",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="chained partition image; repeat for multiple chains",
    )
    avb_verify = avb_sub.add_parser(
        "verify",
        help="verify the VBMeta RSA signature against its embedded key",
    )
    avb_verify.add_argument("image", type=Path, help="VBMeta image")
    avb_verify.add_argument(
        "--key",
        type=Path,
        metavar="AVBPUBKEY",
        help="expected raw AVB public key; without it the embedded key is only self-consistent",
    )
    avb_verify.add_argument(
        "--chain",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="chained partition image; repeat for multiple chains",
    )
    avb_verify.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )
    avb_key_check = avb_sub.add_parser(
        "key-check",
        help="compare the image key with a trusted key under a lock state",
    )
    avb_key_check.add_argument("image", type=Path, help="VBMeta image")
    avb_key_check.add_argument(
        "--key",
        type=Path,
        metavar="AVBPUBKEY",
        help="raw AVB public key trusted for this device",
    )
    avb_key_check.add_argument(
        "--lock-state",
        choices=("locked", "unlocked", "unknown"),
        required=True,
        help="caller-supplied bootloader lock state used to interpret the key match",
    )
    avb_key_check.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )

    rollback = subparsers.add_parser(
        "rollback",
        help="read or check rollback counters",
    )
    rollback_sub = rollback.add_subparsers(dest="rollback_command", metavar="subcommand")
    rollback_check = rollback_sub.add_parser(
        "check",
        help="compare a package's rollback indexes with stored values",
    )
    rollback_check.add_argument("image", type=Path, help="VBMeta image")
    rollback_check.add_argument(
        "--chain",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="chained partition image; repeat for multiple chains",
    )
    rollback_check.add_argument(
        "--stored",
        action="append",
        default=[],
        metavar="LOCATION=VALUE",
        help="caller-supplied stored rollback index; repeat per location",
    )
    rollback_check.add_argument(
        "--device",
        action="store_true",
        help="read stored indexes from the device with read-only fastboot getvar all",
    )
    rollback_check.add_argument(
        "--fastboot",
        type=Path,
        help="path to the official fastboot executable (with --device)",
    )
    rollback_check.add_argument(
        "--serial",
        help="target device serial for the read (with --device)",
    )
    rollback_check.add_argument(
        "--simulate",
        type=Path,
        metavar="TRANSCRIPT",
        help="replay a transcript for the device read instead of touching hardware",
    )
    rollback_check.add_argument(
        "--slot",
        default=None,
        help="slot the stored values belong to",
    )
    rollback_check.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable output",
    )

    rollback_read = rollback_sub.add_parser(
        "read",
        help="read vendor-reported stored rollback indexes (read-only)",
    )
    rollback_read.add_argument(
        "--fastboot",
        type=Path,
        help="path to the official fastboot executable (default: CAIRN_FASTBOOT or PATH)",
    )
    rollback_read.add_argument(
        "--serial",
        help="target device serial; omit to let fastboot choose",
    )
    rollback_read.add_argument(
        "--simulate",
        type=Path,
        metavar="TRANSCRIPT",
        help="replay a recorded transcript instead of touching hardware",
    )
    rollback_read.add_argument(
        "--slot",
        default=None,
        help="slot label for the reported values",
    )
    rollback_read.add_argument(
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
        return _run_doctor(args)

    if args.command == "probe":
        return _run_probe(args)

    if args.command == "inspect":
        return _run_inspect(args)

    if args.command == "provenance":
        return _run_provenance(args)

    if args.command == "plan":
        return _run_plan(args)

    if args.command == "wizard":
        return _run_wizard(args)

    if args.command == "approval":
        return _run_approval(args)

    if args.command == "avb":
        return _run_avb(args)

    if args.command == "rollback":
        return _run_rollback(args)

    parser.error(f"unknown command: {args.command}")


def _run_doctor(args: argparse.Namespace) -> int:
    if args.soak < 0:
        print("cairn doctor: --soak must not be negative", file=sys.stderr)
        return EXIT_USAGE

    runner = ToolRunner()
    simulated = args.simulate is not None
    fastboot_prefix: tuple[str, ...] | None
    fastboot_extra_env: dict[str, str] | None = None
    fastboot_label: str

    if simulated:
        fastboot_prefix = (sys.executable, "-m", "cairn.sim.fastboot_sim")
        fastboot_extra_env = {TRANSCRIPT_ENV: str(args.simulate)}
        fastboot_label = "simulated transcript"
    else:
        fastboot = _resolve_fastboot(args.fastboot)
        if fastboot is None:
            fastboot_prefix = None
            fastboot_label = "not found"
        else:
            fastboot_prefix = (str(fastboot),)
            fastboot_label = str(fastboot)

    adb = _resolve_tool("adb", args.adb, "CAIRN_ADB")
    report = HostDoctor(runner).run(
        fastboot_prefix=fastboot_prefix,
        fastboot_label=fastboot_label,
        adb_path=adb,
        serial=args.serial,
        soak_attempts=args.soak,
        simulated=simulated,
        fastboot_extra_env=fastboot_extra_env,
    )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_doctor(report)
    return report.exit_code


def _print_doctor(report: HostReport) -> None:
    suffix = " (simulated link)" if report.simulated else ""
    print(f"cairn doctor: read-only host checks{suffix}")
    for key in ("os", "release", "machine", "python", "fastboot"):
        if key in report.environment:
            print(f"{key}: {report.environment[key]}")
    for check in report.checks:
        print(f"{check.name}: {check.state.name} - {check.detail}")
    if report.soak is not None:
        print(
            f"soak: {report.soak.attempts} attempts, {report.soak.failures} failures, "
            f"slowest {report.soak.max_ms:.0f} ms"
        )
    verdict = report.verdict
    if verdict is Tri.TRUE:
        print("verdict: TRUE - required host checks passed")
    elif verdict is Tri.FALSE:
        print("verdict: FALSE - a required host check failed; do not flash on this host")
    else:
        print("verdict: UNKNOWN - required checks did not complete; treat as unsafe")
    print("read-only: no device writes were performed")


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
            "name": "fastboot",
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
            "name": "fastboot",
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
    try:
        fingerprint = device_fingerprint(result, now=datetime.now(UTC))
        fingerprint_detail = "fingerprint of fresh PROBED identity facts"
    except ApprovalError as exc:
        fingerprint = None
        fingerprint_detail = str(exc)

    payload = {
        "tool": tool,
        "serial": result.serial,
        "tool_ok": result.tool_ok,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "cancelled": result.cancelled,
        "detail": result.detail,
        "device_fingerprint": fingerprint,
        "device_fingerprint_detail": fingerprint_detail,
        "facts": [_fact_payload(fact) for fact in result.facts],
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        _print_probe(payload, result, simulated=simulated)

    return EXIT_OK if result.tool_ok else EXIT_FAILED


def _run_inspect(args: argparse.Namespace) -> int:
    try:
        manifest = load_package(
            args.package,
            hash_files=args.hash,
            hash_archive=args.hash,
        )
    except PackageError as exc:
        print(f"cairn inspect: {exc}", file=sys.stderr)
        return EXIT_FAILED

    if args.json:
        print(json.dumps(manifest.to_dict(), indent=2))
    else:
        _print_inspect(manifest)
    return EXIT_OK


def _print_inspect(manifest: PackageManifest) -> None:
    print(f"package: {manifest.path}")
    print(f"kind: {manifest.kind.value}")
    print(f"archive: {manifest.archive_size} bytes")
    if manifest.archive_sha256 is not None:
        print(f"archive sha256: {manifest.archive_sha256}")

    counts: dict[str, int] = {}
    for entry in manifest.entries:
        counts[entry.kind.value] = counts.get(entry.kind.value, 0) + 1
    summary = ", ".join(f"{kind}={count}" for kind, count in sorted(counts.items()))
    print(f"entries: {len(manifest.entries)}" + (f" ({summary})" if summary else ""))

    if manifest.fastboot_info is not None:
        print(
            f"fastboot-info: {len(manifest.fastboot_info.commands)} commands "
            f"(version {manifest.fastboot_info.version})"
        )
    if manifest.ota_metadata is not None:
        pre_device = manifest.ota_metadata.first("pre-device") or "unknown"
        print(
            f"ota metadata: {len(manifest.ota_metadata.entries)} entries; pre-device={pre_device}"
        )
    if manifest.payload_properties is not None:
        print(f"payload properties: {len(manifest.payload_properties)} keys")
    if manifest.unknown_entries:
        print("unknown entries:")
        for name in manifest.unknown_entries:
            print(f"  {name}")
    if manifest.warnings:
        print("warnings:")
        for warning in manifest.warnings:
            print(f"  {warning}")
    print("read-only: archive was not extracted; no device access")


def _run_provenance(args: argparse.Namespace) -> int:
    try:
        index = load_hash_index(args.index)
        manifest = load_package(
            args.package,
            hash_files=True,
            hash_archive=True,
        )
    except (HashIndexError, PackageError) as exc:
        print(f"cairn provenance: {exc}", file=sys.stderr)
        return EXIT_FAILED

    result = verify_manifest(index, manifest)
    payload = {
        "package": str(manifest.path),
        "archive_sha256": manifest.archive_sha256,
        "index": str(index.source),
        **result.to_dict(),
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        _print_provenance(payload, result)

    if result.state is Tri.TRUE:
        return EXIT_OK
    if result.state is Tri.FALSE:
        return EXIT_FAILED
    return EXIT_UNKNOWN


def _print_provenance(
    payload: Mapping[str, object],
    result: ProvenanceResult,
) -> None:
    print(f"package: {payload['package']}")
    print(f"archive sha256: {payload['archive_sha256']}")
    print(f"index: {payload['index']}")
    if result.package_id is not None:
        details = []
        if result.device:
            details.append(f"device={result.device}")
        if result.build:
            details.append(f"build={result.build}")
        suffix = f" ({', '.join(details)})" if details else ""
        print(f"package id: {result.package_id}{suffix}")
    if result.state is Tri.TRUE:
        print("verdict: TRUE - package matches the local hash index")
    elif result.state is Tri.FALSE:
        print("verdict: FALSE - package does not match the indexed package")
    else:
        print("verdict: UNKNOWN - package could not be matched to the local index")
    for reason in result.reasons:
        print(f"  {reason}")
    print("note: a local index match is not a signature or authenticity check")
    print("read-only: no device access")


def _run_plan(args: argparse.Namespace) -> int:
    approval_requested = args.approval is not None
    if approval_requested and (
        args.approval_key is None or args.nonce is None or args.device_fingerprint is None
    ):
        print(
            "cairn plan: --approval requires --approval-key, --nonce, and --device-fingerprint",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if not approval_requested and (
        args.approval_key is not None
        or args.nonce is not None
        or args.device_fingerprint is not None
        or args.tool
    ):
        print(
            "cairn plan: --approval-key, --nonce, --device-fingerprint, and --tool "
            "require --approval",
            file=sys.stderr,
        )
        return EXIT_USAGE

    tools = _parse_tool_bindings(args.tool, "cairn plan")
    if tools is None:
        return EXIT_USAGE

    try:
        index = load_hash_index(args.index)
        manifest = load_package(
            args.package,
            hash_files=True,
            hash_archive=True,
        )
        provenance = verify_manifest(index, manifest)
        plan = build_plan(
            manifest,
            provenance,
            options=PlanOptions(
                wipe=args.wipe,
                slot_policy=SlotPolicy(args.slot),
                retrofit_force=args.retrofit_force,
            ),
        )
        pre_safety = SafetyEngine.pre_approval().evaluate(SafetyContext(provenance=provenance))
        approval_check = None
        if approval_requested:
            device = _caller_binding(
                args.nonce,
                args.device_fingerprint,
                "cairn plan",
            )
            if device is None:
                return EXIT_USAGE
            current = ApprovalInputs.from_manifest(
                manifest,
                plan,
                pre_safety,
                device,
                tools=tools,
            )
            token_text = _read_token_text(args.approval)
            key = load_approval_key(args.approval_key)
            approval_check = verify_approval(
                token_text,
                key,
                current,
            ).to_check_state()
        safety = SafetyEngine().evaluate(
            SafetyContext(provenance=provenance, approval=approval_check)
        )
        if safety.evidence_snapshot_sha256 != pre_safety.evidence_snapshot_sha256:
            raise PlanError("internal approval snapshot scope is inconsistent")
        assessment = assess_plan(plan, safety)
    except (HashIndexError, PackageError, PlanError, ApprovalError) as exc:
        print(f"cairn plan: {exc}", file=sys.stderr)
        return EXIT_FAILED

    if args.json:
        print(json.dumps(assessment.to_dict(), indent=2))
    else:
        _print_plan(assessment)
    return EXIT_OK if assessment.executable else EXIT_UNKNOWN


def _run_wizard(args: argparse.Namespace) -> int:
    if args.soak < 0:
        print("cairn wizard: --soak must not be negative", file=sys.stderr)
        return EXIT_USAGE
    if args.stored and args.device_fingerprint is None:
        print(
            "cairn wizard: --stored requires --device-fingerprint; "
            "caller stored indexes are not device evidence",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if args.approval is not None and args.approval_key is None:
        print("cairn wizard: --approval requires --approval-key", file=sys.stderr)
        return EXIT_USAGE
    if args.approval is None and args.approval_key is not None:
        print("cairn wizard: --approval-key requires --approval", file=sys.stderr)
        return EXIT_USAGE
    if args.vbmeta is None and (args.chain or args.key is not None):
        print("cairn wizard: --chain and --key require --vbmeta", file=sys.stderr)
        return EXIT_USAGE

    chain = _parse_chain(args.chain, "cairn wizard")
    if chain is None:
        return EXIT_USAGE
    stored = _parse_stored_indexes(args.stored, "cairn wizard")
    if stored is None:
        return EXIT_USAGE
    tools = _parse_tool_bindings(args.tool, "cairn wizard")
    if tools is None:
        return EXIT_USAGE

    options = WizardOptions(
        package=args.package,
        index=args.index,
        state=args.state,
        fastboot=args.fastboot,
        serial=args.serial,
        simulate=args.simulate,
        device_fingerprint=args.device_fingerprint,
        soak=args.soak,
        vbmeta=args.vbmeta,
        chain=chain,
        key=args.key,
        lock_state=args.lock_state,
        stored=stored,
        slot_policy=SlotPolicy(args.slot),
        rollback_slot=args.rollback_slot,
        wipe=args.wipe,
        retrofit_force=args.retrofit_force,
        tools=tools,
        approval=args.approval,
        approval_key=args.approval_key,
        resume=args.resume,
        force=args.force,
    )
    try:
        session = run_wizard(options)
    except (WizardError, OSError) as exc:
        print(f"cairn wizard: {exc}", file=sys.stderr)
        return EXIT_FAILED

    if args.json:
        print(json.dumps(session.to_dict(), indent=2))
    else:
        print(render_session(session))
    return session_exit_code(session)


def _parse_chain(specs: list[str], command: str) -> dict[str, Path] | None:
    chain: dict[str, Path] = {}
    for spec in specs:
        name, separator, path_text = spec.partition("=")
        if not separator or not name or not path_text:
            print(
                f"{command}: malformed --chain {spec!r}; use NAME=PATH",
                file=sys.stderr,
            )
            return None
        if name in chain:
            print(f"{command}: duplicate chain partition {name!r}", file=sys.stderr)
            return None
        chain[name] = Path(path_text)
    return chain


def _run_approval(args: argparse.Namespace) -> int:
    if args.approval_command == "keygen":
        return _run_approval_keygen(args)
    if args.approval_command == "inspect":
        return _run_approval_inspect(args)
    if args.approval_command == "issue":
        return _run_approval_issue(args)
    if args.approval_command == "verify":
        return _run_approval_verify(args)
    print(
        "cairn approval: choose 'keygen', 'inspect', 'issue', or 'verify'",
        file=sys.stderr,
    )
    return EXIT_USAGE


def _run_approval_keygen(args: argparse.Namespace) -> int:
    key = generate_approval_key()
    try:
        write_approval_key(args.out, key, overwrite=args.force)
    except ApprovalError as exc:
        print(f"cairn approval keygen: {exc}", file=sys.stderr)
        return EXIT_FAILED

    identifier = key_id(key)
    payload = {"key": str(args.out), "key_id": identifier, "bytes": len(key)}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"approval key: {args.out}")
        print(f"key id: {identifier}")
        print("note: this is a per-session consistency key, not a security boundary")
    return EXIT_OK


def _run_approval_inspect(args: argparse.Namespace) -> int:
    try:
        key = load_approval_key(args.key)
        token_text = _read_token_text(args.token)
        token = parse_approval_token(token_text, key)
    except ApprovalError as exc:
        print(f"cairn approval inspect: {exc}", file=sys.stderr)
        return EXIT_FAILED

    token_sha256 = _text_sha256(token_text)
    if args.json:
        print(json.dumps(token.to_dict() | {"token_sha256": token_sha256}, indent=2))
    else:
        _print_approval_token(token, token_sha256)
    return EXIT_OK


def _run_approval_issue(args: argparse.Namespace) -> int:
    if args.session is not None:
        if _session_approval_conflicts(args, "cairn approval issue"):
            return EXIT_USAGE
        try:
            key = load_approval_key(args.key)
            inputs = _session_approval_inputs(
                args.session,
                "cairn approval issue",
                require_ready=True,
            )
            token = issue_approval(
                inputs,
                key,
                operator=args.operator,
                reason=args.reason,
            )
        except (ApprovalError, WizardError) as exc:
            print(f"cairn approval issue: {exc}", file=sys.stderr)
            return EXIT_FAILED
        return _finish_approval_issue(args, token)

    if args.package is None or args.index is None or args.nonce is None:
        print(
            "cairn approval issue: package, --index, and --nonce are required without --session",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if args.device_fingerprint is None and args.fastboot is None:
        print(
            "cairn approval issue: choose --device-fingerprint or --fastboot",
            file=sys.stderr,
        )
        return EXIT_USAGE

    tools = _parse_tool_bindings(args.tool, "cairn approval issue")
    if tools is None:
        return EXIT_USAGE
    try:
        key = load_approval_key(args.key)
        index = load_hash_index(args.index)
        manifest = load_package(
            args.package,
            hash_files=True,
            hash_archive=True,
        )
        provenance = verify_manifest(index, manifest)
        plan = build_plan(
            manifest,
            provenance,
            options=PlanOptions(
                wipe=args.wipe,
                slot_policy=SlotPolicy(args.slot),
                retrofit_force=args.retrofit_force,
            ),
        )
        pre_safety = SafetyEngine.pre_approval().evaluate(SafetyContext(provenance=provenance))
    except (ApprovalError, HashIndexError, PackageError, PlanError) as exc:
        print(f"cairn approval issue: {exc}", file=sys.stderr)
        return EXIT_FAILED

    if not plan.executable:
        print(
            "cairn approval issue: plan is not structurally executable; refusing to approve it",
            file=sys.stderr,
        )
        return EXIT_FAILED
    if not pre_safety.can_proceed:
        print(
            "cairn approval issue: pre-approval safety report blocks: "
            + ", ".join(pre_safety.blocking),
            file=sys.stderr,
        )
        return EXIT_UNKNOWN

    device, tool_binding, code = _approval_device(
        args,
        "cairn approval issue",
        require_acceptable_tool=True,
    )
    if device is None:
        return code
    merged = _merge_tool_bindings(tools, tool_binding, "cairn approval issue")
    if merged is None:
        return EXIT_USAGE

    try:
        inputs = ApprovalInputs.from_manifest(
            manifest,
            plan,
            pre_safety,
            device,
            tools=merged,
        )
        token = issue_approval(
            inputs,
            key,
            operator=args.operator,
            reason=args.reason,
        )
    except ApprovalError as exc:
        print(f"cairn approval issue: {exc}", file=sys.stderr)
        return EXIT_FAILED

    return _finish_approval_issue(args, token)


def _run_approval_verify(args: argparse.Namespace) -> int:
    if args.session is not None:
        if _session_approval_conflicts(args, "cairn approval verify"):
            return EXIT_USAGE
        try:
            key = load_approval_key(args.key)
            token_text = _read_token_text(args.token)
            current = _session_approval_inputs(
                args.session,
                "cairn approval verify",
                require_ready=False,
            )
        except (ApprovalError, WizardError) as exc:
            print(f"cairn approval verify: {exc}", file=sys.stderr)
            return EXIT_FAILED
        verdict = verify_approval(token_text, key, current)
        payload = verdict.to_dict() | {
            "plan_sha256": current.plan_sha256,
            "evidence_snapshot_sha256": current.evidence_snapshot_sha256,
            "archive_sha256": current.archive_sha256,
            "device_source": current.device.source.value,
            "tools": [tool.to_dict() for tool in current.tools],
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            _print_approval_verdict(verdict, current)
        return _exit_code_for_tri(verdict.state)

    if args.package is None or args.index is None or args.nonce is None:
        print(
            "cairn approval verify: package, --index, and --nonce are required without --session",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if args.device_fingerprint is None and args.fastboot is None:
        print(
            "cairn approval verify: choose --device-fingerprint or --fastboot",
            file=sys.stderr,
        )
        return EXIT_USAGE
    tools = _parse_tool_bindings(args.tool, "cairn approval verify")
    if tools is None:
        return EXIT_USAGE
    try:
        key = load_approval_key(args.key)
        token_text = _read_token_text(args.token)
        index = load_hash_index(args.index)
        manifest = load_package(
            args.package,
            hash_files=True,
            hash_archive=True,
        )
        provenance = verify_manifest(index, manifest)
        plan = build_plan(
            manifest,
            provenance,
            options=PlanOptions(
                wipe=args.wipe,
                slot_policy=SlotPolicy(args.slot),
                retrofit_force=args.retrofit_force,
            ),
        )
        pre_safety = SafetyEngine.pre_approval().evaluate(SafetyContext(provenance=provenance))
    except (ApprovalError, HashIndexError, PackageError, PlanError) as exc:
        print(f"cairn approval verify: {exc}", file=sys.stderr)
        return EXIT_FAILED

    device, tool_binding, code = _approval_device(
        args,
        "cairn approval verify",
        require_acceptable_tool=False,
    )
    if device is None:
        return code
    merged = _merge_tool_bindings(tools, tool_binding, "cairn approval verify")
    if merged is None:
        return EXIT_USAGE

    try:
        current = ApprovalInputs.from_manifest(
            manifest,
            plan,
            pre_safety,
            device,
            tools=merged,
        )
    except ApprovalError as exc:
        print(f"cairn approval verify: {exc}", file=sys.stderr)
        return EXIT_FAILED

    verdict = verify_approval(token_text, key, current)
    payload = verdict.to_dict() | {
        "plan_sha256": plan.plan_sha256,
        "evidence_snapshot_sha256": pre_safety.evidence_snapshot_sha256,
        "archive_sha256": manifest.archive_sha256,
        "device_source": device.source.value,
        "tools": [tool.to_dict() for tool in merged],
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        _print_approval_verdict(verdict, current)
    return _exit_code_for_tri(verdict.state)


def _session_approval_conflicts(args: argparse.Namespace, command: str) -> bool:
    """Reject inputs that could silently replace a recorded session binding."""
    conflicting = (
        ("package", args.package),
        ("--index", args.index),
        ("--nonce", args.nonce),
        ("--device-fingerprint", args.device_fingerprint),
        ("--fastboot", args.fastboot),
        ("--serial", args.serial),
    )
    supplied = [name for name, value in conflicting if value is not None]
    if args.tool:
        supplied.append("--tool")
    if args.wipe:
        supplied.append("--wipe")
    if args.slot != SlotPolicy.CURRENT.value:
        supplied.append("--slot")
    if args.retrofit_force:
        supplied.append("--retrofit-force")
    if supplied:
        print(
            f"{command}: --session cannot be combined with " + ", ".join(supplied),
            file=sys.stderr,
        )
        return True
    return False


def _session_approval_inputs(
    path: Path,
    command: str,
    *,
    require_ready: bool,
) -> ApprovalInputs:
    """Reload session artifacts and reconstruct the immutable approval binding."""
    session = load_session(path)
    allowed = (
        (SessionOutcome.READY,) if require_ready else (SessionOutcome.READY, SessionOutcome.CLEARED)
    )
    if session.outcome not in allowed:
        expected = "READY" if require_ready else "READY or CLEARED"
        raise WizardError(f"{command} requires a {expected} wizard session")
    if session.bundle is None or session.device is None or session.pre_safety is None:
        raise WizardError("wizard session is missing its approval binding inputs")
    if session.pre_safety.get("can_proceed") is not True:
        raise WizardError("wizard session pre-approval safety gate does not permit approval")
    snapshot = session.pre_safety.get("evidence_snapshot_sha256")
    if snapshot != session.bundle.evidence_snapshot_sha256:
        raise WizardError("wizard session safety snapshot does not match its approval bundle")
    binding = session.device.binding()
    if binding is None:
        raise WizardError("wizard session device binding is unavailable")
    if binding.source.value != "probed" or not session.device.is_fresh(datetime.now(UTC)):
        raise WizardError(
            "wizard session device probe is stale or not device evidence; rerun wizard"
        )

    reloaded = reload_session_plan(session)
    if reloaded.plan.plan_sha256 != session.bundle.plan_sha256:
        raise WizardError("reloaded wizard plan does not match its approval bundle")
    return ApprovalInputs(
        plan_sha256=session.bundle.plan_sha256,
        evidence_snapshot_sha256=session.bundle.evidence_snapshot_sha256,
        archive_sha256=session.bundle.archive_sha256,
        package_hashes=session.bundle.package_hashes,
        device=binding,
        tools=session.bundle.tools,
    )


def _finish_approval_issue(args: argparse.Namespace, token: ApprovalToken) -> int:
    token_text = token.to_json()
    if args.out is None or str(args.out) == "-":
        print(token_text, end="")
        return EXIT_OK
    try:
        args.out.write_text(token_text, encoding="utf-8", newline="\n")
    except OSError as exc:
        print(
            f"cairn approval issue: cannot write token {args.out}: {exc}",
            file=sys.stderr,
        )
        return EXIT_FAILED

    payload = {
        "token": str(args.out),
        "token_sha256": _text_sha256(token_text),
        "key_id": token.key_id,
        "binding_sha256": token.binding_sha256,
        "plan_sha256": token.inputs.plan_sha256,
        "evidence_snapshot_sha256": token.inputs.evidence_snapshot_sha256,
        "device_source": token.inputs.device.source.value,
        "tools": [tool.to_dict() for tool in token.inputs.tools],
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"approval token: {args.out}")
        print(f"token sha256: {payload['token_sha256']}")
        print(f"key id: {token.key_id}")
        print(f"binding sha256: {token.binding_sha256}")
        print(f"device source: {token.inputs.device.source.value}")
        print("note: the token is a consistency boundary, not an authorization boundary")
    return EXIT_OK


def _approval_device(
    args: argparse.Namespace,
    command: str,
    *,
    require_acceptable_tool: bool,
) -> tuple[DeviceBinding | None, ToolBinding | None, int]:
    if args.device_fingerprint is not None:
        binding = _caller_binding(args.nonce, args.device_fingerprint, command)
        if binding is None:
            return None, None, EXIT_USAGE
        return binding, None, EXIT_OK

    setup = _prepare_fastboot(args, command=command)
    if setup is None:
        return None, None, EXIT_USAGE
    client, tool, simulated = setup
    if simulated:
        print(f"{command}: simulated probes are not device evidence", file=sys.stderr)
        return None, None, EXIT_UNKNOWN
    if require_acceptable_tool and tool.get("manifest_ok") is not True:
        print(
            f"{command}: fastboot tool is not acceptable: {tool.get('manifest_detail')}",
            file=sys.stderr,
        )
        return None, None, EXIT_FAILED

    result = client.probe(
        serial=args.serial,
        expected_serial=args.serial,
        source=EvidenceSource.PROBED,
    )
    try:
        device = build_device_binding(result, args.nonce)
    except ApprovalError as exc:
        print(f"{command}: {exc}", file=sys.stderr)
        return None, None, EXIT_UNKNOWN
    fastboot_binding = _tool_binding_from_payload(tool)
    if fastboot_binding is None:
        print(f"{command}: fastboot tool identity is unavailable", file=sys.stderr)
        return None, None, EXIT_UNKNOWN
    return device, fastboot_binding, EXIT_OK


def _caller_binding(
    nonce: str,
    fingerprint: str,
    command: str,
) -> DeviceBinding | None:
    try:
        return caller_device_binding(nonce, fingerprint)
    except ApprovalError as exc:
        print(f"{command}: {exc}", file=sys.stderr)
        return None


def _tool_binding_from_payload(
    tool: Mapping[str, object],
) -> ToolBinding | None:
    if tool.get("kind") != "fastboot":
        return None
    name = tool.get("name")
    version = tool.get("version")
    sha256 = tool.get("sha256")
    if not isinstance(name, str) or not isinstance(sha256, str):
        return None
    if version is not None and not isinstance(version, str):
        return None
    try:
        return ToolBinding(name=name, version=version, sha256=sha256)
    except ApprovalError:
        return None


def _merge_tool_bindings(
    tools: tuple[ToolBinding, ...],
    probed: ToolBinding | None,
    command: str,
) -> tuple[ToolBinding, ...] | None:
    if probed is None:
        return tools
    if any(tool.name == probed.name for tool in tools):
        print(
            f"{command}: --tool {probed.name!r} duplicates the probed fastboot binding",
            file=sys.stderr,
        )
        return None
    return tuple(sorted((*tools, probed), key=lambda tool: tool.name))


def _parse_tool_bindings(
    specs: list[str],
    command: str,
) -> tuple[ToolBinding, ...] | None:
    bindings: dict[str, ToolBinding] = {}
    for spec in specs:
        name, separator, rest = spec.partition("=")
        if not separator or not name or not rest:
            print(
                f"{command}: malformed --tool {spec!r}; use NAME=VERSION[@SHA256]",
                file=sys.stderr,
            )
            return None
        version, at, sha = rest.partition("@")
        version = version.strip()
        if not version:
            print(f"{command}: --tool {spec!r} needs a version", file=sys.stderr)
            return None
        digest = sha.strip() if at else None
        if digest == "":
            print(f"{command}: --tool {spec!r} has an empty sha256", file=sys.stderr)
            return None
        try:
            binding = ToolBinding(name=name.strip(), version=version, sha256=digest)
        except ApprovalError as exc:
            print(f"{command}: {exc}", file=sys.stderr)
            return None
        if binding.name in bindings:
            print(f"{command}: duplicate --tool {binding.name!r}", file=sys.stderr)
            return None
        bindings[binding.name] = binding
    return tuple(bindings[name] for name in sorted(bindings))


def _read_token_text(path: Path) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ApprovalError(f"cannot stat approval token {path}: {exc}") from exc
    if size > MAX_TOKEN_BYTES:
        raise ApprovalError(f"approval token at {path} is above the {MAX_TOKEN_BYTES}-byte limit")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ApprovalError(f"cannot read approval token {path}: {exc}") from exc


def _text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _print_approval_token(token: ApprovalToken, token_sha256: str) -> None:
    print(f"approval token sha256: {token_sha256}")
    print(f"key id: {token.key_id}")
    print(f"issued at: {token.issued_at.isoformat()}")
    print(f"operator: {token.operator}")
    print(f"reason: {token.reason}")
    print(f"binding sha256: {token.binding_sha256}")
    print(f"plan sha256: {token.inputs.plan_sha256}")
    print(f"evidence snapshot: {token.inputs.evidence_snapshot_sha256}")
    print(f"archive sha256: {token.inputs.archive_sha256}")
    print(f"package entries: {len(token.inputs.package_hashes)}")
    for name, digest in token.inputs.package_hashes:
        print(f"  {name}: {digest}")
    print(f"device nonce: {token.inputs.device.nonce}")
    print(f"device fingerprint: {token.inputs.device.fingerprint_sha256}")
    print(f"device source: {token.inputs.device.source.value}")
    if token.inputs.tools:
        print("tools:")
        for tool in token.inputs.tools:
            print(
                f"  {tool.name}: version={tool.version or 'unknown'} "
                f"sha256={tool.sha256 or 'unknown'}"
            )
    else:
        print("tools: none")
    print("signature: valid (HMAC-SHA256)")
    print("note: this token is a consistency boundary, not an authorization boundary")


def _print_approval_verdict(
    verdict: ApprovalVerdict,
    current: ApprovalInputs,
) -> None:
    print(f"approval verdict: {verdict.state.name}")
    for reason in verdict.reasons:
        print(f"  {reason}")
    for warning in verdict.warnings:
        print(f"  warning: {warning}")
    if verdict.mismatches:
        print("mismatches: " + ", ".join(verdict.mismatches))
    if verdict.token_sha256 is not None:
        print(f"token sha256: {verdict.token_sha256}")
    if verdict.binding_sha256 is not None:
        print(f"approval binding sha256: {verdict.binding_sha256}")
    print(f"current binding sha256: {current.binding_sha256}")
    print("note: a matching approval is not authorization; other safety rules still apply")
    print("read-only: no device writes")


def _print_plan(assessment: PlanAssessment) -> None:
    plan = assessment.plan
    safety = assessment.safety
    print(f"plan: {plan.plan_sha256}")
    print(f"package sha256: {plan.package_sha256}")
    print(f"provenance: {plan.provenance.state.name}")
    for reason in plan.provenance.reasons:
        print(f"  provenance: {reason}")
    print(
        "options: "
        f"wipe={'yes' if plan.options.wipe else 'no'}, "
        f"slot={plan.options.slot_policy.value}, "
        f"retrofit_force={'yes' if plan.options.retrofit_force else 'no'}"
    )
    print(f"structurally executable: {'TRUE' if plan.executable else 'FALSE'}")
    print(f"safety verdict: {safety.verdict.name}")
    print(f"safety can proceed: {'TRUE' if safety.can_proceed else 'FALSE'}")
    print(f"safety evidence snapshot: {safety.evidence_snapshot_sha256}")
    if safety.blocking:
        print("safety blocking:")
        for rule_id in safety.blocking:
            print(f"  - {rule_id}")
    print("safety rules:")
    for rule in safety.rules:
        print(f"  {rule.rule_id}: {rule.state.name} - {rule.reason}")
        for warning in rule.warnings:
            print(f"     warning: {warning}")
    print(f"executable: {'TRUE' if assessment.executable else 'FALSE'}")
    print(f"steps: {len(plan.steps)}")
    for step in plan.steps:
        print(f"  {step.number}. {_step_summary(step)} (line {step.source_line})")
        for annotation in step.annotations:
            print(f"     - {annotation}")
    if plan.deviations:
        print("deviations:")
        for deviation in plan.deviations:
            print(f"  - {deviation}")
    if plan.warnings:
        print("warnings:")
        for warning in plan.warnings:
            print(f"  - {warning}")
    print(f"fallback: {plan.fallback.action} - {plan.fallback.detail}")
    print("read-only dry run; no device writes")


def _step_summary(step: PlanStep) -> str:
    if step.action.value == "flash":
        return f"flash {step.partition} {step.image}"
    if step.action.value == "erase":
        return f"erase {step.partition}"
    if step.action.value == "reboot":
        return f"reboot {step.target}"
    return "update-super"


def _run_avb(args: argparse.Namespace) -> int:
    if args.avb_command == "info":
        return _run_avb_info(args)
    if args.avb_command == "digest":
        return _run_avb_digest(args)
    if args.avb_command == "verify":
        return _run_avb_verify(args)
    if args.avb_command == "key-check":
        return _run_avb_key_check(args)
    print(
        "cairn avb: choose 'info', 'digest', 'verify', or 'key-check'",
        file=sys.stderr,
    )
    return EXIT_USAGE


def _run_avb_info(args: argparse.Namespace) -> int:
    try:
        image = load_vbmeta(args.image)
    except AvbError as exc:
        print(f"cairn avb info: {exc}", file=sys.stderr)
        return EXIT_FAILED

    if args.json:
        print(json.dumps(image.to_dict(), indent=2))
    else:
        _print_vbmeta(image)
    return EXIT_OK


def _run_avb_digest(args: argparse.Namespace) -> int:
    paths = _parse_chain_paths(args.chain, "cairn avb digest")
    if paths is None:
        return EXIT_USAGE
    try:
        chain = _load_chain_images(paths)
        image = load_vbmeta(args.image)
        digest = calculate_vbmeta_digest(image, hash_name=args.hash, chain=chain)
    except AvbError as exc:
        print(f"cairn avb digest: {exc}", file=sys.stderr)
        return EXIT_FAILED

    print(digest)
    return EXIT_OK


def _run_avb_verify(args: argparse.Namespace) -> int:
    paths = _parse_chain_paths(args.chain, "cairn avb verify")
    if paths is None:
        return EXIT_USAGE
    try:
        image = load_vbmeta(args.image)
        expected_key = None if args.key is None else _read_avb_key(args.key)
        if paths:
            chain = _load_chain_images(paths)
            report = verify_vbmeta_chain(image, chain, expected_key=expected_key)
        else:
            report = None
            result = verify_vbmeta_signature(image, expected_key=expected_key)
    except AvbError as exc:
        print(f"cairn avb verify: {exc}", file=sys.stderr)
        return EXIT_FAILED

    if report is not None:
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            _print_chain_report(report)
        return _exit_code_for_state(report.valid)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_signature(result)
    return _exit_code_for_state(result.valid)


def _run_avb_key_check(args: argparse.Namespace) -> int:
    try:
        image = load_vbmeta(args.image)
        trusted_key = None if args.key is None else _read_avb_key(args.key)
        signature = verify_vbmeta_signature(image)
        result = evaluate_lock_key(
            signature,
            lock_state=LockState(args.lock_state),
            trusted_key=trusted_key,
        )
    except AvbError as exc:
        print(f"cairn avb key-check: {exc}", file=sys.stderr)
        return EXIT_FAILED

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_lock_key_check(result)
    return _exit_code_for_tri(result.state)


def _parse_chain_paths(specs: list[str], command: str) -> dict[str, Path] | None:
    paths: dict[str, Path] = {}
    for spec in specs:
        name, separator, path_text = spec.partition("=")
        if not separator or not name or not path_text:
            print(
                f"{command}: malformed --chain {spec!r}; use NAME=PATH",
                file=sys.stderr,
            )
            return None
        if name in paths:
            print(f"{command}: duplicate chain {name!r}", file=sys.stderr)
            return None
        paths[name] = Path(path_text)
    return paths


def _load_chain_images(paths: dict[str, Path]) -> dict[str, VbmetaImage]:
    return {name: load_vbmeta(path) for name, path in paths.items()}


def _exit_code_for_state(state: bool | None) -> int:
    if state is True:
        return EXIT_OK
    if state is False:
        return EXIT_FAILED
    return EXIT_UNKNOWN


def _read_avb_key(path: Path) -> bytes:
    if not path.is_file():
        raise AvbError(f"AVB public key not found at {path}")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise AvbError(f"cannot read AVB public key {path}: {exc}") from exc
    if not data:
        raise AvbError(f"AVB public key at {path} is empty")
    if len(data) > 8192:
        raise AvbError(f"AVB public key at {path} is above the 8192-byte limit")
    return data


def _print_signature(result: AvbSignature, *, chain_checked: bool = False) -> None:
    print(f"algorithm: {result.algorithm.name}")
    if not result.signed:
        print("signature: unsigned; not verified")
    elif result.valid:
        print(f"signature: valid ({result.reason})")
    else:
        print(f"signature: INVALID ({result.reason})")
    if result.signed:
        print(f"key sha256: {result.key_sha256}")
        if result.expected_key_sha256 is not None:
            print(f"expected key sha256: {result.expected_key_sha256}")
        print(f"stored digest: {result.stored_digest.hex()}")
        print(f"computed digest: {result.computed_digest.hex()}")
    if chain_checked:
        print("note: chain-of-trust checked; rollback is not checked")
    else:
        print("note: chain-of-trust and rollback are not checked")
    print("read-only: no device access")


def _print_lock_key_check(result: LockKeyCheck) -> None:
    print(f"key trust: {_tri_label(result.state)}")
    print(f"lock state: {result.lock_state.value}")
    if result.key_matches is None:
        print("key match: unknown")
    elif result.key_matches:
        print("key match: yes")
    else:
        print("key match: no")
    if result.image_key_sha256 is not None:
        print(f"image key sha256: {result.image_key_sha256}")
    if result.trusted_key_sha256 is not None:
        print(f"trusted key sha256: {result.trusted_key_sha256}")
    print(f"reason: {result.reason}")
    for warning in result.warnings:
        print(f"warning: {warning}")
    print(
        "note: the lock state and trusted key are caller-supplied; this does not "
        "read device evidence or the device's root of trust"
    )
    print("read-only: no device access")


def _print_chain_report(report: AvbChainReport) -> None:
    _print_signature(report.signature, chain_checked=bool(report.chains))
    if report.chains:
        print(f"chains: {len(report.chains)}")
        for chain in report.chains:
            state = _state_label(chain.valid)
            print(
                f"  {chain.partition_name}: {state} "
                f"(depth={chain.depth}, location={chain.rollback_index_location}; "
                f"{chain.reason})"
            )
    print(f"overall: {_state_label(report.valid)} ({report.reason})")


def _state_label(state: bool | None) -> str:
    if state is True:
        return "valid"
    if state is False:
        return "INVALID"
    return "UNKNOWN"


def _print_vbmeta(image: VbmetaImage) -> None:
    header = image.header
    source = image.source if image.source is not None else "(memory)"
    print(f"image: {source}")
    trailing = f" (+{image.trailing_bytes} trailing bytes)" if image.trailing_bytes else ""
    print(f"vbmeta size: {len(image.blob)} bytes{trailing}")
    if image.image_size is not None:
        print(f"image size: {image.image_size} bytes")
    if image.footer is not None:
        print(
            f"footer: version={image.footer.version_major}."
            f"{image.footer.version_minor}, "
            f"original_image_size={image.footer.original_image_size}, "
            f"vbmeta_offset={image.footer.vbmeta_offset}, "
            f"vbmeta_size={image.footer.vbmeta_size}"
        )
    print(f"algorithm: {header.algorithm.name}")
    print(f"version: {header.required_libavb_version_major}.{header.required_libavb_version_minor}")
    print(f"rollback index: {header.rollback_index}")
    print(f"rollback index location: {header.rollback_index_location}")
    print(f"flags: {header.flags}")
    print(f"release: {header.release_string}")
    print(f"descriptors: {len(image.descriptors)}")
    for descriptor in image.descriptors:
        if isinstance(descriptor, AvbProperty):
            print(f"  property {descriptor.key} = {descriptor.value!r}")
        elif isinstance(descriptor, AvbHashDescriptor):
            print(
                f"  hash {descriptor.partition_name}: {descriptor.image_size} bytes, "
                f"{descriptor.hash_algorithm}, digest={descriptor.digest.hex()}"
            )
        elif isinstance(descriptor, AvbHashtreeDescriptor):
            print(
                f"  hashtree {descriptor.partition_name}: "
                f"{descriptor.image_size} bytes, {descriptor.hash_algorithm}, "
                f"root={descriptor.root_digest.hex()}"
            )
        elif isinstance(descriptor, AvbKernelCmdline):
            print(f"  kernel_cmdline: {descriptor.cmdline!r} (flags={descriptor.flags})")
        elif isinstance(descriptor, AvbChainPartition):
            key_sha256 = descriptor.to_dict()["public_key_sha256"]
            print(
                f"  chain {descriptor.partition_name}: "
                f"location={descriptor.rollback_index_location}, key_sha256={key_sha256}"
            )
        elif isinstance(descriptor, AvbUnknownDescriptor):
            print(f"  unknown tag {descriptor.tag}: {len(descriptor.payload)} bytes")
    if image.unknown_descriptors:
        print("warning: unknown descriptors are reported but not interpreted")
    print("note: parsing only; signatures and chain-of-trust are not verified")
    print("read-only: no device access")


def _run_rollback(args: argparse.Namespace) -> int:
    if args.rollback_command == "read":
        return _run_rollback_read(args)
    if args.rollback_command != "check":
        print("cairn rollback: choose 'check' or 'read'", file=sys.stderr)
        return EXIT_USAGE

    if args.device and args.stored:
        print("cairn rollback check: choose either --device or --stored", file=sys.stderr)
        return EXIT_USAGE
    if not args.device and (
        args.fastboot is not None or args.serial is not None or args.simulate is not None
    ):
        print(
            "cairn rollback check: --fastboot, --serial, and --simulate require --device",
            file=sys.stderr,
        )
        return EXIT_USAGE

    chain_paths = _parse_chain_paths(args.chain, "cairn rollback check")
    if chain_paths is None:
        return EXIT_USAGE

    stored: dict[int, int] | None = None
    if not args.device:
        stored = _parse_stored_indexes(args.stored, "cairn rollback check")
        if stored is None:
            return EXIT_USAGE

    device_read: DeviceRollbackRead | None = None
    tool: dict[str, object] | None = None
    simulated = False

    try:
        image = load_vbmeta(args.image)
        chain = _load_chain_images(chain_paths)
        if args.device:
            setup = _prepare_fastboot(args, command="cairn rollback check")
            if setup is None:
                return EXIT_USAGE
            client, tool, simulated = setup
            device_read = read_stored_rollback_indexes(
                client,
                serial=args.serial,
                slot=args.slot,
            )
            stored = device_read.stored
        stored_source = (
            "fastboot getvar all" if args.device else ("device" if stored else "unknown")
        )
        report = evaluate_avb_rollback(
            image,
            chain,
            slot=args.slot,
            stored=stored,
            stored_source=stored_source,
        )
        if device_read is not None:
            extra = device_read.warnings + device_read.unresolved
            if extra:
                report = replace(report, warnings=report.warnings + extra)
    except (AvbError, RollbackError) as exc:
        print(f"cairn rollback check: {exc}", file=sys.stderr)
        return EXIT_UNKNOWN

    if args.json:
        payload = report.to_dict()
        if device_read is not None:
            payload["device_read"] = device_read.to_dict()
            payload["tool"] = tool
            payload["simulated"] = simulated
        print(json.dumps(payload, indent=2))
    else:
        _print_rollback_report(
            report,
            chain_supplied=bool(chain_paths),
            device_read=device_read,
        )
    return _exit_code_for_tri(report.state)


def _run_rollback_read(args: argparse.Namespace) -> int:
    setup = _prepare_fastboot(args, command="cairn rollback read")
    if setup is None:
        return EXIT_USAGE
    client, tool, simulated = setup
    read = read_stored_rollback_indexes(client, serial=args.serial, slot=args.slot)

    if args.json:
        payload: dict[str, object] = {
            "tool": tool,
            "simulated": simulated,
            **read.to_dict(),
        }
        print(json.dumps(payload, indent=2))
    else:
        _print_rollback_read(read, simulated=simulated)
    return EXIT_OK if read.state is Tri.TRUE else EXIT_UNKNOWN


def _prepare_fastboot(
    args: argparse.Namespace,
    *,
    command: str,
) -> tuple[FastbootClient, dict[str, object], bool] | None:
    runner = ToolRunner()
    simulate = getattr(args, "simulate", None)
    if simulate is not None:
        prefix = (sys.executable, "-m", "cairn.sim.fastboot_sim")
        extra_env = {TRANSCRIPT_ENV: str(simulate)}
        tool: dict[str, object] = {
            "kind": "simulated",
            "name": "fastboot",
            "transcript": str(simulate),
            "manifest_ok": None,
            "simulated": True,
        }
        return FastbootClient(prefix, runner=runner, extra_env=extra_env), tool, True

    fastboot = _resolve_fastboot(args.fastboot)
    if fastboot is None:
        print(
            f"{command}: fastboot not found; pass --fastboot or set CAIRN_FASTBOOT",
            file=sys.stderr,
        )
        return None
    try:
        report = TOOL_MANIFEST.verify("fastboot", fastboot, runner)
    except ToolError as exc:
        print(f"{command}: {exc}", file=sys.stderr)
        return None
    tool = {
        "kind": "fastboot",
        "name": "fastboot",
        "path": str(report.path),
        "version": report.version,
        "sha256": report.sha256,
        "license": report.license,
        "manifest_ok": report.ok,
        "manifest_detail": report.detail,
        "simulated": False,
    }
    return FastbootClient((str(fastboot),), runner=runner), tool, False


def _parse_stored_indexes(specs: list[str], command: str) -> dict[int, int] | None:
    values: dict[int, int] = {}
    for spec in specs:
        location_text, separator, value_text = spec.partition("=")
        if not separator or not location_text or not value_text:
            print(
                f"{command}: malformed --stored {spec!r}; use LOCATION=VALUE",
                file=sys.stderr,
            )
            return None
        try:
            location = int(location_text, 0)
            value = int(value_text, 0)
        except ValueError:
            print(f"{command}: --stored {spec!r} must use integers", file=sys.stderr)
            return None
        if location < 0 or value < 0:
            print(f"{command}: --stored {spec!r} must not be negative", file=sys.stderr)
            return None
        if value > MAX_ROLLBACK_INDEX:
            print(
                f"{command}: --stored {spec!r} exceeds the 64-bit rollback index limit",
                file=sys.stderr,
            )
            return None
        if location in values:
            print(f"{command}: duplicate stored location {location}", file=sys.stderr)
            return None
        values[location] = value
    return values


def _print_rollback_read(read: DeviceRollbackRead, *, simulated: bool) -> None:
    suffix = " (SIMULATED)" if simulated else ""
    print(f"cairn rollback read: read-only fastboot getvar all{suffix}")
    if read.serial is not None:
        print(f"serial: {read.serial}")
    if read.slot is not None:
        print(f"slot: {read.slot}")
    state = "complete" if read.state is Tri.TRUE else "UNKNOWN"
    print(f"stored index read: {state}")
    if read.indexes:
        print(f"indexes: {len(read.indexes)}")
        for index in read.indexes:
            print(f"  location {index.location} = {index.value} ({index.variable})")
    else:
        print("indexes: none")
    for warning in read.warnings:
        print(f"warning: {warning}")
    for item in read.unresolved:
        print(f"unresolved: {item}")
    print(f"detail: {read.detail}")
    print("note: a device read is a claim, not AVB verification")
    print("read-only: no device writes")


def _print_rollback_report(
    report: RollbackReport,
    *,
    chain_supplied: bool,
    device_read: DeviceRollbackRead | None = None,
) -> None:
    print(f"findings: {len(report.findings)}")
    for finding in report.findings:
        location = "unknown" if finding.location is None else str(finding.location)
        slot = "unknown" if finding.slot is None else finding.slot
        print(
            f"  {finding.counter}: {_tri_label(finding.state)} "
            f"(location={location}, slot={slot}; {finding.reason})"
        )
    for warning in report.warnings:
        print(f"  warning: {warning}")
    if device_read is not None:
        state = "complete" if device_read.state is Tri.TRUE else "UNKNOWN"
        print(
            f"stored index read: {state} ({len(device_read.indexes)} indexes; {device_read.detail})"
        )
    print(f"verdict: {_tri_label(report.state)} - {_rollback_verdict(report.state)}")
    if chain_supplied:
        print("note: chain images are parsed, not signature-checked; use avb verify --chain")
    print("note: an UNKNOWN verdict is a hard stop for SR-004, not a warning")
    if device_read is not None:
        print("read-only: getvar only; no device writes")
    else:
        print("read-only: no device access")


def _rollback_verdict(state: Tri) -> str:
    if state is Tri.TRUE:
        return "the package cannot lower any evaluated counter"
    if state is Tri.FALSE:
        return "the package definitely lowers a counter and this is not overridable"
    return "the package may lower a counter and the evidence is incomplete"


def _tri_label(state: Tri) -> str:
    """Label a tri-state fact. Distinct from _state_label, which takes bool | None."""
    if state is Tri.TRUE:
        return "TRUE"
    if state is Tri.FALSE:
        return "FALSE"
    return "UNKNOWN"


def _exit_code_for_tri(state: Tri) -> int:
    if state is Tri.TRUE:
        return EXIT_OK
    if state is Tri.FALSE:
        return EXIT_FAILED
    return EXIT_UNKNOWN


def _resolve_fastboot(explicit: Path | None) -> Path | None:
    return _resolve_tool("fastboot", explicit, "CAIRN_FASTBOOT")


def _resolve_tool(name: str, explicit: Path | None, env_var: str) -> Path | None:
    if explicit is not None:
        return explicit
    env_value = os.environ.get(env_var)
    if env_value:
        return Path(env_value)
    found = shutil.which(name)
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
    fingerprint = payload.get("device_fingerprint")
    if isinstance(fingerprint, str):
        print(f"device fingerprint: {fingerprint}")
    else:
        print("device fingerprint: unavailable")
        detail = payload.get("device_fingerprint_detail")
        if isinstance(detail, str):
            print(f"  {detail}")
    unknown = sum(1 for fact in result.facts if fact.evidence.state.is_unknown)
    print(f"{len(result.facts)} facts, {unknown} unknown; read-only probe, no device writes")


if __name__ == "__main__":
    raise SystemExit(main())
