"""Command-line entry point for Cairn."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from cairn import __version__
from cairn.adapters.fastboot import FastbootClient, ProbedFact, ProbeResult
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

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_UNKNOWN = 3


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
        safety = SafetyEngine().evaluate(SafetyContext(provenance=provenance))
        assessment = assess_plan(plan, safety)
    except (HashIndexError, PackageError, PlanError) as exc:
        print(f"cairn plan: {exc}", file=sys.stderr)
        return EXIT_FAILED

    if args.json:
        print(json.dumps(assessment.to_dict(), indent=2))
    else:
        _print_plan(assessment)
    return EXIT_OK if assessment.executable else EXIT_UNKNOWN


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
    if args.simulate is not None:
        prefix = (sys.executable, "-m", "cairn.sim.fastboot_sim")
        extra_env = {TRANSCRIPT_ENV: str(args.simulate)}
        tool: dict[str, object] = {
            "kind": "simulated",
            "transcript": str(args.simulate),
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
    unknown = sum(1 for fact in result.facts if fact.evidence.state.is_unknown)
    print(f"{len(result.facts)} facts, {unknown} unknown; read-only probe, no device writes")


if __name__ == "__main__":
    raise SystemExit(main())
