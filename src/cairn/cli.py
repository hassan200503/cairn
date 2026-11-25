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
from cairn.core.tristate import Tri
from cairn.core.verification import VerificationLevel
from cairn.host.doctor import SOAK_ATTEMPTS_DEFAULT, HostDoctor, HostReport
from cairn.package.archive import PackageError, PackageManifest, load_package
from cairn.plan.planner import (
    Plan,
    PlanError,
    PlanOptions,
    PlanStep,
    SlotPolicy,
    build_plan,
)
from cairn.provenance.avb import (
    AvbChainPartition,
    AvbError,
    AvbHashDescriptor,
    AvbHashtreeDescriptor,
    AvbKernelCmdline,
    AvbProperty,
    AvbUnknownDescriptor,
    VbmetaImage,
    calculate_vbmeta_digest,
    load_vbmeta,
)
from cairn.provenance.hash_index import (
    HashIndexError,
    ProvenanceResult,
    load_hash_index,
    verify_manifest,
)
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
        help="read-only AVB VBMeta inspection (no signature verification)",
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
    except (HashIndexError, PackageError, PlanError) as exc:
        print(f"cairn plan: {exc}", file=sys.stderr)
        return EXIT_FAILED

    if args.json:
        print(json.dumps(plan.to_dict(), indent=2))
    else:
        _print_plan(plan)
    return EXIT_OK if plan.executable else EXIT_UNKNOWN


def _print_plan(plan: Plan) -> None:
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
    print(f"executable: {'TRUE' if plan.executable else 'FALSE'}")
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
    print("cairn avb: choose 'info' or 'digest'", file=sys.stderr)
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
    chain: dict[str, VbmetaImage] = {}
    for spec in args.chain:
        name, separator, path_text = spec.partition("=")
        if not separator or not name or not path_text:
            print(
                f"cairn avb digest: malformed --chain {spec!r}; use NAME=PATH",
                file=sys.stderr,
            )
            return EXIT_USAGE
        if name in chain:
            print(f"cairn avb digest: duplicate chain {name!r}", file=sys.stderr)
            return EXIT_USAGE
        try:
            chain[name] = load_vbmeta(Path(path_text))
        except AvbError as exc:
            print(f"cairn avb digest: {exc}", file=sys.stderr)
            return EXIT_FAILED

    try:
        image = load_vbmeta(args.image)
        digest = calculate_vbmeta_digest(image, hash_name=args.hash, chain=chain)
    except AvbError as exc:
        print(f"cairn avb digest: {exc}", file=sys.stderr)
        return EXIT_FAILED

    print(digest)
    return EXIT_OK


def _print_vbmeta(image: VbmetaImage) -> None:
    header = image.header
    source = image.source if image.source is not None else "(memory)"
    print(f"image: {source}")
    trailing = f" (+{image.trailing_bytes} trailing bytes)" if image.trailing_bytes else ""
    print(f"size: {len(image.blob)} bytes{trailing}")
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
