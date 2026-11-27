#!/usr/bin/env python3
"""Mutation checks for the safety rules and the approval binding.

AGENTS.md requires every safety rule to have at least three mutants that
the test suite kills, and T13 requires mutation tests for the approval
binding. This script mutates the source in memory-shaped steps (write,
run pytest in a subprocess, restore) and reports killed/survived:

- safety rules: every rule registered in ``DEFAULT_RULES`` gets three
  evaluator-wrapping mutants — ``always-true``, ``unknown-true`` (the
  silent-pass mutant), and ``false-true`` (the unsafe-pass mutant).
- approval binding: explicit mutants over ``approval/token.py``,
  ``approval/binding.py``, and ``approval/device.py`` — skipped field
  comparisons, skipped MAC/binding-hash/key-id checks, a dropped payload
  field, disabled hash validation, a dropped fingerprint fact, and stale
  facts accepted.

A mutant is *killed* when the relevant test run fails. The script exits
non-zero if anything survives and always restores the original sources
byte-exactly. Stdlib only; run on demand (a full pass takes a few
minutes); not part of the default CI loop.

Usage::

    python tools/mutation_check.py [--python PATH] [--only RULE|approval]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ENGINE = REPO / "src" / "cairn" / "safety" / "engine.py"
TOKEN = REPO / "src" / "cairn" / "approval" / "token.py"
BINDING = REPO / "src" / "cairn" / "approval" / "binding.py"
DEVICE = REPO / "src" / "cairn" / "approval" / "device.py"

RULE_TEST_FILES = [
    "tests/test_safety_engine.py",
    "tests/test_cli.py",
    "tests/test_recovery.py",
    "tests/test_vab.py",
    "tests/test_dynpart.py",
    "tests/test_snapshot_flows.py",
    "tests/test_wizard.py",
]
APPROVAL_TEST_FILES = [
    "tests/test_approval.py",
    "tests/test_cli.py",
    "tests/test_wizard.py",
]

MUTANT_KINDS = ("always-true", "unknown-true", "false-true")

_WRAPPER_CLASS = '''
class _MutantWrap:
    """Injected by tools/mutation_check.py; a temporarily mutated evaluator."""

    def __init__(self, evaluator, mutant: str) -> None:
        self._evaluator = evaluator
        self._mutant = mutant

    def __call__(self, ctx, now, spec):
        result = self._evaluator(ctx, now, spec)
        if self._mutant == "always-true":
            return replace(result, state=Tri.TRUE)
        if self._mutant == "unknown-true" and result.state is Tri.UNKNOWN:
            return replace(result, state=Tri.TRUE)
        if self._mutant == "false-true" and result.state is Tri.FALSE:
            return replace(result, state=Tri.TRUE)
        return result

'''


@dataclass(frozen=True)
class MutantSpec:
    name: str
    path: Path
    old: str
    new: str
    test_files: tuple[str, ...]


def _rule_mutants(source: str) -> list[MutantSpec]:
    specs: list[MutantSpec] = []
    for line in source.splitlines():
        stripped = line.strip()
        if not (stripped.startswith("(_SR_") and stripped.endswith("),") and ", _sr" in stripped):
            continue
        inner = stripped[1:-2]
        rule_id, _, evaluator = inner.partition(", ")
        rule_id, evaluator = rule_id.strip(), evaluator.strip()
        old = f"({rule_id}, {evaluator}),"
        for kind in MUTANT_KINDS:
            wrapper = f"(_MutantWrap({evaluator}, {kind!r})),  # mutant: {rule_id}"
            specs.append(
                MutantSpec(f"{rule_id}:{kind}", ENGINE, old, wrapper, tuple(RULE_TEST_FILES))
            )
    return specs


def _engine_source_with_wrapper(source: str) -> str:
    marker = "DEFAULT_RULES: Final["
    if marker not in source:
        raise SystemExit("mutation harness: DEFAULT_RULES marker missing from engine.py")
    return source.replace(marker, _WRAPPER_CLASS + marker, 1)


def _pass() -> str:
    return "    pass  # mutant: comparison skipped"


def _neutered(condition: str) -> str:
    return f"    if False and {condition}:"


def _approval_mutants() -> list[MutantSpec]:
    token = TOKEN.read_text(encoding="utf-8")

    def compare_block(label: str) -> str:
        return (
            f"    _compare(\n"
            f'        "{label}",\n'
            f"        token.inputs.{label},\n"
            f"        current.{label},\n"
            f"        mismatches,\n"
            f"        reasons,\n"
            f"    )\n"
        )

    mutants: list[MutantSpec] = []
    for label in ("plan_sha256", "evidence_snapshot_sha256", "archive_sha256"):
        mutants.append(
            MutantSpec(
                f"approval:{label}-compare-skipped",
                TOKEN,
                compare_block(label),
                _pass() + "\n",
                tuple(APPROVAL_TEST_FILES),
            )
        )
    mutants.append(
        MutantSpec(
            "approval:device-compare-skipped",
            TOKEN,
            "    _compare_device(token.inputs.device, current.device, mismatches, reasons)\n",
            _pass() + "\n",
            tuple(APPROVAL_TEST_FILES),
        )
    )
    mutants.append(
        MutantSpec(
            "approval:package-hashes-compare-skipped",
            TOKEN,
            (
                "    _compare_package_hashes(\n"
                "        token.inputs.package_hashes,\n"
                "        current.package_hashes,\n"
                "        mismatches,\n"
                "        reasons,\n"
                "    )\n"
            ),
            _pass() + "\n",
            tuple(APPROVAL_TEST_FILES),
        )
    )
    mutants.append(
        MutantSpec(
            "approval:tools-compare-skipped",
            TOKEN,
            "    _compare_tools(token.inputs.tools, current.tools, mismatches, reasons)\n",
            _pass() + "\n",
            tuple(APPROVAL_TEST_FILES),
        )
    )
    mutants.append(
        MutantSpec(
            "approval:mismatches-ignored",
            TOKEN,
            "    if mismatches:\n",
            _neutered("mismatches:") + "\n",
            tuple(APPROVAL_TEST_FILES),
        )
    )
    mutants.append(
        MutantSpec(
            "approval:parse-failure-passes",
            TOKEN,
            (
                "        return ApprovalVerdict(\n"
                "            state=Tri.FALSE,\n"
                "            reasons=(str(exc),),\n"
                '            mismatches=("token",),\n'
            ),
            (
                "        return ApprovalVerdict(\n"
                "            state=Tri.TRUE,\n"
                "            reasons=(str(exc),),\n"
                '            mismatches=("token",),\n'
            ),
            tuple(APPROVAL_TEST_FILES),
        )
    )
    mutants.append(
        MutantSpec(
            "approval:signature-check-skipped",
            TOKEN,
            "    if not hmac.compare_digest(signature, expected):\n",
            _neutered("not hmac.compare_digest(signature, expected):") + "\n",
            tuple(APPROVAL_TEST_FILES),
        )
    )
    mutants.append(
        MutantSpec(
            "approval:binding-hash-check-skipped",
            TOKEN,
            "    if recorded_binding != inputs.binding_sha256:\n",
            _neutered("recorded_binding != inputs.binding_sha256:") + "\n",
            tuple(APPROVAL_TEST_FILES),
        )
    )
    mutants.append(
        MutantSpec(
            "approval:key-id-check-skipped",
            TOKEN,
            "    if recorded_key_id != key_id(key):\n",
            _neutered("recorded_key_id != key_id(key):") + "\n",
            tuple(APPROVAL_TEST_FILES),
        )
    )
    mutants.append(
        MutantSpec(
            "approval:binding-payload-drops-plan",
            BINDING,
            '            "plan_sha256": self.plan_sha256,\n',
            "",
            tuple(APPROVAL_TEST_FILES),
        )
    )
    mutants.append(
        MutantSpec(
            "approval:hex64-validation-off",
            BINDING,
            "    if _HEX64_RE.fullmatch(value) is None:\n",
            _neutered("_HEX64_RE.fullmatch(value) is None:") + "\n",
            tuple(APPROVAL_TEST_FILES),
        )
    )
    mutants.append(
        MutantSpec(
            "approval:fingerprint-drops-product",
            DEVICE,
            '    "product",\n',
            "",
            tuple(APPROVAL_TEST_FILES),
        )
    )
    mutants.append(
        MutantSpec(
            "approval:stale-required-fact-accepted",
            DEVICE,
            '            raise ApprovalError(f"device fact {name} is stale or inferred")\n',
            "            pass  # mutant: stale fact accepted\n",
            tuple(APPROVAL_TEST_FILES),
        )
    )
    # Verify every anchor is unique now, before any run.
    for path, source in ((TOKEN, token),):
        for spec in mutants:
            if spec.path == path and source.count(spec.old) != 1:
                raise SystemExit(
                    f"mutation harness: anchor for {spec.name} appears "
                    f"{source.count(spec.old)} times; update the harness"
                )
    return mutants


def main() -> int:
    parser = argparse.ArgumentParser(description="mutation checks for safety-critical logic")
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="interpreter used to run pytest (default: the current one)",
    )
    parser.add_argument(
        "--only",
        choices=("rules", "approval"),
        help="run only one mutant family",
    )
    args = parser.parse_args()

    engine_original = ENGINE.read_bytes().decode("utf-8")
    token_original = TOKEN.read_bytes().decode("utf-8")
    binding_original = BINDING.read_bytes().decode("utf-8")
    device_original = DEVICE.read_bytes().decode("utf-8")
    originals = {
        ENGINE: engine_original,
        TOKEN: token_original,
        BINDING: binding_original,
        DEVICE: device_original,
    }

    specs: list[MutantSpec] = []
    if args.only in (None, "rules"):
        specs.extend(_rule_mutants(engine_original))
    if args.only in (None, "approval"):
        specs.extend(_approval_mutants())
    if not specs:
        raise SystemExit("mutation harness: no mutants discovered")

    print(f"{len(specs)} mutants")
    results: list[tuple[MutantSpec, str]] = []
    try:
        for spec in specs:
            source = originals[spec.path]
            if source.count(spec.old) != 1:
                raise SystemExit(
                    f"mutation harness: anchor for {spec.name} appears "
                    f"{source.count(spec.old)} times; update the harness"
                )
            mutated = source.replace(spec.old, spec.new, 1)
            if spec.path == ENGINE:
                mutated = _engine_source_with_wrapper(mutated)
            spec.path.write_bytes(mutated.encode("utf-8"))
            start = time.monotonic()
            try:
                proc = subprocess.run(
                    [
                        args.python,
                        "-m",
                        "pytest",
                        *spec.test_files,
                        "-x",
                        "-q",
                        "--no-header",
                        "-p",
                        "no:cacheprovider",
                    ],
                    cwd=REPO,
                    capture_output=True,
                    text=True,
                    timeout=900,
                )
            except subprocess.TimeoutExpired:
                results.append((spec, "TIMEOUT"))
                print(f"{spec.name:<44} TIMEOUT")
                continue
            elapsed = time.monotonic() - start
            verdict = "killed" if proc.returncode != 0 else "SURVIVED"
            results.append((spec, verdict))
            print(f"{spec.name:<44} {verdict:<10} ({elapsed:.1f}s)")
    finally:
        for path, source in originals.items():
            path.write_bytes(source.encode("utf-8"))

    survivors = [spec for spec, verdict in results if verdict != "killed"]
    print()
    print(f"{len(results) - len(survivors)}/{len(results)} mutants killed")
    if survivors:
        print("SURVIVORS (add a test that fails for each):")
        for spec in survivors:
            print(f"  {spec.name}")
        return 1
    print("every mutant was killed by the suite")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
