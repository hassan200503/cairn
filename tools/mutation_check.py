#!/usr/bin/env python3
"""Mutation check for the safety rules (AGENTS.md testing requirement).

Every safety rule must have at least three mutants that the test suite
kills. For each rule this script temporarily replaces the rule's evaluator
in ``src/cairn/safety/engine.py`` with a wrapped mutant:

- ``always-true``   the evaluator's verdict is forced to TRUE
- ``unknown-true``  UNKNOWN verdicts become TRUE (the silent-pass mutant)
- ``false-true``    FALSE verdicts become TRUE (the unsafe-pass mutant)

Each mutant runs the safety-relevant test files in a subprocess; a mutant
is *killed* when the run fails, and *survived* when it passes. The script
exits non-zero if any mutant survives, and always restores the original
engine source.

Stdlib only. Run on demand (a full pass takes a few minutes); it is not
part of the default CI loop.

Usage::

    python tools/mutation_check.py [--python PATH]
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

# The safety-relevant test files: anything that asserts on rule verdicts.
TEST_FILES = [
    "tests/test_safety_engine.py",
    "tests/test_cli.py",
    "tests/test_recovery.py",
    "tests/test_vab.py",
    "tests/test_dynpart.py",
    "tests/test_snapshot_flows.py",
    "tests/test_wizard.py",
]

MUTANTS = ("always-true", "unknown-true", "false-true")

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

# The registration site is the single place a rule binds to its evaluator;
# mutating it scopes each mutant to exactly one rule.
_WRAPPER_TEMPLATE = "(_MutantWrap({evaluator}, {mutant!r})),  # mutant: {rule_id}"


@dataclass(frozen=True)
class MutantSpec:
    rule_id: str
    evaluator: str
    mutant: str

    @property
    def name(self) -> str:
        return f"{self.rule_id}:{self.mutant}"


def _discover_rules(source: str) -> list[MutantSpec]:
    specs: list[MutantSpec] = []
    for line in source.splitlines():
        stripped = line.strip()
        if not (stripped.startswith("(_SR_") and stripped.endswith("),") and ", _sr" in stripped):
            continue
        inner = stripped[1:-2]
        rule_id, _, evaluator = inner.partition(", ")
        for mutant in MUTANTS:
            specs.append(MutantSpec(rule_id.strip(), evaluator.strip(), mutant))
    return specs


def _mutated_source(source: str, spec: MutantSpec) -> str:
    old = f"({spec.rule_id}, {spec.evaluator}),"
    if source.count(old) != 1:
        raise SystemExit(
            f"mutation harness: registration {old!r} appears {source.count(old)} "
            "times in engine.py; update the harness after a refactor"
        )
    wrapper = _WRAPPER_TEMPLATE.format(
        evaluator=spec.evaluator, mutant=spec.mutant, rule_id=spec.rule_id
    )
    mutated = source.replace(old, wrapper, 1)
    marker = "DEFAULT_RULES: Final["
    if marker not in mutated:
        raise SystemExit("mutation harness: DEFAULT_RULES marker missing from engine.py")
    return mutated.replace(marker, _WRAPPER_CLASS + marker, 1)


def main() -> int:
    parser = argparse.ArgumentParser(description="safety-rule mutation check")
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="interpreter used to run pytest (default: the current one)",
    )
    args = parser.parse_args()

    original = ENGINE.read_bytes().decode("utf-8")
    specs = _discover_rules(original)
    if not specs:
        raise SystemExit("mutation harness: no rule registrations found in engine.py")

    print(f"discovered {len(specs) // len(MUTANTS)} rules, {len(specs)} mutants")
    results: list[tuple[MutantSpec, str]] = []
    try:
        for spec in specs:
            ENGINE.write_bytes(_mutated_source(original, spec).encode("utf-8"))
            start = time.monotonic()
            try:
                proc = subprocess.run(
                    [
                        args.python,
                        "-m",
                        "pytest",
                        *TEST_FILES,
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
                print(f"{spec.name:<28} TIMEOUT")
                continue
            elapsed = time.monotonic() - start
            verdict = "killed" if proc.returncode != 0 else "SURVIVED"
            results.append((spec, verdict))
            print(f"{spec.name:<28} {verdict:<10} ({elapsed:.1f}s)")
    finally:
        # Byte-exact restore: the harness must never leave a diff behind.
        ENGINE.write_bytes(original.encode("utf-8"))

    survivors = [spec for spec, verdict in results if verdict != "killed"]
    print()
    print(f"{len(results) - len(survivors)}/{len(results)} mutants killed")
    if survivors:
        print("SURVIVORS (add a test that fails for each):")
        for spec in survivors:
            print(f"  {spec.name}")
        return 1
    print("every safety rule has three suite-killed mutants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
