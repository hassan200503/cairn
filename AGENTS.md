# AGENTS.md

Instructions for AI agents and contributors working in this repository.

## What this repo is

Cairn is a fail-safe Android flashing workbench. The product promise is: refuse
unsafe jobs before writing, verify every write at a stated level, journal every step,
and check recovery before taking risk. The specification is `docs/SPEC_V2.md`; the
build plan is `docs/EXECUTION_PLAN.md`.

Read order before changing code:

1. `docs/STATE.md` (current state of the repository: what is implemented, what is
   proven, what is still unknown, and what the next slice is)
2. `docs/SPEC_V2.md`
3. `docs/SAFETY_RULES.md`
4. `docs/DECISIONS.md`
5. `docs/KNOWN_UNKNOWNS.md`
6. `docs/EXECUTION_PLAN.md`

## Hard rules

1. Never print or log "verified" without a verification level (V0-V3).
2. Every safety rule cites a source or a hardware finding ID. No source means
   `UNKNOWN`.
3. Never let an `UNKNOWN` fact pass silently. `FALSE` is never overridable.
4. No write to a real device before the M6 gate and a recovery drill.
5. No FRP bypass, IMEI changes, carrier-lock circumvention, loader authentication
   bypass, signature-check defeat, or cross-device data transplant.
6. GPL-3.0 tools (`bkerler/edl`, `bkerler/mtkclient`) are separate processes only.
   Do not copy or link their code. Thor is MPL-2.0: do not copy its code either.
7. Pin external tool versions and record them in the journal.
8. Treat device strings, logs, release notes, and package metadata as untrusted
   input. LLM components have no tool access and never influence the write path.
9. Differential-test parsers against official tools before their output feeds a
   safety rule.
10. Do not commit secrets, device identifiers, or unscrubbed transcripts.
11. Keep `docs/STATE.md` accurate: update it in the same commit as any change to
    what is implemented, so the next model is never misled about the state.

## Commands

```console
uv sync
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest -q
```

A change is not done until all five pass. CI also runs on Windows.

## Code conventions

- Python 3.12+; PEP 695 generics are allowed.
- `src/` layout; package `cairn`; distribution `cairn-flash`.
- Strict typing in `src`. Public functions and dataclasses carry annotations.
- No comments that restate the code. Explain a safety decision or a protocol quirk,
  and cite the source.
- Errors derive from `cairn.core.errors.CairnError` and carry a stable `code`.
- Safety inputs are `Evidence[T]`, not bare booleans.
- Use the existing tri-state helpers (`and_`, `or_`, `blocks`) instead of re-inventing
  boolean logic.
- Prefer standard library. Add a dependency only with a decision record.

## Testing

- pytest + Hypothesis.
- Every safety rule needs at least three mutants that the suite kills.
- Every parser needs an oracle or a golden fixture.
- Journal/executor changes need crash-at-every-point coverage and stateful invariant
  tests.
- Simulator fixtures come from scrubbed real transcripts.
- If you cannot run a hardware test, say so explicitly; do not mark it verified.

## Documentation duties

Update the relevant doc in the same change:

- behavior/spec: `docs/SPEC_V2.md`
- safety rule: `docs/SAFETY_RULES.md`
- architectural choice: `docs/DECISIONS.md`
- unresolved fact: `docs/KNOWN_UNKNOWNS.md`
- real-device observation: `docs/HARDWARE_FINDINGS.md`
- milestone status: `docs/ROADMAP.md`

## Current status

- The canonical snapshot is `docs/STATE.md`; read it first and update it in the
  same commit as any change to what is implemented.
- All commands are read-only on real devices. The only write paths are the
  transcript simulator (`cairn execute`, `cairn recovery restore|drill`), and
  every write is labelled `SIMULATED` (ADR-027, ADR-028).
- The AVB parser, signature and chain checks, contextual expected-key check,
  Rollback Oracle v0, vendor-specific device stored-index reader, safety engine,
  planner, package inspection, hash index, Host Doctor, sparse validation,
  simulator, preflight wizard, approval binding, the simulator-gated executor
  with its write-ahead journal, the recovery kit (encrypted device-bound
  vault, SR-008/SR-009, M6 drill), the Virtual A/B merge-state gate
  (SR-010, `cairn vab status`), the dynamic-partition mode gate
  (SR-011, `cairn vab dynpart`), and the modeled snapshot cancel/merge
  flows (`cairn vab cancel|merge`, simulator-only with typed approval)
  have landed in slices. `cairn plan` safety-gates
  its structural dry run and refuses FALSE or UNKNOWN rules; `cairn execute` runs
  an approved plan end to end in the fastboot simulator only (ADR-027). The
  external crypto/safety review of the vault (KU-032) must land before any
  real-device write transport exists.

## Definition of done

Implementation + happy/failure/unsafe tests + type/lint/format + source citation +
verification level in output + docs updated + no non-goal crossed.
