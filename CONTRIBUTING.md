# Contributing to Cairn

Cairn is safety-critical software for physical devices. A plausible-looking change
that weakens a safety rule is worse than no change.

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```console
git clone https://github.com/hassan200503/cairn.git
cd cairn
uv sync
uv run pytest -q
```

## Workflow

1. Open an issue or a draft PR describing the behavior and the safety impact.
2. Add tests first when the change touches a parser, a safety rule, or the journal.
3. Keep the diff focused. Do not mix refactors with behavior changes.
4. Update the docs listed in `AGENTS.md`.
5. Run the five quality commands.
6. Request review from a safety-sensitive reviewer for rule, journal, or write-path
   changes.

```console
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest -q
```

## Safety-sensitive changes

A change is safety-sensitive if it touches:

- `src/cairn/core/` or future `safety/`, `executor/`, `journal/`, `recovery/` code;
- a parser whose output feeds a rule;
- device capability detection;
- verification-level reporting;
- approval binding;
- overrides or irreversible actions.

Such a change needs:

- a source reference or hardware finding ID;
- a `FALSE`/`UNKNOWN` behavior test;
- a mutation test that fails when the rule is weakened;
- an explicit note in the PR about what could now pass that previously blocked.

## Device findings

Use `docs/HARDWARE_FINDINGS.md`. Scrub identifiers. Never attach an unscrubbed
transcript or a screenshot containing personal data.

## License

By contributing, you agree that your contribution is licensed under Apache-2.0. Do
not copy code from GPL-3.0 or MPL-2.0 projects into this repository. Do not add
dependencies without a decision record.

## Non-goals

PRs that implement FRP bypass, IMEI changes, carrier-lock circumvention, loader
authentication bypass, signature-check defeat, or cross-device transplant will be
closed.
