# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Cairn v2 specification with corrections to the v1 sparse constants, AVB
  chain-of-trust rule, licensing, Samsung strategy, fastboot read-back, post-wipe
  verification, A/B rollback language, planner order, resplitter scope, approval
  binding, and battery threshold.
- Execution plan, milestone roadmap, safety rules, ADRs, known unknowns, and
  hardware findings template.
- Python scaffold: `cairn` package, CLI (`version`, `levels`, `doctor` placeholder),
  tri-state logic, evidence with provenance and freshness, verification levels, error
  hierarchy, and sparse format header parsing.
- Tests for tri-state logic, evidence freshness, sparse constants and headers, and
  CLI behavior.
- CI on Ubuntu and Windows with ruff, mypy strict, and pytest.
- Bounded subprocess runner: no shell, scrubbed environment, timeout, cancellation,
  byte-capped output, and explicit failure classification.
- Tool manifest with minimum versions, license audit flags, GPL separation markers,
  and SHA-256 verification; platform-tools 37.0.3 `fastboot.exe` artifact pinned.
- Full sparse-image walk and validation (chunk sizes, block totals, extended headers,
  trailing bytes), plus a `img2simg`/`simg2img` differential oracle harness and a
  dedicated CI job that installs AOSP libsparse on Ubuntu.
- Transcript schema, recorder, and fault-injecting fastboot simulator (timeout,
  truncated, disconnect, fail, garbage); synthetic scrubbed `getvar all` fixture.
- Read-only fastboot adapter and `cairn probe` command with JSON output; simulated
  probes are labeled and their evidence source is `INFERRED`.
- Fail-closed AOSP v1 `fastboot-info.txt` parser.
- Read-only factory/OTA zip inspection and unified `PackageManifest`: unsafe names,
  duplicate entries, encryption, symlinks, unsupported compression, and size/count
  limits fail closed; unknown entries are reported; OTA metadata and payload
  properties are parsed without trusting them. `cairn inspect` prints the manifest
  with optional per-entry and archive hashes. Nested factory image zips are reported
  but not opened.
- Offline vendor hash index and `cairn provenance`: strict JSON schema, duplicate and
  unsafe-name rejection, archive/entry SHA-256 comparison, tri-state result, and an
  explicit warning that a local index match is not a signature check.
- Evidence IDs and an evidence graph: boot-epoch stamping, post-reboot invalidation,
  inferred/stale refusal, verified JSON serialization, and property tests.
- Host Doctor MVP: WSL/VM detection, USB controller check, Windows driver heuristic,
  USB selective-suspend check, antivirus warning, tool manifest checks, and a bounded
  `getvar` link soak with failure and latency thresholds. Read-only by construction.

### Known limitations

- No device write path.
- Host Doctor covers host, tool, and `getvar` link checks; staged-download soak,
  driver enumeration, and USB topology depth are pending.
- The sparse oracle skips locally when libsparse is absent; CI enforces it.
- The fastboot adapter has not yet run against real hardware.
- Sparse oracle, fastboot-info, and the AOSP fastboot source findings are verified
  against pinned primary sources, but device-dependent behavior remains hypothesis.
- No hardware findings yet.

## [0.1.0] - 2026-11-24

### Added

- Initial public scaffold under Apache-2.0.
