# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Catalog file signing (ADR-030): `cairn catalog sign` writes a detached
  HMAC-SHA256 signature of the exact file bytes; `cairn catalog verify`
  re-checks schema and signature; `avb key-check --catalog`, `rollback check
  --catalog`, and `wizard --catalog` accept `--catalog-key`/
  `--catalog-signature` and refuse a mismatched or half-supplied pair.
- Catalog rollback bounds (catalog schema v2): a device entry may carry cited
  per-location `rollback_bounds`; the rollback oracle consults a bound only when
  the stored value is unavailable (a maximum proves safety, a minimum proves a
  downgrade, an inconclusive bound stays UNKNOWN, and a stored read outranks a
  bound). Wired into `cairn rollback check --catalog` and `cairn wizard --catalog`
  with the entry's source printed as the citation. Old v1 catalogs are refused.
- Local workbench UI (ADR-031): `cairn ui` serves a loopback-only dashboard
  (`127.0.0.1:8722`) over the audited core — doctor, probe, wizard, plan,
  execute, avb, rollback, vab, catalog, and recovery backup/drill — with
  tri-state TRUE/FALSE/UNKNOWN colour rendering. No safety logic lives in the
  UI; every write path is the same simulator-gated transport as the CLI
  (ADR-027). 23 new tests in `tests/test_ui.py`.

## [0.2.0] - 2026-11-27

### Added

- Release packaging: `install.ps1` and `install.sh` installer scripts that install
  the CLI as an isolated `uv tool`, and a full README overhaul with real-output
  screenshots (`docs/screenshots/`).
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
- Read-only AVB VBMeta parser and `cairn avb info|digest|verify`: strict header and
  descriptor bounds, standalone/padded/footer-embedded images, hash/hashtree/chain/
  property/kernel-cmdline descriptors, AOSP digest with supplied chained images, and
  PKCS#1 v1.5 RSA signature verification against the embedded key or an expected raw
  AVB public key. AOSP avbtool-generated unsigned, signed, and footer fixtures;
  embedded-key validity is not a trust anchor.
- AVB chain-of-trust verification and `cairn avb verify --chain NAME=PATH`: each
  chain descriptor's key is matched against the chained image's embedded key, the
  chained signature is verified, the descriptor rollback location must be non-zero
  while the chained header location must be zero, and nested chains are followed
  with cycle detection and a depth limit. Results are tri-state and fail-closed,
  with FALSE outranking UNKNOWN outranking TRUE. Backed by an AOSP avbtool-generated
  two-level chain fixture whose digest matches `avbtool calculate_vbmeta_digest`.
- Lock-state-contextual AVB expected-key checks via `cairn avb key-check`: an
  invalid signature or locked-key mismatch is FALSE; unsigned images, a missing
  key, or unknown lock state are UNKNOWN; an unlocked mismatch is explicitly
  UNKNOWN with a warning. The lock state and trusted key are caller-supplied, so
  this is not device-root evidence and does not satisfy SR-013 by itself.
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
- Read-only planner v0 and `cairn plan`: preserves vendor order, filters if-wipe
  commands with deviations, annotates critical writes, hashes the canonical plan,
  and refuses to mark a plan executable without TRUE provenance and modeled options.
  The fallback is stop-and-reprobe, not a speculative flash sequence.
- Safety-gated `cairn plan`: every dry run now carries SR-001/002/003/004/012/013,
  a deterministic evidence-snapshot hash, and distinct structural versus safety
  decisions. The command combines both gates before it calls a plan executable;
  unavailable evidence is `UNKNOWN` and blocks instead of being assumed.
- Safety rule engine v0 with SR-001 identity, SR-002 provenance, SR-003 AVB chain,
  SR-004 rollback, SR-012 tool identity, and SR-013 lock/key aggregation. FALSE is
  never overridable; UNKNOWN blocks unless the rule is explicitly overridable;
  overrides log operator, reason, timestamp, evidence-snapshot hash, and exact report
  text without converting UNKNOWN to TRUE. Checks that assert a result without
  evidence references are downgraded to UNKNOWN.
- Approval binding and `cairn approval keygen|issue|verify|inspect`: a canonical
  binding over the plan hash, evidence-snapshot hash, archive hash, every package
  entry hash, a device binding (host-generated nonce plus a probed or caller
  fingerprint), and tool identities, serialized to `binding_sha256` and signed with
  HMAC-SHA256 under a per-session consistency key. Strict parsing rejects duplicate
  keys, unknown fields, wrong types, a wrong key id, and any binding mismatch; any
  byte change in any bound input invalidates the approval. The engine adds rule
  SR-018 ("approval binding valid") to a post-approval rule set
  (`PRE_APPROVAL_RULES` omits it); SR-018 is never overridable. Approval is a
  consistency boundary, not an authorization boundary (ADR-014, ADR-025), and it
  writes only token files, never a device.
- Rollback Oracle v0 and `cairn rollback check`: applies the AOSP rollback
  inequality to the counters a VBMeta package declares, including chained
  partitions at the location named by the chain descriptor and nested chains up
  to a depth limit, and returns a tri-state verdict with per-counter reasons.
  Missing or malformed chained counters are unresolved, and an unreadable
  image or chain is UNKNOWN rather than FALSE. The device's stored value is
  authoritative when readable; a catalog bound can otherwise prove safety or
  prove a downgrade. An unknown stored index is UNKNOWN and a hard stop, never
  overridable. Chain images are parsed but not signature-checked; SR-003 is
  separate. No OEM counter policy ships yet.
- Vendor-specific device stored-index reader and `cairn rollback read` /
  `cairn rollback check --device`: one read-only `fastboot getvar all`, parsing
  the observed `stored_rollback_index:<location> = <value>` and
  `avb_stored_rollback_indexes:<location>:<value>` forms. Duplicate identical
  values are accepted once; conflicts, malformed or empty values, absent
  variables, truncated output, and failed commands are unresolved and UNKNOWN.
  OEM signals such as `ap-ar-s` are warnings and are never mapped to AVB
  locations. AOSP fastboot has no standard variable for this value.
- Evidence IDs and an evidence graph: boot-epoch stamping, post-reboot invalidation,
  inferred/stale refusal, verified JSON serialization, and property tests.
- Host Doctor MVP: WSL/VM detection, USB controller check, Windows driver heuristic,
  USB selective-suspend check, antivirus warning, tool manifest checks, and a bounded
  `getvar` link soak with failure and latency thresholds. Read-only by construction.
- Read-only `cairn wizard`: an atomic, bounded, strict-JSON, canonical session record
  that chains doctor, inspect, provenance, probe, AVB, rollback, plan, and optional
  approval verification. Resume reuses only fresh successful matching observations;
  simulations are labeled `SIMULATED` and never become device evidence. The wizard
  writes no device and cannot elevate UNKNOWN safety facts.
- Session-bound approval issue/verify: `approval issue --session` requires a fresh
  `READY` session; both paths reload the package and index, re-hash entries, rebuild
  the plan, and reject archive, index, entry, or plan drift. The session hash is
  tamper-evident rather than a security boundary.

### Known limitations

- No device write path.
- Host Doctor covers host, tool, and `getvar` link checks; staged-download soak,
  driver enumeration, and USB topology depth are pending.
- The sparse oracle skips locally when libsparse is absent; CI enforces it.
- The fastboot adapter has not yet run against real hardware.
- Device stored-index reading is vendor-specific and fixture-backed only; no real
  scrubbed transcript exists, some SKUs need an EDL fallback, and Pixel `ap-ar-s`
  is not mapped to AVB locations.
- Sparse oracle, fastboot-info, and the AOSP fastboot source findings are verified
  against pinned primary sources, but device-dependent behavior remains hypothesis.
- No hardware findings yet.

## [0.1.0] - 2026-11-24

### Added

- Initial public scaffold under Apache-2.0.
