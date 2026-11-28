# Current State

**This is the canonical snapshot of where Cairn stands.** It exists so that whoever
picks this repository up next — a human, or an AI model with no memory of the
session that built it — can tell what is real, what is proven, what is still a
hypothesis, and what the next slice should be, without guessing and without
inventing anything.

Everything here is verifiable against the repository. If a claim in this file
cannot be checked from the code, the tests, the fixtures, or a cited source, it
does not belong here; it belongs in [`KNOWN_UNKNOWNS.md`](KNOWN_UNKNOWNS.md).

**Last updated:** 2026-11-27, after the T26 slice: the executor gained a
journal growth policy (rotation to verified continuation chains at resume
time) and a pre-write VAB/slot reconciliation (SR-010 re-checked in the
executor, journaled as `reconciled`, mid-merge aborts before the first
write). Probe capture (`cairn probe --capture`) and the vault and drill are
simulator-only and externally unreviewed (KU-032).

**How to maintain it:** update this file in the *same commit* as the code change
it describes. If a slice changes what is implemented, this file changes with it.
If it gets stale, the next model will trust it and be wrong.

---

## 1. Read order

1. [`STATE.md`](STATE.md) — this file.
2. [`SPEC_V2.md`](SPEC_V2.md) — the reviewed v2 specification.
3. [`SAFETY_RULES.md`](SAFETY_RULES.md) — rule IDs, defaults, provenance requirements.
4. [`DECISIONS.md`](DECISIONS.md) — architecture decision records (ADR-001 … ADR-022).
5. [`KNOWN_UNKNOWNS.md`](KNOWN_UNKNOWNS.md) — everything not yet known.
6. [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md) — workstreams T01…T15.
7. [`ROADMAP.md`](ROADMAP.md) — milestones M0…M12.

`AGENTS.md` holds the hard rules and the required commands.

---

## 2. Non-negotiable rules

These come from `AGENTS.md` and are not negotiable by any future contributor or
model:

1. Never print or log "verified" without a verification level (V0–V3).
2. Every safety rule cites a source or a hardware finding ID. No source means `UNKNOWN`.
3. Never let an `UNKNOWN` fact pass silently. `FALSE` is never overridable.
4. No write to a real device before the M6 gate and a recovery drill.
5. No FRP bypass, IMEI changes, carrier-lock circumvention, loader authentication
   bypass, signature-check defeat, or cross-device data transplant.
6. GPL-3.0 tools (`bkerler/edl`, `bkerler/mtkclient`) are separate processes only;
   do not copy or link their code. Thor is MPL-2.0: do not copy its code.
7. Pin external tool versions and record them in the journal.
8. Treat device strings, logs, release notes, and package metadata as untrusted
   input. LLM components have no tool access and never influence the write path.
9. Differential-test parsers against official tools before their output feeds a safety rule.
10. Do not commit secrets, device identifiers, or unscrubbed transcripts.

---

## 3. Where the code lives

```text
src/cairn/
  core/          tri-state logic, evidence + evidence graph, verification levels, errors
  tools/         bounded subprocess runner, pinned tool manifest
  sparse/        AOSP sparse format parsing/validation, libsparse oracle
  adapters/      read-only fastboot transport (getvar, devices, probe) and probe capture (scrubbed transcripts + finding drafts)
  host/          Host Doctor: WSL/VM, USB, drivers, power policy, link soak
  package/       fastboot-info v1 parser, factory/OTA zip inspection
  plan/          read-only vendor-order planner, canonical plan hash
  provenance/    offline vendor hash index, AVB parser, AVB chain verification
  rollback/      rollback oracle plus vendor-specific device stored-index reader
  safety/        safety rule engine and override policy
  sim/           transcript schema, recorder/replayer, fault-injecting fastboot simulator
  wizard/        resumable read-only preflight stages, strict session persistence, rendering
  executor/      simulator-gated plan executor, hash-chained write-ahead journal
  recovery/      encrypted device-bound vault, SR-008/SR-009 asset checks, M6 drill
  vab/           Virtual A/B merge-state (SR-010), dynamic-partition mode (SR-011), snapshot flows, super metadata parser
```

Design notes, in the order the reader should meet them:

- **No command writes to a real device.** The only write-capable code paths are
  the transcript simulator (`cairn.executor` via `cairn execute`, and
  `cairn recovery restore|drill`), and every write is labelled `SIMULATED`, never
  device evidence. Real fastboot binaries are refused by the transport (ADR-027).
  That is deliberate: the M6 gate, its external reviews (KU-032), and the
  recovery drill come before a real-device write path exists.
- **Plans have two gates.** Structural planning proves only the vendor-order dry
  run is modeled; a separate SafetyReport must also allow proceeding. Missing
  evidence is shown as `UNKNOWN` and blocks rather than becoming a pass.
- **Tri-state everywhere.** `TRUE` / `FALSE` / `UNKNOWN` with the helpers in
  `core/tristate.py`. `UNKNOWN` blocks. `FALSE` blocks and is never overridable.
- **Evidence carries its provenance.** `core/evidence.py` gives every fact a
  source, observation time, freshness bound, boot ID, and a deterministic ID.
  `core/evidence_graph.py` refuses inferred or stale facts and invalidates
  pre-reboot facts after a reboot.
- **Errors are typed.** Every error derives from `cairn.core.errors.CairnError`
  and carries a stable `code` (for example `AVB_ERROR`, `SAFETY_ENGINE_ERROR`).

---

## 4. Command surface

| Command | Purpose | Exit codes |
| --- | --- | --- |
| `cairn version` | print the version | 0 |
| `cairn levels` | print the V0–V3 verification levels | 0 |
| `cairn doctor` | read-only host checks plus a bounded `getvar` link soak | 0/1/3 |
| `cairn probe` | read-only `getvar all` device probe; with `--capture DIR` it also records the §5 checklist getvars into a scrubbed transcript plus a finding draft (real device only, never with `--simulate`) | 0/1/2 |
| `cairn inspect PACKAGE` | read-only factory/OTA zip inspection, no extraction | 0/1 |
| `cairn provenance PACKAGE --index INDEX` | match a package against a local hash index | 0 TRUE / 1 FALSE / 3 UNKNOWN |
| `cairn plan PACKAGE --index INDEX` | read-only vendor-order dry run plus SR-001/002/003/004/012/013 safety report | 0 both structural and safety gates pass / 1 error / 3 blocked |
| `cairn wizard PACKAGE --index INDEX --state SESSION [--resume \| --force]` | resumable, read-only preflight: doctor, inspect, provenance, probe, AVB, rollback, plan, and optional approval verification | 0 only when every supplied stage and post-approval gate passes / 1 failed / 3 blocked or simulated |
| `cairn approval keygen --out KEY` | create a 32-byte approval consistency key (never a device write) | 0/1 |
| `cairn approval issue PACKAGE --index INDEX --key KEY --operator OP --reason TEXT --nonce NONCE (--fastboot PATH [--serial S] \| --device-fingerprint HEX)` | issue an HMAC-signed approval token after the pre-approval gate passes | 0/1/2/3 |
| `cairn approval verify TOKEN PACKAGE --index INDEX --key KEY --nonce NONCE (--fastboot PATH \| --device-fingerprint HEX)` | compare a token against the current plan, evidence snapshot, package, device, and tools | 0 TRUE / 1 FALSE / 2 usage / 3 UNKNOWN |
| `cairn approval issue --session SESSION ...` / `cairn approval verify TOKEN --session SESSION --key KEY` | issue only from a fresh `READY` session, or verify against a fresh `READY`/`CLEARED` session after package, index, entry-hash, and plan-hash reload | 0/1/2/3 |
| `cairn approval inspect TOKEN --key KEY` | verify and print a signed approval token | 0/1 |
| `cairn avb info IMAGE` | parse VBMeta headers and descriptors | 0/1 |
| `cairn avb digest IMAGE [--chain NAME=PATH]` | compute the AOSP VBMeta digest | 0/1/2 |
| `cairn avb verify IMAGE [--key KEY] [--chain NAME=PATH]` | verify signature and, with `--chain`, the chain of trust | 0 valid / 1 invalid / 3 unknown |
| `cairn avb key-check IMAGE [--key KEY] --lock-state STATE` | contextual expected-key check; inputs are caller-supplied, not device evidence | 0 TRUE / 1 FALSE / 3 UNKNOWN |
| `cairn rollback read [--fastboot PATH] [--serial SERIAL] [--simulate TRANSCRIPT]` | read vendor-reported stored rollback indexes with one read-only `getvar all` | 0 complete / 2 usage / 3 UNKNOWN |
| `cairn rollback check IMAGE [--chain NAME=PATH] [--stored LOCATION=VALUE] [--device]` | compare package rollback counters with caller-supplied or device-read stored values | 0 TRUE / 1 FALSE / 2 usage / 3 UNKNOWN |
| `cairn execute --state SESSION --simulate TRANSCRIPT --token TOKEN --key KEY (--nonce N --device-fingerprint HEX \| nothing for a probed session) [--journal PATH] [--staging-dir DIR]` | execute an approved, safety-gated plan in the transcript simulator only, with a write-ahead journal; real fastboot binaries are refused (ADR-027) | 0 complete / 1 failed / 2 usage / 3 blocked |
| `cairn recovery backup --partition P --asset IMG --out VAULT --product PR --serial-sha256 H --device-fingerprint H [--passphrase-file F]` | encrypt a critical partition image into a device-bound vault; raw serials are never accepted, only their sha256 (ADR-028) | 0 / 1 refused / 2 usage |
| `cairn recovery verify VAULT [--passphrase-file F]` | verify a vault's MAC and recorded plaintext hashes | 0 verified / 1 tampered or wrong passphrase |
| `cairn recovery restore VAULT --partition P --simulate TRANSCRIPT [--journal PATH] [--staging-dir DIR] --product PR --serial-sha256 H --device-fingerprint H [--passphrase-file F]` | restore a vault entry to its bound device identity in the simulator only; any other identity is REFUSED, never overridable (ADR-027, ADR-028) | 0 / 1 refused or failed / 2 usage / 3 simulator refused |
| `cairn recovery drill --partition P --asset IMG --expected-sha256 H --vault VAULT --last-resort TEXT --simulate TRANSCRIPT --other-serial-sha256 H --other-fingerprint H --product PR --serial-sha256 H --device-fingerprint H [--passphrase-file F] [--json]` | run the M6 drill: verify, back up, restore same-device, refuse cross-device; the report is labelled SIMULATED and is not device evidence | 0 drill TRUE / 1 drill FAILED / 2 usage |
| `cairn vab status [--fastboot PATH] [--serial S] [--simulate TRANSCRIPT]` | read-only `getvar snapshot-update-status` and SR-010 merge-state verdict: `none` passes, a mid-merge state is a never-overridable FALSE, anything unrecognized is UNKNOWN | 0 TRUE / 1 FALSE / 2 usage / 3 UNKNOWN |
| `cairn vab dynpart --mode fastbootd\|bootloader [--fastboot PATH] [--serial S] [--simulate TRANSCRIPT]` | read-only SR-011 mode check: three getvars (`is-userspace`, `dynamic-partition`, `super-partition-name`) are compared with the job's required mode; a fastbootd job from the bootloader is FALSE, unreadable facts are UNKNOWN | 0 TRUE / 1 FALSE / 2 usage / 3 UNKNOWN |
| `cairn vab cancel --simulate TRANSCRIPT --acknowledgment TEXT --recovery-asset IMG --recovery-sha256 H --last-resort TEXT [--json]` | cancel an in-progress snapshot: exact typed acknowledgment, verified recovery assets, stated last-resort path, and a matching merge state are all required; simulator only (ADR-027) | 0 / 1 refused or failed / 2 usage / 3 simulator error |
| `cairn vab merge --simulate TRANSCRIPT --acknowledgment TEXT --recovery-asset IMG --recovery-sha256 H --last-resort TEXT [--json]` | merge an in-progress snapshot: same gates as cancel, but the merge state must be `merging`; simulator only (ADR-027) | 0 / 1 refused or failed / 2 usage / 3 simulator error |

Exit code constants: `EXIT_OK=0`, `EXIT_FAILED=1`, `EXIT_USAGE=2`, `EXIT_UNKNOWN=3`.
Every command supports `--json` where structured output makes sense.

---

## 5. The AVB trust ladder

This is the single most important section for anyone touching AVB code. The
ladder is ordered by strength, and each rung proves strictly less than the one
below it. **Do not let a higher rung's wording leak into a lower rung's output.**

| Rung | Command | What it actually proves | What it does **not** prove |
| --- | --- | --- | --- |
| 1. Parsed | `avb info` | the bytes are a structurally valid VBMeta | anything about authenticity |
| 2. Digest | `avb digest` | byte-identity of VBMeta blobs, matching AOSP | anything about authenticity |
| 3. Embedded-key signature | `avb verify IMAGE` | the image is internally self-consistent | that the image came from the vendor |
| 4. Chain of trust | `avb verify IMAGE --chain boot=boot.img` | the chain is internally coherent end to end | that the top-level key belongs to the device |
| 5. Expected / device-bound key | `avb verify IMAGE --key known.avbpubkey` | the image is signed by a key we already trust | — |
| 6. Device-bound lock/key anchor | *not implemented* | the key is bound to this device | — |

Rungs 1–4 are implemented. Rung 5 is implemented only when the caller supplies an
expected key file, and it is still only as strong as that file. `avb key-check`
adds a caller-supplied lock-state context: invalid signatures and locked mismatches
are FALSE; unsigned images, missing keys, unknown state, and unlocked mismatches
are UNKNOWN. It is useful offline diagnosis, not a new trust rung, because neither
the lock state nor the key is read from the device. Rung 6 remains the missing
piece and is tracked as KU-029.

Additional AVB facts that the implementation encodes:

- The VBMeta signature covers the 256-byte header plus the auxiliary block. The
  digest is stored in the authentication block; the signature is a raw RSA
  PKCS#1 v1.5 signature over the DigestInfo and digest.
- The AVB public key blob is `num_bits`, `n0inv`, modulus, `rr`. The exponent is
  fixed at 65537.
- A chain descriptor names a partition, a rollback index location, and the public
  key that signed the chained partition. The descriptor's location must be
  non-zero; the chained VBMeta header's own location must be zero.
- An unsigned VBMeta (`algorithm NONE`) is `UNKNOWN`, never valid, and can never
  satisfy an expected-key check.

### Chain verification semantics

`verify_vbmeta_chain` is tri-state and fail-closed:

- Top-level signature invalid → `FALSE`.
- Top-level unsigned → `UNKNOWN`.
- Chained image not supplied → `UNKNOWN`.
- Chain descriptor key ≠ chained image's embedded key → `FALSE`.
- Chained signature invalid → `FALSE`.
- Descriptor rollback location is zero → `FALSE`.
- Chained header rollback location is non-zero → `FALSE`.
- Chain cycle → `FALSE`.
- Chain depth above the limit (default 8) → `FALSE`.
- Nested chains combine recursively.

Overall precedence is `FALSE` > `UNKNOWN` > `TRUE`. A `TRUE` chain result means
"internally consistent", never "trusted", unless the top-level key was compared
against an expected key.

### Rollback Oracle semantics

`evaluate_avb_rollback` and `cairn rollback check` answer a narrower question:
can this package lower a rollback counter? The inequality is AOSP's
`rollback_index[n] >= stored_rollback_index[n]` for every location `n`.

- The top-level VBMeta contributes `avb:main` at its own location.
- Each chain descriptor contributes `avb:<partition>` at the descriptor's
  location, carrying the chained image's rollback index. Nested chains are
  followed with a depth limit.
- Stored indexes come from the caller (`--stored`) or from a read-only
  `fastboot getvar all` with `--device`. A missing stored index is `UNKNOWN`,
  never `TRUE`.
- `cairn rollback read` parses the observed vendor forms
  `stored_rollback_index:<location> = <value>` and
  `avb_stored_rollback_indexes:<location>:<value>`. Values are decimal, `0x` hex,
  or bare hex containing `A-F`; all-digit values are decimal.
- Duplicate identical locations are accepted once. Conflicting, empty, malformed,
  out-of-range, absent, truncated, or failed reads are unresolved and therefore
  `UNKNOWN`. `--device` and `--stored` are mutually exclusive.
- OEM anti-rollback signals such as `ap-ar-s` are reported as warnings and are
  never mapped to AVB locations. A `TRUE` verdict covers only the AVB counters
  that were evaluated; OEM policy remains unknown.
- Package below stored -> `FALSE`; package at or above stored -> `TRUE`.
- An unreadable image or chain is `UNKNOWN`, never `FALSE`; a parse error is not
  evidence of a downgrade.
- Without a stored value, a catalog upper bound can prove safety, a catalog lower
  bound can prove a downgrade, and an inconclusive bound leaves `UNKNOWN`.
- `FALSE` and `UNKNOWN` are hard stops for SR-004; neither is overridable.
- Chain images are parsed for counters, not signature-checked. SR-003 must pass
  separately before the counters are trusted.

### Executor semantics

`cairn.executor` is the first module with write verbs, and it cannot reach real
hardware: the only transport that can issue flash/erase/reboot/update-super is
`SimulatedFastbootTransport`, built exclusively from a transcript replay; a real
fastboot binary raises `EXECUTOR_REFUSED` (ADR-027). `cairn execute` therefore runs
approved plans end to end with every output labelled `SIMULATED`, never device
evidence, and the result verdict is at most `TRUE` for "the simulation completed".

- **Gates.** Plan hash must verify and the plan must be executable; the safety
  verdict must not be FALSE (FALSE is never overridable); the approval token must
  verify TRUE against the reloaded plan, package, entry hashes, and device binding.
  UNKNOWN safety verdicts execute only because the transport is the simulator.
- **TOCTOU guard.** Every flashed image is extracted from the package and re-hashed
  against the approval bundle immediately before staging; a byte mismatch refuses
  the run and deletes the staged file.
- **Journal.** Append-only JSONL, one fsync per record, SHA-256 hash chain from a
  genesis record. Loading tolerates a torn final line (reported, then truncated on
  resume) and refuses mid-chain corruption. The journal is tamper-evident, not
  tamper-proof.
- **Idempotency and resume.** FLASH, ERASE, and UPDATE-SUPER are idempotent and are
  re-run when found STARTED without DONE. REBOOT is non-idempotent: an interrupted
  reboot aborts the resume with the plan's stop-and-reprobe fallback and requires a
  fresh preflight, because a reboot invalidates pre-reboot evidence. A step recorded
  as FAILED is never retried automatically.
- **Crash harness.** `tests/test_executor.py` kills execution after every journal
  record and proves each resume reaches exactly the uninterrupted final device
  state; the interrupted-reboot point must abort, not complete.

---

## 6. What is deliberately not claimed

These statements are enforced in code and in output text. Do not weaken them.

- Parsing a VBMeta successfully is **not** verification (ADR-018).
- A valid embedded-key signature is **not** trust (ADR-019).
- A coherent chain is **not** a trust anchor without an expected key (ADR-020).
- `avb key-check` takes caller-supplied lock state and trusted-key inputs; it is
  not device evidence and cannot satisfy SR-013 (ADR-023, KU-029).
- An approval token is a consistency boundary, not an authorization boundary. It
  binds a plan, an evidence snapshot, a package, a device, and tool identities, but
  it does not defend against a compromised host and the HMAC key is a per-session
  consistency key, not a security secret (ADR-014, ADR-025).
- A rollback comparison without `--device` uses caller-supplied stored indexes.
  With `--device`, the stored indexes are a vendor-specific device claim, not AVB
  verification; absence, conflict, or a failed read is `UNKNOWN` (ADR-021,
  ADR-022, KU-030).
- A rollback comparison does **not** verify chain signatures; SR-003 is separate.
- An OEM anti-rollback signal is **not** an AVB stored index, and this repository
  does not map one to the other.
- A local hash index match is **not** a signature or authenticity check (ADR-016).
- A simulated transcript is **not** device evidence; it is recorded with
  `EvidenceSource.INFERRED`.
- Fastboot generally tops out at **V1**. There is no generic partition read-back
  in the fastboot protocol; AOSP `fetch` is restricted to `vendor_boot` on
  debuggable, unlocked devices. The tool says so instead of pretending otherwise.
- `UNKNOWN` is a block, not a soft warning. Overrides never convert `UNKNOWN`
  into `TRUE`.
- An executor run is `SIMULATED` by construction and never device evidence; a
  completed simulation is not a flashed device (ADR-027).

---

## 7. Fixtures and oracles

Every AVB fixture is generated by AOSP `avbtool` 1.3.0 from the pinned research
tree (`external/avb`, commit `c66af46cc55138dd6ee70b51cbeb4501b83d23ec`), so the
tool is checked against upstream behaviour rather than against our own
expectations. Generation commands and hashes are in
[`tests/fixtures/avb/README.md`](../tests/fixtures/avb/README.md).

| Fixture | Bytes | SHA-256 | Proves |
| --- | --- | --- | --- |
| `tests/fixtures/avb/unsigned_vbmeta.img` | 384 | `df3d0b84fce2abbf0ebdcebbec571cbc2d4b089dca88cf3ab8214c610059b405` | header and descriptor parsing, algorithm `NONE` |
| `tests/fixtures/avb/signed_vbmeta.img` | 1216 | `f92fdbd4ce4cd1ee3178d1ff70d16e098c30776cb987bc9d4785f42d1428c160` | signature verification, `SHA256_RSA2048` |
| `tests/fixtures/avb/signed_vbmeta.avbpubkey` | 520 | `30ea9460353fd77b178f1a939dfd0e59aa0f0aa983c622b6ae74c445349f2e28` | expected-key comparison |
| `tests/fixtures/avb/signed_boot.img` | 131072 | `33c3d2c531988a99ffcf9fd1bd12aadf1dad75f3ee62ec98684428f6bdbecb31` | AVB footer parsing; digest matches AOSP `5ce1e977…` |
| `tests/fixtures/avb/chain/vbmeta.img` | 1728 | `6429beddcf514e17235ba72fa3bc47558495d0d313aa7231c6070560f8dbf4c1` | top-level VBMeta with a `boot` chain descriptor at location 3 |
| `tests/fixtures/avb/chain/boot.img` | 131072 | `33c3d2c531988a99ffcf9fd1bd12aadf1dad75f3ee62ec98684428f6bdbecb31` | chained partition signed by the chain key |
| `tests/fixtures/avb/chain/top.avbpubkey` | 520 | `984eaad7d57d566dc2ad0f3e233e160d41f322fac9adb12406c98688cc2e3679` | expected top-level key |
| `tests/fixtures/avb/chain/boot.avbpubkey` | 520 | `30ea9460353fd77b178f1a939dfd0e59aa0f0aa983c622b6ae74c445349f2e28` | chain key named by the descriptor |

Chain fixture digest oracle: AOSP `avbtool calculate_vbmeta_digest --image
chain/vbmeta.img` reports
`4718daa501cd42cf97865a46b45cf52b205cd6f0a45a09f46c2a95363df9fb83`, and
`cairn avb digest --chain boot=boot.img` must produce the same value.

The private keys behind these fixtures are throwaway and deliberately not
committed.

Other fixtures: `tests/fixtures/fastboot/pixel8_getvar_all.json` (synthetic
`getvar all` transcript), `tests/fixtures/fastboot/legion_y700_stored_indexes.json`
and `tests/fixtures/fastboot/pixel2_stored_indexes.json` (synthetic vendor
stored-index transcripts with fabricated values), and
`tests/fixtures/fastboot/fastboot-info.txt` (AOSP v1 grammar sample).

---

## 8. Environment facts for this host

Verified on this machine (Windows, PowerShell 5.1):

- Python 3.12+ is driven through `uv`. The project venv has no `Crypto` and no
  `cryptography`; all cryptography in `cairn` is pure Python stdlib.
- `openssl` 3.5.5 exists at `C:\Program Files\Git\mingw64\bin\openssl.exe` but is
  **not on `PATH`**. Call it by full path.
- AOSP `avbtool verify_image` cannot complete here: its `NamedTemporaryFile` /
  `openssl` handshake fails on Windows. Use `openssl pkeyutl -verifyrecover
  -pkeyopt rsa_padding_mode:none` for an independent raw-RSA check instead.
- `avbtool add_hash_footer` needs an explicit `--salt`, because `/dev/urandom`
  does not exist here.
- `avbtool --chain_partition` splits on `:`, so Windows absolute paths in that
  field break it. Run `avbtool` from inside the fixture directory and use a
  relative key path.
- The shell here does not apply a working directory to commands. Start every
  command with `Set-Location 'C:\Users\kkc36\cairn'`.
- AOSP source research copy: `C:\Users\kkc36\.zcode\workspace\default\research-aosp-fastboot`
  (`avbtool.py`, `avb-readme.md`, `src/`, `listing.json`).

---

## 9. Test and CI state

Local baseline at the time of writing:

```console
uv run ruff format --check .   # clean
uv run ruff check .            # clean
uv run mypy src                # clean
uv run pytest -q               # 609 passed, 6 skipped
```

The latest CI run is `46090782794` for the T21/T24 super-oracle slice merged
through pull request [#10](https://github.com/hassan200503/cairn/pull/10)
(merge `dc0ed9f`) and is green, including the lpmake differential job (10
passed, 0 skipped). The T22/T23 capture slice postdates that run; its CI run
must be green before merge. The 609-test baseline above was confirmed locally
on the T26 slice.

The six local skips are environmental, not gaps in coverage:

- `tests/test_package_archive.py` — `zipfile` normalizes backslashes to slashes
  on Windows, so the Windows-specific archive-name case is skipped there.
- `tests/test_sparse_oracle.py` — AOSP `libsparse` (`img2simg`/`simg2img`) is
  not installed locally. CI installs `android-sdk-libsparse-utils` and runs this
  oracle on Ubuntu, so the oracle is enforced there.
- `tests/test_super_meta.py` — the `lpmake` differential layer needs the
  oracle built from pinned AOSP source (`tools/oracle/build_lpmake.sh`); CI
  builds it in a dedicated Ubuntu job. The golden-fixture and negative tests
  run everywhere.

CI (`.github/workflows/ci.yml`) runs seven jobs on every push to `main`:

1. `Lint, format, and types` (ubuntu) — ruff check, ruff format check, mypy.
2. `Sparse oracle (AOSP libsparse)` (ubuntu) — installs libsparse, runs the oracle.
3. `Super oracle (AOSP lpmake from pinned source)` (ubuntu) — builds `lpmake`
   per `tools/oracle/PINNED.md`, runs the super-metadata differential tests.
4. `Test (ubuntu-latest, Python 3.12)`
5. `Test (ubuntu-latest, Python 3.14)`
6. `Test (windows-latest, Python 3.12)`
7. `Test (windows-latest, Python 3.14)`

The cloud Windows runners have no USB controllers, so the Host Doctor verdict
there is legitimately `FALSE`. Integration tests assert on checks, never on a
host-dependent verdict.

Verify the latest run with:

```console
gh run list --branch main --limit 1 --json databaseId,headSha,status,conclusion
```

---

## 10. Known blockers

These are the reasons the remaining work cannot simply be "finished":

- **No hardware findings.** `docs/HARDWARE_FINDINGS.md` is empty. Every
  device-dependent claim is a hypothesis. G0 ("simulator replays a real
  transcript") is not fully met.
- **No real vendor packages.** T08 golden packages, T10 golden plans, and a T09
  real AVB/hash corpus are all missing. Every package-related fixture here is
  synthetic.
- **Nested factory image zips are reported but not opened** (KU-026). A real
  Pixel package may keep `fastboot-info.txt` inside the nested image zip.
- **Slot, retrofit, and commutation semantics are unmodeled** (KU-028), so
  `cairn plan --slot other` and `--retrofit-force` stay non-executable by design.
- **No generic device stored-index reader.** A vendor-specific reader now parses
  the observed `stored_rollback_index` and `avb_stored_rollback_indexes` forms, but
  AOSP fastboot has no standard variable, some SKUs need an EDL fallback, and the
  Pixel `ap-ar-s` OEM signal has no known AVB mapping. Devices without an observed
  variable stay `UNKNOWN` and SR-004 blocks (KU-030). No OEM counter policy ships
  yet.
- **No device-bound lock/key anchor.** `avb key-check` consumes caller-supplied
  inputs only; rung 6 remains unimplemented (KU-029).
- **No catalog-bound safety preflight.** `cairn plan` now evaluates all six current
  safety rules, but it has only package provenance evidence; absent identity, AVB,
  rollback, tool, and lock/key facts remain UNKNOWN and it is therefore
  non-executable (KU-031).
- **No external review of the recovery vault.** The vault crypto and the M6
  drill have only this project's own review and tests; external sign-off is an
  explicit T15 acceptance condition (KU-032), and no real-device write may
  depend on the vault until it lands.
- **No real-device super image fixtures.** The official AOSP `lpmake` is now
  built from pinned source in CI (`tools/oracle/`), and the super-metadata
  parser is differentially tested against it (T21/T24, closing the KU-033
  tool gap). Real factory `super.img`/`super_empty.img` fixtures from actual
  devices are still missing, so vendor metadata variants remain unverified
  (KU-016).
- **No Pixel verifier oracle.** `pixel_factory_image_verify.py` has not been
  run against our output.
- **EDL, MediaTek, and Samsung backends** are research-only; no hardware, no
  vendor DA files, no legal review.

---

## 11. Next steps, in order

Each is a self-contained slice: implement, test, update the docs above, commit,
push, confirm CI green.

1. **T12 — Device stored-index reader.** The vendor-specific reader, `cairn
   rollback read`, and `cairn rollback check --device` have landed for the observed
   getvar forms. Remaining work: collect real scrubbed transcripts and hardware
   findings, decide whether an EDL fallback is in scope, and keep OEM counter
   policy out until it has a source. KU-030 stays open for the generic/OEM paths.
2. **T09 — Device-bound lock/key anchor.** The contextual `avb key-check` is
   implemented, but rung 6 still needs a fresh device lock-state observation and
   a hardware finding or catalog record that anchors the expected key.
3. **T11 — Wire the safety engine into the CLI.** `cairn plan` should evaluate
   all six current rules and refuses an executable result for any `FALSE` or
   un-overridden `UNKNOWN`. Remaining work is catalog-bound collection and binding
   of fresh identity, AVB, rollback, tool, and lock/key evidence (KU-031).
4. **T13 — Approval binding (landed).** `cairn approval keygen|issue|verify|inspect`
   bind the plan hash, evidence-snapshot hash, archive hash, every package entry
   hash, a device binding (nonce plus a probed or caller fingerprint), and tool
   identities, and enforce the result as rule SR-018. The binding is canonical JSON
   hashed to `binding_sha256` and HMAC-SHA256 signed under a per-session consistency
   key; any byte change in any bound input invalidates it. It is a consistency
   boundary, not an authorization boundary (ADR-014, ADR-025). The executor now
   enforces the token as a hard gate and re-verifies every staged image against the
   bound entry hashes at execution time (ADR-027). Remaining work is mutation
   testing of the binding and the safety rules.
5. **T14 — Journal and executor (landed, simulator-gated).** The hash-chained
   write-ahead journal, idempotency classes, reconcile-on-resume, and the
   crash-at-every-journal-point harness are in `cairn.executor`, wired to the CLI as
   `cairn execute` (ADR-027). Every write verb reaches the transcript simulator
   only; a real fastboot binary is refused. The T26 slice added the journal
   growth policy (a journal nearing its 32 MiB limit is rotated at resume time
   to a verified continuation chain — `.r1`, `.r2`, … files whose session
   records chain to the predecessor's head hash; predecessors are kept as
   evidence) and pre-write slot/VAB reconciliation: before the first write the
   executor reads `snapshot-update-status` and `current-slot` through the
   transport's read-only seam, journals a `reconciled` record, and aborts on a
   mid-merge state (SR-010 FALSE; UNKNOWN is journaled as a warning in the
   simulator-only executor). Remaining work: the real-device transport (blocked
   behind T15 and the M6 gate).
6. **T15 — Recovery Kit and the M6 gate (landed, simulator-only).** The threat
   model (`docs/RECOVERY_THREAT_MODEL.md`), the SR-008 asset-verification and
   readiness checks, the encrypted device-bound vault with
   restore-only-same-device enforcement, and the `cairn recovery
   backup|verify|restore|drill` CLI are in `cairn.recovery` (ADR-028). The drill
   proves the same-device round trip and the cross-device refusal in the
   simulator. Remaining work before the M6 gate opens a real-device transport:
   external crypto review of the vault and external safety review of the drill
   (KU-032), real scrubbed transcripts and hardware findings, and the Virtual
   A/B / dynamic-partition state machines.
7. **T16 — Virtual A/B merge-state gate (landed).** `cairn.vab` reads
   `snapshot-update-status` with one read-only getvar and classifies it
   tri-state: `none` passes, `snapshotted`/`merging`/`merge_pending` are a
   never-overridable FALSE, and unrecognized vendor values or a FAIL are
   UNKNOWN that blocks (KU-004 stays open for vendor variants). The gate is
   wired into the safety engine as rule SR-010 and exposed as the read-only
   `cairn vab status` command (real device or transcript replay). Remaining
   work: the super/dynamic-partition metadata state machine (SR-011), and
   explicit operator-approved merge/cancel flows modeled as plans — cairn
   never auto-cancels.
8. **T17 — Dynamic-partition mode gate (landed).** `cairn.vab.dynpart`
   reads `is-userspace`, `dynamic-partition`, and `super-partition-name`
   with three read-only getvars and evaluates the job's required mode
   (`--mode fastbootd|bootloader`): a fastbootd job from the bootloader is a
   never-overridable FALSE, a bootloader job on a dynamic device is UNKNOWN
   with warnings (retrofit force and logical targeting are unmodeled), and
   unreadable facts are UNKNOWN that blocks. The gate is safety-engine rule
   SR-011 (blocking; UNKNOWN is typed-overridable, FALSE is not overridable)
   and the read-only `cairn vab dynpart` command. Remaining work: real super
   metadata parsing (lpunpack/lpmake oracles) and modeled merge/cancel
   flows.
9. **T18 — Modeled snapshot cancel/merge flows (landed, simulator-only).**
   `cairn.vab.flows` gates `cairn vab cancel|merge` behind: a merge state
   that matches the flow's precondition (cancel needs `snapshotted` or
   `merging`; merge needs `merging`; `none` refuses with "nothing to act
   on"), an exact typed acknowledgment sentence, verified recovery assets
   and a stated last-resort path (SR-008), and a transcript-replay
   transport (ADR-027). The executor gained the `snapshot-update`
   PlanAction for the modeled argv. Cairn never auto-cancels; no real
   device can be targeted. Remaining M6 work: super metadata parsing
   oracles, and the external reviews (KU-032).
10. **T19 — Safety-rule mutation harness (landed).** `tools/mutation_check.py`
    wraps each registered rule's evaluator with three mutants (`always-true`,
    `unknown-true`, `false-true`) at its `DEFAULT_RULES` registration site and
    runs the safety-relevant test files in a subprocess per mutant. The
    recorded run killed **33/33 mutants** across all 11 registered rules,
    satisfying the AGENTS.md "three suite-killed mutants per safety rule"
    requirement for the current rule set. Run it after any change to rule
    logic (`python tools/mutation_check.py`, ~3 minutes, on demand — not in
    the default CI loop).
11. **T20 — Approval-binding mutation tests (landed).** The mutation harness
    gained an `approval` family over `approval/token.py`, `binding.py`, and
    `device.py`: skipped bound-field comparisons (plan, evidence snapshot,
    archive, device, package hashes, tools), a verdict-flip on parse failure,
    neutered signature/binding-hash/key-id checks, a dropped `binding_payload`
    field, disabled hex64 validation, a dropped required fingerprint fact, and
    stale required facts accepted. The first run exposed a real gap — no test
    pinned the `archive_sha256` comparison — now killed by
    `test_verify_is_false_when_the_archive_hash_changed`. Recorded run:
    **48/48 mutants killed** (33 rule + 15 approval).
12. **T21 — Super metadata parser (landed, with the T24 oracle).** The
    official AOSP `lpmake` host tool is built from pinned source
    (`tools/oracle/build_lpmake.sh`, pins in `tools/oracle/PINNED.md`) in a
    dedicated CI job, closing the KU-033 tool gap. `cairn.vab.super_meta`
    parses both on-disk layouts — full super images (geometry at 4096,
    primary/backup metadata copies) and empty supers (`lpmake
    --device-size auto`, metadata at 4096) — with strict validation: geometry
    and header and table checksums, version bounds, table bounds and entry
    sizes, name charset and uniqueness, attribute mask, extent target
    validation. Any anomaly raises `SuperMetadataError`, which callers must
    treat as UNKNOWN. Tests: a golden fixture generated by the oracle with a
    pinned SHA-256, differential tests against fresh oracle output (full
    image, super-empty, slot-suffixing; run in CI, skipped locally), and
    negative checksum/truncation tests. Remaining work: wire the parsed
    layout into a rule or the planner (it must never feed a write decision
    until its differential coverage is CI-enforced, which it now is), and
    real-device `super.img` fixtures (KU-016). The executor's TOCTOU re-hash
    guard was re-checked and is covered by
    `test_execute_refuses_image_that_changed_after_approval` and the
    not-covered-by-binding test.
13. **T22/T23 — Real-transport review folded into probe capture (landed).**
    The T22 review concluded that `cairn.adapters.fastboot` already covers the
    verb surface through `ToolRunner`, so the missing M6 input is evidence, not
    transport code. `cairn probe --capture DIR` now runs `getvar all` plus the
    `HARDWARE_FINDINGS.md` §5 checklist against a real device, records every
    invocation in a transcript, scrubs serials (scrubbing raises rather than
    letting one through), and writes a finding-template draft next to the
    transcript with its SHA-256. It refuses `--simulate` combinations; no write
    verb is ever recorded. Remaining work: run it on real devices and promote
    the results through the finding process (KU-033's hardware half), the
    external reviews (KU-032), and the executor's journal growth policy and
    slot/VAB reconciliation.

The **guided session orchestrator** (`cairn wizard`) landed as the M11 spine in
front of T14. It persists an atomically written, byte-bounded, strict JSON session
with a canonical state hash and no raw serial or transcript. Its read-only stages
are doctor → inspect → provenance → probe → AVB → rollback → plan → approval. It
reuses only fresh successful doctor, probe, and rollback observations with matching
input fingerprints; it reloads package and index bytes before a session-based
approval is issued or verified. A simulated transcript is explicitly `SIMULATED`,
not device evidence. The wizard adds no trust rung, performs no device write, and
cannot turn missing catalog/device facts into a pass. `READY` therefore remains
unreachable until the existing device-bound/canonical-preflight unknowns are
resolved; this is intentional fail-closed behavior, not a wizard defect.

---

## 12. Working agreements

- One slice, one commit, one green CI run. Documentation travels with the code.
- Before writing code for a behavior, check `KNOWN_UNKNOWNS.md` for that exact
  behavior. If it is an unknown, the code must return `UNKNOWN`, not a guess.
- When a fixture is needed, generate it with the upstream tool, record the exact
  command and the SHA-256 in the fixture README, and add an oracle assertion
  against upstream output.
- Never widen a verification claim in output text without the corresponding
  evidence. The wording in `docs/SAFETY_RULES.md` is deliberately conservative.
- Keep the required commands green before pushing:
  `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`,
  `uv run pytest -q`.
- Update this file in the same commit as the change it describes.
