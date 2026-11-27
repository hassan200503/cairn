# Current State

**This is the canonical snapshot of where Cairn stands.** It exists so that whoever
picks this repository up next — a human, or an AI model with no memory of the
session that built it — can tell what is real, what is proven, what is still a
hypothesis, and what the next slice should be, without guessing and without
inventing anything.

Everything here is verifiable against the repository. If a claim in this file
cannot be checked from the code, the tests, the fixtures, or a cited source, it
does not belong here; it belongs in [`KNOWN_UNKNOWNS.md`](KNOWN_UNKNOWNS.md).

**Last updated:** 2026-11-26, after the safety-gated plan slice.

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
  adapters/      read-only fastboot transport (getvar, devices, probe)
  host/          Host Doctor: WSL/VM, USB, drivers, power policy, link soak
  package/       fastboot-info v1 parser, factory/OTA zip inspection
  plan/          read-only vendor-order planner, canonical plan hash
  provenance/    offline vendor hash index, AVB parser, AVB chain verification
  rollback/      rollback oracle plus vendor-specific device stored-index reader
  safety/        safety rule engine and override policy
  sim/           transcript schema, recorder/replayer, fault-injecting fastboot simulator
```

Design notes, in the order the reader should meet them:

- **Everything is read-only so far.** No command in this repository writes to a
  device. `cairn plan` is a dry run. That is deliberate: the M6 gate and the
  recovery drill (T15) come before any write path exists.
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
| `cairn probe` | read-only `getvar all` device probe | 0/1 |
| `cairn inspect PACKAGE` | read-only factory/OTA zip inspection, no extraction | 0/1 |
| `cairn provenance PACKAGE --index INDEX` | match a package against a local hash index | 0 TRUE / 1 FALSE / 3 UNKNOWN |
| `cairn plan PACKAGE --index INDEX` | read-only vendor-order dry run plus SR-001/002/003/004/012/013 safety report | 0 both structural and safety gates pass / 1 error / 3 blocked |
| `cairn approval keygen --out KEY` | create a 32-byte approval consistency key (never a device write) | 0/1 |
| `cairn approval issue PACKAGE --index INDEX --key KEY --operator OP --reason TEXT --nonce NONCE (--fastboot PATH [--serial S] \| --device-fingerprint HEX)` | issue an HMAC-signed approval token after the pre-approval gate passes | 0/1/2/3 |
| `cairn approval verify TOKEN PACKAGE --index INDEX --key KEY --nonce NONCE (--fastboot PATH \| --device-fingerprint HEX)` | compare a token against the current plan, evidence snapshot, package, device, and tools | 0 TRUE / 1 FALSE / 2 usage / 3 UNKNOWN |
| `cairn approval inspect TOKEN --key KEY` | verify and print a signed approval token | 0/1 |
| `cairn avb info IMAGE` | parse VBMeta headers and descriptors | 0/1 |
| `cairn avb digest IMAGE [--chain NAME=PATH]` | compute the AOSP VBMeta digest | 0/1/2 |
| `cairn avb verify IMAGE [--key KEY] [--chain NAME=PATH]` | verify signature and, with `--chain`, the chain of trust | 0 valid / 1 invalid / 3 unknown |
| `cairn avb key-check IMAGE [--key KEY] --lock-state STATE` | contextual expected-key check; inputs are caller-supplied, not device evidence | 0 TRUE / 1 FALSE / 3 UNKNOWN |
| `cairn rollback read [--fastboot PATH] [--serial SERIAL] [--simulate TRANSCRIPT]` | read vendor-reported stored rollback indexes with one read-only `getvar all` | 0 complete / 2 usage / 3 UNKNOWN |
| `cairn rollback check IMAGE [--chain NAME=PATH] [--stored LOCATION=VALUE] [--device]` | compare package rollback counters with caller-supplied or device-read stored values | 0 TRUE / 1 FALSE / 2 usage / 3 UNKNOWN |

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
uv run pytest -q               # 501 passed, 2 skipped
```

The latest CI run is `45951665085` for `e358aea` on pull request
[#1](https://github.com/hassan200503/cairn/pull/1) and is green: lint, format, and
types; the AOSP libsparse sparse oracle; and tests on Ubuntu and Windows under
Python 3.12 and 3.14. That run covers the AVB key-check slice (`58c03a8`) and the
approval-binding slice (`e358aea`), neither of which had run in CI before. The
501-test baseline above was confirmed locally on the same slice.

The two local skips are environmental, not gaps in coverage:

- `tests/test_package_archive.py` — `zipfile` normalizes backslashes to slashes
  on Windows, so the Windows-specific archive-name case is skipped there.
- `tests/test_sparse_oracle.py` — AOSP `libsparse` (`img2simg`/`simg2img`) is
  not installed locally. CI installs `android-sdk-libsparse-utils` and runs this
  oracle on Ubuntu, so the oracle is enforced there.

CI (`.github/workflows/ci.yml`) runs six jobs on every push to `main`:

1. `Lint, format, and types` (ubuntu) — ruff check, ruff format check, mypy.
2. `Sparse oracle (AOSP libsparse)` (ubuntu) — installs libsparse, runs the oracle.
3. `Test (ubuntu-latest, Python 3.12)`
4. `Test (ubuntu-latest, Python 3.14)`
5. `Test (windows-latest, Python 3.12)`
6. `Test (windows-latest, Python 3.14)`

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
   boundary, not an authorization boundary (ADR-014, ADR-025). Remaining work is
   mutation and TOCTOU tests and CLI-to-safety-engine wiring inside the executor.
5. **T14 — Journal and executor.** Write-ahead journal, idempotency classes,
   reconciliation, and a crash harness that kills at every journal point. This
   is the first slice that may write, and it is still gated behind simulator
   execution until T15 completes.
6. **T15 — Recovery Kit and the M6 gate.** Threat model, recovery asset
   verification, encrypted device-bound vault design, restore-only-same-device
   rule, and a recovery drill script.

The **guided session orchestrator** (`cairn wizard`) is the next slice, in front of
T14 as the M11 spine: one resumable, fail-closed, read-only flow that chains
doctor → probe → inspect → provenance → AVB → rollback → plan → approval and
explains each step with its verification level. It writes no device and adds no
new trust rung; it makes the existing read-only primitives usable by a technician
and is the substrate the future write path will hang from.

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
