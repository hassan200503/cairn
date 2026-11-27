# Cairn v2 Specification

**Status:** Draft 2.0, 2026-11-24
**Supersedes:** Flashwright Engineering Spec v1.0
**Owner:** Hassan Tsuma
**Review basis:** the Flashwright v1 review, plus source checks recorded in
[RESEARCH_NOTES.md](RESEARCH_NOTES.md).

> Cairn (n.): a stack of stones that marks a proven path across uncertain ground.
> Every flash leaves a cairn behind: evidence of where you have been and how to get
> back.

This document is normative for the v2 build. Where it disagrees with v1, v2 wins.
Where a device-dependent claim lacks a source tag or a hardware finding ID, it is a
hypothesis, not a rule. Every safety rule must cite a source and be mutation-tested.

---

## 1. Product contract

### 1.1 The promise

Cairn is a fail-safe Android flashing workbench. It does not promise that nothing
can go wrong. It promises:

1. **Refuse before write.** An unsafe job is blocked before the first write, with a
   named rule and the evidence that failed.
2. **Verified at a stated level.** Every write is reported at V0, V1, V2, or V3.
   The word "verified" never appears without a level.
3. **Known state after interruption.** Every operation is journaled before and after
   it runs. An interrupted job can resume, roll back, or be classified into a state
   with a documented recovery path.
4. **Recovery before risk.** Before a bootchain write on a device without a safe A/B
   path, the recovery assets and the last-resort path are checked.
5. **No hidden uncertainty.** `UNKNOWN` blocks by default. Overrides are explicit,
   typed, sourced, logged, and visible in the report header.

### 1.2 Non-goals (unchanged from v1)

Cairn will never include:

- FRP bypass;
- IMEI changes;
- carrier-lock circumvention;
- loader authentication bypass;
- signature-check defeat;
- cross-device transplant of user data or calibration.

Restoring a device's own backed-up data to that same device is allowed. Restoring it
to a different device is not.

### 1.3 Measurable goals

These are release gates, not marketing claims. Publish the measured numbers per
device tier.

| Metric | Definition | Target |
| --- | --- | --- |
| Refuse-before-write | Unsafe jobs in the labeled corpus blocked before the first write | 100% |
| Known-state | Interrupted or failed jobs ending in a named state with a documented recovery | > 99.9% on Verified devices |
| Unrecoverable-state | Jobs requiring hardware repair, per 10,000 jobs | Ceiling per tier; release fails if exceeded in lab |
| Resume success | Crash-injected jobs reaching the same final state as an uninterrupted run | 100% in simulator; tracked on hardware |
| Mean time to recover | Time from classified failure to known state | Measured and reported per failure class |
| Bare "verified" | Output containing "verified" without a level | 0 |

---

## 2. Normative corrections to v1

### 2.1 Sparse format constants

v1 scrambled the constants. The AOSP values are:

| Item | Value |
| --- | --- |
| File magic | `0xED26FF3A` |
| Raw chunk | `0xCAC1` |
| Fill chunk | `0xCAC2` |
| Don't-care chunk | `0xCAC3` |
| CRC32 chunk | `0xCAC4` |
| File header size | 28 bytes |
| Chunk header size | 12 bytes |

The parser MUST be differentially tested against AOSP libsparse (`simg2img` and
`img2simg`) as the oracle. A parser change without an oracle test does not merge.
The constants live in `src/cairn/sparse/format.py` with a test that pins each value.

Source: AOSP `system/core/libsparse/sparse_format.h` [AOSP-SPARSE].

### 2.2 AVB chain of trust

The v1 rule "every image hash is present in the vbmeta being flashed" is wrong for
AVB 2.0. A VBMeta struct can contain:

- **hash descriptors** for small partitions (for example `boot`);
- **hashtree descriptors** for large partitions (`system`, `vendor`, and similar),
  carrying a root hash, salt, and tree geometry rather than a whole-image hash;
- **chain partition descriptors** that delegate to another VBMeta image (for
  example `vbmeta_system`), with its own key, footer, and rollback indexes.

The replacement rule:

1. Run `avbtool` verification with chain following over the whole package.
2. Compute the VBMeta digest and compare it to a vendor-published digest where one
   exists. AOSP ships `pixel_factory_image_verify.py` for Pixel 3 and later.
3. Read lock state. On a locked device the signing key must match the
   device-trusted key. On an unlocked device, a key mismatch is a warning, not a
   silent pass.
4. Record the verification result and tool version in the journal.

Exact `avbtool` flags are pinned in M2 against the AOSP version in use; the rule is
chain-following plus digest comparison, not a hand-rolled descriptor walk.

Until a device-specific lock-state probe and trusted-key binding have a hardware
finding or signed catalog source, an operator-supplied lock-state value is only
context for offline inspection. `cairn avb key-check` may compare that value and a
caller-supplied AVB key with a VBMeta signature, but its result is not device
evidence and cannot satisfy SR-013 or authorize a write.

Source: AOSP AVB 2.0 README [AOSP-AVB]. Lock-state handling is confirmed per device
by hardware finding.

### 2.3 Licensing

The v1 license audit had an error and an omission:

| Tool | License | Use |
| --- | --- | --- |
| Heimdall | MIT | Separate process; may be bundled with attribution |
| Thor (`Samsung-Loki/Thor`) | MPL-2.0 | Separate process; file-level copyleft, do not copy code into Cairn |
| `bkerler/edl` | GPL-3.0 | Separate process only |
| `bkerler/mtkclient` | GPL-3.0 | Separate process only |

The separate-process boundary remains mandatory for GPL-3.0 tools. It is not a
license workaround; it keeps Cairn's Apache-2.0 core clean and lets users replace
the tool. The license audit must confirm each tool at the pinned version.

Sources: [GH-HEIMDALL], [GH-THOR], [GH-EDL], [GH-MTKCLIENT].

### 2.4 Samsung backend

Heimdall is not a safe sole backbone for Samsung. It speaks the Odin 3/Thor protocol,
and independent implementations report device-specific failures and session-reuse
limits that Heimdall does not always handle. Thor itself warns that an Odin session
cannot be reused after closing it, so the device must be rebooted between sessions.

Design:

- A pluggable Samsung backend interface (Heimdall, Thor, official Odin variants).
- Backend selected per model by the signed catalog.
- Start with detect, validate, and dry-run only. No write path until the M9 gate.
- Treat Samsung maintenance mode as a precondition, not a detail (see 6.4).

Sources: [GH-THOR], [SAMSUNG-2026], [WIKI-ODIN].

### 2.5 Read-back is not generally available on fastboot

There is no generic partition read-back in the fastboot protocol. AOSP documents
`fetch`, but its own documentation restricts it:

- the device must be running a **debuggable** build;
- the device must be **unlocked** (boot state orange);
- the fetched partition must be **`vendor_boot`**;
- the requested size must fit within `max-fetch-size`.

That makes `fetch` unsuitable as general post-write verification on production,
locked devices. It can verify a `vendor_boot` write on an unlocked debug build, and
nothing more.

Rules:

- Default `read_back` capability to `UNKNOWN` for the fastboot family.
- Probe at runtime: `getvar max-fetch-size`, then a small bounded `fetch` test; the
  probe may only lower the capability, never raise it.
- A fastboot device tops out at **V1** for general partitions. Do not plan read-back
  verification for fastboot.
- Catalog entries state the maximum verification level reachable for a device/job.
- V2 requires EDL, MediaTek read-back, or the narrow `vendor_boot` `fetch` case.

Source verification (2026-11-25): fastbootd's allowlist is exactly `vendor_boot`,
`vendor_boot_a`, `vendor_boot_b`; fetch is compiled out on user builds, refuses a
locked device, and caps the request at `kMaxFetchSizeDefault = 0x10000000`
(256 MiB). The host fetches in `max-fetch-size` chunks. See [AOSP-FASTBOOT-SRC].

Sources: [AOSP-FASTBOOTD], [AOSP-FASTBOOT-SRC]. The exact constraints are in the
code; availability remains a per-device hardware finding.

### 2.6 Post-wipe adb fingerprint checks

After `userdata` is wiped, USB debugging is off. A fingerprint check over adb is
therefore unavailable for the most common restore-with-wipe job.

Replacement V3 signals, in order of preference:

1. Bootloader signals after returning to the bootloader: `current-slot`,
   `slot-successful:<slot>`, `slot-unbootable:<slot>`, `slot-retry-count:<slot>`.
2. A user-confirmed first boot with a device-specific instruction.
3. adb fingerprint only when the job did not wipe userdata and adb is known enabled.

The report states which signal was used. "Booted successfully" is never inferred
from a timeout or a missing error.

### 2.7 A/B rollback language

The v1 "rollback guarantee" is overstated. The defensible promise is:

> **The previous slot is left untouched until commit.**

Corollaries:

- Virtual A/B snapshot and merge state must be modeled. A merge in progress changes
  what flashing is allowed.
- AVB stored rollback indexes can be raised once a newer image boots. The old slot
  may then no longer boot. Catalog entries record when indexes are updated and
  whether a downgrade is allowed.
- Wiping userdata and then falling back to the old slot is not a clean rollback.
- Bootloader-chain partitions are not always A/B.
- The slot flip is one commit operation, but it is not a universal undo button.

### 2.8 Planner order

Exact DP over a dozen groups is cheap, but the order is mostly forced. The
vendor-tested order (`fastboot-info.txt`, factory flash scripts) is itself a safety
asset. AOSP documents the baseline: the bootloader flashes bootloader, radio, and
boot partitions, then the device moves to userspace fastboot for the rest, and the
bootloader must refuse dynamic partitions.

Rules:

- Default: **vendor order is the baseline.**
- Deviate only where the catalog marks two groups commutative and a golden test
  proves equivalence.
- Optimize for risk and time, not only reboot count.
- Include the retrofit-dynamic-partition case: flash in the bootloader with the
  vendor force mode.
- The report shows the vendor baseline and every deviation with its justification.

Source: [AOSP-FASTBOOTD], vendor `fastboot-info.txt` files.

### 2.9 Resplitter scope

Official fastboot already resplits sparse images to the maximum download size.
Cairn needs its own resplitter only for:

- per-piece journaling;
- phase-2 native USB;
- pre-hashing pieces before transfer.

If per-piece resume is required while wrapping official fastboot, test early that
official fastboot accepts piece files (size checks, logical partition sizing). Do
not put a custom resplitter on the M1 critical path.

### 2.10 Approval signing

A per-session key held in the same process protects against bugs and TOCTOU drift,
not against a malicious local user with the same privileges. The spec says so.

Approval binds:

- the plan hash;
- the snapshot hash;
- every package content hash;
- a device-bound nonce;
- the tool versions used to produce the plan.

A mismatch is `FALSE` and blocks. The approval is not an authorization boundary
against a compromised host; it is a consistency boundary.

### 2.11 Battery threshold

Hard-coding 50% and 30% is a guess. AOSP's fastboot HAL includes a minimum flashing
battery voltage, and some devices expose battery getvars.

**Correction (2026-11-25):** fastbootd's `battery-soc-ok` compares
`battery-voltage` against the HAL's `getBatteryVoltageFlashingThreshold`; it is not
a state-of-charge percentage. `battery-soc` is the separate state-of-charge value
in the health HAL.

Rule:

1. Prefer `battery-soc-ok` when the device reports it: `yes` is `TRUE`, `no` is
   `FALSE`, and an unreadable variable is `UNKNOWN`.
2. Otherwise read `battery-voltage` and compare it with the device threshold where
   available.
3. `battery-soc` is a secondary signal, never the sole basis for a pass.
4. Fall back to the catalog/operator numbers only if the device exposes no usable
   voltage signal.
5. Record which source was used and the observed value in the journal and report.
6. A reading below the applicable threshold is `FALSE` and blocks.

Sources: [AOSP-FASTBOOTD], [AOSP-FASTBOOT-SRC]; exact getvar availability is a
per-device finding.

### 2.12 Official `flashall` is not a safe primitive

Source verification found two behaviors that contradict Cairn's promise if official
`flashall`/`update` is used as a black box:

1. Official `flashall` calls `set_active` **before** flashing. On an A/B device this
   marks the current slot active and clears `slot-unbootable` before any write, so
   the boot-control state is not left untouched until commit.
2. If `snapshot-update-status` is not `none`, official `flashall` automatically
   sends `snapshot-update:cancel`. AOSP's own help text warns that cancelling may
   make the device unbootable until reflashed.

Rules:

- Cairn's executor MUST NOT invoke `fastboot flashall` or `fastboot update` as an
  unexamined primitive. It drives explicit `flash`, `set_active`, `update-super`,
  and reboot operations so each is journaled and gated.
- `set_active` is a recorded operation with its own precondition and verification,
  not an implicit side effect.
- Cairn never cancels, merges, or otherwise resolves a snapshot/merge state
  automatically. It blocks (SR-010) and offers an explicit, typed flow.
- The defensible A/B promise remains: the **other slot's partition contents** are
  left untouched until commit. Boot-control flags are separate and are always
  journaled.

Source: [AOSP-FASTBOOT-SRC] (`FlashAllTool::Flash`, `CancelSnapshotIfNeeded`,
`set_active`).

---

## 3. Architecture

```text
CLI / Shop Mode / wizard (web later)
                |
        Orchestrator: sessions, journal, resume, reports, queue, opt-in telemetry
                |
        Strategy selector (native-path ladder)
                |
        Planner (vendor-order baseline + proven commutations)
                |
        Executor (transactional) <---- Approval (plan + package + snapshot + nonce)
                |
        Safety engine <--> Evidence graph <--> Signed catalog
                |
        Host Doctor | Recovery Kit + Vault | Provenance checker | Rollback Oracle
                |
        Adapters + Simulators (transcript-driven)
                |
        Transport (pinned official tools first; native USB after measurement)
```

### 3.1 Components

| Component | Responsibility |
| --- | --- |
| Evidence graph | Facts with source, observation time, freshness, and strength |
| Strategy selector | Chooses the least invasive path that satisfies the job |
| Planner | Vendor baseline, commutation proof, mode switches, fallback |
| Provenance checker | Establishes package identity before trusting contents |
| Rollback Oracle | Answers "can this package lower any counter on this device?" |
| Safety engine | Evaluates rules over evidence; TRUE/FALSE/UNKNOWN; overrides |
| Approval | Binds plan, package, snapshot, nonce, and tool versions |
| Wizard session | Read-only, resumable technician preflight; canonical state record and fail-closed approval handoff |
| Executor | Journaled operations, crash-safe reconcile, verification levels |
| Host Doctor | Drivers, topology, power, cable, link soak |
| Recovery Kit + Vault | Host-verified recovery assets; encrypted device-bound backups |
| Adapters | Fastboot, sideload/update_engine, Samsung, EDL, MediaTek, Unisoc |
| Simulators | Transcript replay and fault injection for every adapter |
| Tool pinning | Hash-verified external tools, recorded versions, minimum versions |
| Shop Mode | Queue, port identity, labels, parallel jobs, receipts, audit log |

### 3.2 Evidence graph

Every fact is an `Evidence[T]` with:

- `state`: `TRUE`, `FALSE`, or `UNKNOWN`;
- `source`: `PROBED`, `PACKAGE`, `CATALOG`, `USER`, or `INFERRED`;
- `observed_at`: timezone-aware timestamp;
- `max_age`: optional freshness bound;
- `value`: optional payload;
- `detail`: human-readable context.

Rules:

- `INFERRED` evidence is never usable in a safety decision, even when fresh.
- A stale probe is downgraded to `UNKNOWN` at the point of use.
- A probe from before a reboot does not satisfy a precondition after the reboot.
- Catalog claims and user assertions are weaker than direct probes.
- Rule results carry the evidence IDs and source references that produced them.

### 3.2.1 Read-only wizard sessions

`cairn wizard` is an orchestration surface, not a new verifier and not an
executor. It runs doctor, inspection, provenance, probe, AVB, rollback, planning,
and optional approval verification in that order. It never invokes a write-capable
device operation.

The session file is canonical JSON with a schema version, exact-key parsing,
duplicate-key rejection, an 8 MiB bound, atomic replacement, and a SHA-256 state
hash. It contains hashes and redacted device facts, not a raw serial or transcript.
The hash detects accidental edits; it is not a defense against a compromised host.
Only fresh successful doctor, probe, and rollback stages whose input fingerprints
still match can be reused. A simulated stage is `SIMULATED`, never usable device
evidence. A blocked, failed, stale, or changed input is rerun or blocks; it is never
silently reused.

`approval issue --session` accepts only a fresh `READY` session. Both session-based
issue and verify reload the package and index, re-hash package entries, and rebuild
the plan before constructing current approval inputs. Any archive, index, entry, or
plan-hash drift is a refusal. This remains a consistency boundary under section
2.10, not authorization and not permission to write.

### 3.3 Strategy ladder

The selector picks the least invasive path that satisfies the job:

1. **Signed full OTA** through `adb sideload` or `update_engine`. Device-side
   verification, device-side slot logic.
2. **Vendor flashing flow** driven by `fastboot-info.txt`.
3. **Per-partition fastboot** flashing.
4. **Low-level modes** (EDL, MediaTek preloader, Samsung download mode) as Assisted
   tier.

The selector's choice and rejected alternatives are explained in the report. It may
not silently fall down the ladder; each step down is a decision with a reason.

### 3.4 Planner

- Vendor order is the baseline.
- Commutation is catalog data backed by a golden test.
- Mode switches are minimized within the vendor constraints.
- Retrofit dynamic partitions use the bootloader force mode.
- The fallback plan is computed before the first write.
- The plan hash covers every operation, argument, tool version, and expected effect.
- Dry-run renders the plan and evidence without touching the device.
- A structurally complete plan is not authorization. The final executable decision
  requires a separate Safety Engine report; its evidence snapshot is carried beside,
  not folded into, the structural plan hash for later approval binding.
- Missing identity, AVB, rollback, tool, or lock/key evidence remains `UNKNOWN` and
  blocks. The planner may not manufacture a substitute fact from package structure.

### 3.5 Executor and journal

Journal invariants (check these with Hypothesis stateful tests at minimum):

1. No write without a valid approval.
2. No advance past an operation whose verification level is below the required level.
3. Slot flip only after every slot-specific operation is verified.
4. Reconcile never re-runs a non-idempotent operation blindly.
5. Every journal record is written before the effect it describes and updated after.
6. A crash at any journal point leaves a state the reconciler can classify.
7. The journal records tool versions, evidence IDs, and the operator's override text.

Crash-at-every-journal-point is a required test harness, not a stretch goal.

### 3.6 Rollback Oracle

Combines:

- AVB rollback indexes per location (and per slot where they differ);
- OEM counters (Xiaomi anti-rollback values, Samsung binary version/SWREV bits,
  fuse-based counters on some Qualcomm devices);
- OTA metadata (for example pre-device and post-timestamp properties).

Decision:

- Package cannot lower any counter: `TRUE`.
- Package may lower a counter and the stored index is known and safe: `TRUE`.
- Package may lower a counter and the stored index is unknown: `UNKNOWN`, hard stop
  unless the catalog proves otherwise. No override (ADR-020, ADR-021).
- Package definitely lowers a counter: `FALSE`, never overridable.

Unknown stored index plus a package that might lower it is a hard stop. This is the
single most important anti-brick rule.

Device reads are best-effort and vendor-specific. AOSP fastboot has no standard
stored-rollback getvar. Cairn parses only the observed vendor forms and treats
absence, conflict, malformed output, truncation, or tool failure as `UNKNOWN`. OEM
signals such as `ap-ar-s` are reported but never mapped to AVB locations. A
successful read is a device claim, not AVB verification.

### 3.7 Recovery Kit and Critical Partition Vault

Before any bootchain write on a device without a safe A/B bootloader:

- require known-good recovery assets, hash-verified on the host;
- require user-supplied programmer/Download Agent where the family needs one;
- state the device-specific last-resort path (EDL entry, test point, service only).

Before wiping or relocking, back up readable critical partitions where supported:
`persist`, modem/EFS-class data, calibration, nvdata-class data. Store encrypted,
hashed, and bound to the device identity (serial plus hardware ID). Restore only to
the same device. Never cross-device. This preserves the IMEI non-goal.

### 3.8 Host Doctor

The most common real-world failure is the host, not the phone. Check:

- **Drivers per mode on Windows:** WinUSB or vendor driver, Qualcomm 9008, MediaTek
  VCOM, Samsung. Guided setup with explicit consent.
- **Topology:** direct port, no hubs, USB 2 vs 3 behavior, cable swap advice.
- **Power:** sleep and USB selective suspend disabled, antivirus interference, WSL
  or VM passthrough warning.
- **Link soak:** repeated `getvar` plus a timed large staged `fastboot download`
  (writes to RAM, not flash) to measure throughput and error rate.

The job is gated on a passing soak. Thresholds are versioned and recorded; v1's
thresholds are provisional until the hardware lab calibrates them. A failed soak is
a hard stop, not a warning.

### 3.9 Provenance checker

Verify what the file is before what it contains:

- vendor-published hashes;
- VBMeta digest comparison;
- OTA payload signature and metadata;
- a signed index of known-good package hashes in the catalog.

Unknown-but-valid-looking packages are **Assisted**, not Verified. Repacked or
modified images produce a warning plus a typed override path. The provenance result
and all hashes are journaled.

### 3.10 Tool pinning

- Download official platform-tools with hash verification.
- Pin the exact version and record it in every journal.
- Refuse versions below the package-required minimum.
- Sign releases, publish an SBOM, aim for reproducible builds.
- Run wrapped tools with minimal privileges and no network during a flash.

### 3.11 Simulators and transcripts

A simulator encodes assumptions. Add:

- a transcript recorder and replayer for command-level real-device transcripts
  (scrubbed before storage);
- golden fixtures generated from those transcripts;
- differential tests against real fastboot behavior where possible;
- fault injection at the transport and journal layers.

Simulator agreement is not evidence about a phone. It is evidence about the code.

### 3.12 Shop Mode

- Job queue with per-USB-port identity mapping.
- Labels that survive reconnects.
- Parallel jobs across different devices, never against one device.
- Isolated journals per job.
- Printable job report/receipt.
- Technician audit log.
- Opt-in telemetry only; no device identifiers without consent.

---

## 4. Verification model

### 4.1 Levels

| Level | Meaning | Typical source |
| --- | --- | --- |
| V0 | Transport acknowledged the write | fastboot `OKAY`, EDL response |
| V1 | Host source hash matched the manifest and the device acknowledged | manifest + `OKAY` |
| V2 | Device read-back hash matched the source | `fetch`, EDL read-back, MediaTek read-back |
| V3 | Post-boot identity confirmed | slot signals, adb fingerprint, user-confirmed boot |

### 4.2 Rules

- Every operation reports its achieved level, never a bare "verified".
- A job reports the minimum level across its operations, plus the per-operation
  table.
- Catalog entries state the maximum level reachable for a device and job type.
- A capability probe may only lower the claimed level, never raise it.
- Fastboot defaults to V1 unless `fetch` is proven.
- Wipe jobs cannot rely on adb fingerprint for V3.

---

## 5. Safety model

### 5.1 Tri-state policy

- `TRUE` passes.
- `FALSE` always blocks and is never overridable.
- `UNKNOWN` blocks unless the catalog marks the rule overridable.
- An override requires a typed reason, is logged with its provenance, and appears in
  the report header.
- A rule that cannot cite a source is encoded as `UNKNOWN`.

### 5.2 Rule table

Full details and test plans are in [SAFETY_RULES.md](SAFETY_RULES.md).

| ID | Rule | FALSE | UNKNOWN | Overridable |
| --- | --- | --- | --- | --- |
| SR-001 | Device identity matches package | Block | Block | Unknown only, typed |
| SR-002 | Package provenance | Block | Assist/override | Unknown only |
| SR-003 | AVB chain and VBMeta digest | Block | Block | No |
| SR-004 | Rollback Oracle | Block | Block | No |
| SR-005 | Battery above threshold | Block | Block | No |
| SR-006 | Link soak passed | Block | Block | No |
| SR-007 | Host power stable | Block | Block | Typed override |
| SR-008 | Recovery readiness | Block | Block | No for bootchain |
| SR-009 | Vault backup before wipe/relock | Block | Block | No |
| SR-010 | Virtual A/B merge state | Block | Block | No |
| SR-011 | Dynamic partition state | Block | Block | Typed override |
| SR-012 | Tool version pinned and supported | Block | Block | No |
| SR-013 | Lock state vs AVB key | Block | Block | Unknown lock state typed; unlocked mismatch is a warning |
| SR-014 | Verification level meets job requirement | Block | Block | Typed override |
| SR-015 | Irreversible action confirmed | Block | Block | Typed, twice |
| SR-016 | Samsung Knox risk accepted | Block | Block | Typed, irreversible warning |
| SR-017 | EDL/MediaTek programmer match | Block | Block | No |
| SR-018 | Approval binding valid | Block | Block | No |
| SR-019 | Evidence fresh and usable | Block | Block | Typed override |
| SR-020 | Untrusted input handled as data | Block | Block | No |
| SR-021 | Samsung recovery path reachable | Block | Block | Typed service-risk acceptance |

### 5.3 Irreversibles

Typed confirmation twice, with an explanation of what cannot be undone:

- bootloader relock;
- fuse blow;
- calibration erase;
- IMEI-adjacent operations (not offered; this is the boundary);
- Samsung Knox warranty bit trip from unauthorized binaries;
- userdata wipe.

The confirmation text is stored in the journal and printed in the report.

### 5.4 LLM hygiene

Device strings, logs, release notes, and package metadata are untrusted input. The
explainer and catalog assistant:

- treat all such input as data;
- have no tool access;
- never influence the write path;
- have output validated against structured findings;
- are advisory only.

---

## 6. Device state machines

### 6.1 Fastboot and vendor flow

1. Bootloader mode: flash bootloader, radio, boot, and other bootloader-owned groups.
2. Reboot to userspace fastboot (fastbootd) for dynamic partitions.
3. The bootloader refuses dynamic partitions; the executor must not send them.
4. Vendor order is the baseline; deviations require commutation proof.
5. Commit/slot flip is one operation, gated on all prior verifications.
6. `fastboot-info.txt` version 1 is the vendor-order source. Grammar verified in
   AOSP: comments (`#`), `version N` (N <= 1), `if-wipe`, `flash PART [IMG]
   [--apply-vbmeta] [--slot-other]`, `reboot [bootloader|fastboot|recovery]`,
   `update-super`, `erase PART`. Unknown commands fail closed.
7. Official fastboot may replace `reboot fastboot` + `update-super` + dynamic
   flashes with one optimized sparse `super` write. Cairn may use that optimization
   only when it can journal the single super write as a recoverable unit, and never
   on a job with an unknown super size or merge state.

Sources: [AOSP-FASTBOOT-SRC], vendor `fastboot-info.txt` files.

### 6.2 Virtual A/B

Model at least: `none`, `snapshot_active`, `merge_pending`, `merging`,
`merge_complete`, `merge_cancelled`, `unknown`.

Observed signals (AOSP fastbootd, 2026-11-25): `getvar snapshot-update-status`
returns `snapshotted`, `merging`, or `none`; it fails with `not supported` when the
boot-control 1.1 HAL is absent. Map `snapshotted` to `snapshot_active`, `merging` to
`merging`, and a FAIL to `unknown`. A device may report additional vendor values;
anything unrecognized is `unknown`.

Preconditions:

- `merge_pending` or `merging`: do not flash. Offer wait-for-merge or an explicit
  cancel flow, with backup and recovery readiness.
- `snapshot_active`: do not flash.
- `unknown`: block (SR-010).
- Cancel and merge are operations with their own journal entries and verification.
- Cairn never auto-cancels or auto-merges. The operator must approve the flow, and
  the report states that AOSP documents cancel as potentially unbootable until
  reflashed.

Primary source: [AOSP-FASTBOOT-SRC] (`GetSnapshotUpdateStatus`,
`snapshot-update:cancel|merge`, `CancelSnapshotIfNeeded`). Exact availability is a
per-device hardware finding.

### 6.3 Dynamic partitions

Model:

- `super` presence and metadata version;
- logical partition create, resize, delete;
- slot metadata and group ownership;
- retrofit devices;
- `wipe-super`.

Operations are allowed only in the mode the vendor flow expects. Retrofit devices
flash in the bootloader with the force mode. Unknown `super` metadata is
`UNKNOWN` and blocks.

### 6.4 Samsung

- Download mode may be gated behind Maintenance Mode (One UI 8.5, 2026).
- If Android cannot boot, Maintenance Mode may be unreachable, so the usual recovery
  path can be unavailable. This is a recovery-risk market.
- Knox warranty bit is irreversible.
- Backend is pluggable and selected by catalog.
- Until M9: detect, validate, and dry-run only. No real write path.
- A Samsung job requires SR-021: a stated recovery path or a typed acceptance of
  service-center risk.

Sources: [SAMSUNG-2026], [WIKI-ODIN], [GH-THOR].

### 6.5 EDL and MediaTek (Assisted)

- User supplies the programmer/Download Agent where the vendor requires it.
- Verify programmer/DA hash and device match. Mismatch is always vetoed.
- No loader authentication bypass.
- No firehose authentication bypass.
- Read-back is the preferred verification path where the vendor permits it.
- Unisoc is analysis only.

---

## 7. Reliability model

The ranking below is an estimate from how flashing fails in practice. Replace it
with Cairn telemetry and lab data as soon as it exists.

| Cause | Primary defense |
| --- | --- |
| Host and link: cable, port, driver, sleep, hub | Host Doctor, soak test, adaptive transfer, clear stop messages |
| Wrong package: model, region, counter-lowering | Provenance, identity rule, Rollback Oracle, catalog |
| Device state: locked bootloader, merge in progress, low battery | Snapshot, Virtual A/B rule, device-specific battery threshold |
| Interrupted bootchain write | Recovery readiness, tight write windows, journaled resume, A/B commit |
| Tool bug | Differential tests, transcript fixtures, mutation tests, stateful model checks |
| Hardware failure | Honest `FATAL_HARDWARE`, diagnostics bundle, stop |

Targets are in 1.3. Do not publish a target as a guarantee.

---

## 8. Performance

Real flash time is dominated by USB transfer, reboots, and decompression, not
planning.

- Stream directly from the zip or payload; do not unpack everything to disk.
- Use bounded buffers.
- Hash and decompress the next image while the current one transfers. Pipeline;
  never write to one device in parallel.
- Skip all-zero and fill regions through sparse encoding.
- Skip unchanged partitions only where read-back exists (V2 devices).
- Minimize mode switches within vendor-order constraints.
- Use link-aware chunk sizing and the same hard retry budget as v1.
- Parallelize across different devices only.
- Native USB with large bulk buffers only after hardware data shows the official
  tool is the bottleneck.

---

## 9. Scope and market

Device mix differs sharply by region. The scope order is:

1. **Qualcomm/fastboot class.** Best documented by AOSP; proves the core.
2. **adb sideload and update_engine.** Cheap, safe, broad.
3. **Samsung with a pluggable backend.** Recovery risk is higher in 2026; proceed
   carefully and later.
4. **EDL and MediaTek as Assisted tier.** Verification-first; no auth bypass.
5. **Unisoc as Experimental analysis only.**

If the market is MediaTek-heavy, reorder, but keep the shared core first: provenance,
Host Doctor, journal, Vault, and evidence graph are needed by every family.

Commercial shape:

- open-source the core under Apache-2.0;
- keep the signed catalog as the commercial moat;
- use a documented WinUSB-based driver step with explicit consent;
- keep telemetry opt-in.

---

## 10. Agent and contributor rules

1. Differential-test every parser and protocol claim against an official tool or a
   recorded real transcript before it becomes a rule.
2. Never print or log "verified" without a verification level.
3. Every safety rule and catalog quirk carries a source reference or a hardware
   finding ID; no source means `UNKNOWN`.
4. Pin and record every external tool version in the journal.
5. Keep `DECISIONS.md` and `KNOWN_UNKNOWNS.md` current; add
   `HARDWARE_FINDINGS.md` entries from every real-device run.
6. Treat all device strings, logs, and release notes as untrusted input, including
   in LLM components.
7. Keep the non-goals unchanged.
8. No real-device write before the M6 gate and a recovery drill.

---

## 11. Sources

Source tags resolve in [RESEARCH_NOTES.md](RESEARCH_NOTES.md). Primary sources:

- AOSP `system/core/libsparse/sparse_format.h` [AOSP-SPARSE]
- AOSP Android Verified Boot 2.0 README and `avbtool` [AOSP-AVB]
- AOSP AVB README and `avbtool.py` source, pinned 2026-11-25 [AOSP-AVBSRC]
- AOSP fastbootd documentation [AOSP-FASTBOOTD]
- AOSP `system/core/fastboot` host and fastbootd source, pinned tree
  `c66af46cc55138dd6ee70b51cbeb4501b83d23ec` [AOSP-FASTBOOT-SRC]
- AOSP platform-tools `fastboot` behavior, pinned per release
- Heimdall repository (MIT) [GH-HEIMDALL]
- Thor repository (MPL-2.0) [GH-THOR]
- `bkerler/edl` (GPL-3.0) [GH-EDL]
- `bkerler/mtkclient` (GPL-3.0) [GH-MTKCLIENT]
- Samsung Maintenance Mode reporting, 2026 [SAMSUNG-2026]
- Wikipedia: Odin (firmware flashing software) [WIKI-ODIN]

Every device-dependent statement is a hypothesis until a hardware finding ID exists.
