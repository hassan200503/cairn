# Cairn Safety Rules

**Status:** Draft 2.0, 2026-11-24
**Normative companion:** [SPEC_V2.md](SPEC_V2.md), section 5.

Safety rules consume evidence, never bare booleans. `TRUE` passes, `FALSE` always
blocks, and `UNKNOWN` blocks unless the catalog marks the rule overridable and the
operator supplies a typed reason. A rule without a source reference is encoded as
`UNKNOWN`.

---

## 1. Rule result

```text
RuleResult:
  rule_id:        SR-xxx
  state:          TRUE | FALSE | UNKNOWN
  evidence_ids:   [stable IDs used in the decision]
  source_refs:    [AOSP section, vendor doc, or HF-xxxx]
  reason:         human-readable, no bare "verified"
  warnings:       [non-blocking findings]
  override:       null or OverrideRecord
```

`OverrideRecord` contains the rule ID, operator, typed reason, timestamp, the
evidence snapshot hash, and the exact text shown in the report header.

### Override policy

- `FALSE` is never overridable.
- `UNKNOWN` is overridable only where the rule says so.
- Some rules are never overridable at all (battery below threshold, link failure,
  recovery readiness for bootchain, vault missing before wipe, config mismatch).
- Every override is logged, hashed, and shown in the report header.
- An override does not turn `UNKNOWN` into `TRUE`; it records informed acceptance.

---

## 2. Rule index

| ID | Rule | FALSE | UNKNOWN | Overridable |
| --- | --- | --- | --- | --- |
| SR-001 | Device identity matches package | Block | Block | UNKNOWN only, typed |
| SR-002 | Package provenance | Block | Assist/override | UNKNOWN only |
| SR-003 | AVB chain and VBMeta digest | Block | Block | UNKNOWN only, typed |
| SR-004 | Rollback Oracle | Block | Block | UNKNOWN only, typed |
| SR-005 | Battery above threshold | Block | Block | No |
| SR-006 | Link soak passed | Block | Block | No |
| SR-007 | Host power stable | Block | Block | Typed |
| SR-008 | Recovery readiness | Block | Block | No for bootchain |
| SR-009 | Vault backup before wipe/relock | Block | Block | No |
| SR-010 | Virtual A/B merge state | Block | Block | No |
| SR-011 | Dynamic partition state | Block | Block | Typed |
| SR-012 | Tool version pinned and supported | Block | Block | No |
| SR-013 | Lock state vs AVB key | Block | Block | Unlocked mismatch = warning |
| SR-014 | Verification level meets requirement | Block | Block | Typed |
| SR-015 | Irreversible action confirmed | Block | Block | Typed twice |
| SR-016 | Samsung Knox risk accepted | Block | Block | Typed, irreversible warning |
| SR-017 | EDL/MediaTek programmer match | Block | Block | No |
| SR-018 | Approval binding valid | Block | Block | No |
| SR-019 | Evidence fresh and usable | Block | Block | Typed |
| SR-020 | Untrusted input handled as data | Block | Block | No |
| SR-021 | Samsung recovery path reachable | Block | Block | Typed service-risk acceptance |

---

## 3. Rules in detail

### SR-001 - Device identity

**Condition:** package model, region, variant, and expected hardware ID match the
device.

**FALSE:** mismatch. Never overridable.
**UNKNOWN:** block; typed override only after the operator confirms the exact model
and region from a second source.
**Source:** vendor package metadata, device probes.
**Test:** swapped model; swapped region; missing metadata; same model, different
hardware ID.

### SR-002 - Package provenance

**Condition:** package hashes match a vendor-published hash or the signed catalog's
known-good index, and the VBMeta digest matches where published.

**FALSE:** hash mismatch or signature failure. Never overridable.
**UNKNOWN:** unknown-but-valid-looking package is **Assisted**; typed override with
a warning.
**Source:** vendor hash, VBMeta digest, OTA signature, signed catalog.
**Test:** repacked image; modified file; unknown package; catalog index miss.

### SR-003 - AVB chain and VBMeta digest

**Condition:** `avbtool` chain-following verification passes; digest matches where a
published digest exists; lock state is considered.

**FALSE:** verification failure on a locked device, or digest mismatch. Never
overridable.
**UNKNOWN:** verification could not run or lock state is unknown. Typed override only
if the operator accepts the risk; the report says "unverified".
**Source:** [AOSP-AVB], pinned `avbtool`.
**Test:** hash descriptor, hashtree descriptor, chained `vbmeta_system`, per-location
rollback index, locked key mismatch, unlocked key mismatch.

### SR-004 - Rollback Oracle

**Condition:** the package cannot lower any AVB/OEM counter on this device, or the
stored counter is known and the package is not lower.

**FALSE:** package definitely lowers a counter. Never overridable.
**UNKNOWN:** package may lower a counter and the stored index is unknown. Hard stop;
catalog proof or typed override only.
**Source:** [AOSP-AVB], OEM catalog quirk with HF ID.
**Test:** known-safe, definitely-lower, unknown index, per-slot index difference,
OEM counter unknown.

### SR-005 - Battery threshold

**Condition:** the battery is above the applicable flashing threshold. Prefer the
device's `battery-soc-ok` (voltage vs. the HAL flashing threshold); otherwise use
`battery-voltage` against a known threshold. `battery-soc` alone is not sufficient.

**FALSE:** observed voltage below threshold, or `battery-soc-ok` is `no`. Never
overridable.
**UNKNOWN:** voltage, `battery-soc-ok`, and threshold cannot be read. Block. (This is
deliberately strict; the fix is a probe or a charged-device confirmation protocol,
not a silent pass.)
**Source:** device threshold, AOSP fastboot HAL, catalog fallback. Record which was
used. [AOSP-FASTBOOT-SRC] confirms `battery-soc-ok` is a voltage comparison, not a
state-of-charge percentage.
**Test:** below, at, above; `battery-soc-ok` yes/no; threshold from device; fallback
threshold; unreadable; `battery-soc` high but voltage low.

### SR-006 - Link soak

**Condition:** the link soak completed within the configured error and throughput
thresholds.

**FALSE:** failed soak. Never overridable.
**UNKNOWN:** soak not run. Block.
**Source:** v1 thresholds plus lab calibration; versioned config.
**Test:** timeout, disconnect, truncated response, error rate above threshold,
throughput below threshold, healthy link.

### SR-007 - Host power

**Condition:** sleep and USB selective suspend are disabled, no VM/WSL passthrough
warning, no known interfering antivirus state.

**FALSE:** a condition known to interrupt USB. Block; typed override allowed only
for read-only jobs.
**UNKNOWN:** cannot inspect. Block; typed override for a write with explicit
acknowledgement.
**Source:** Host Doctor.
**Test:** sleep enabled; hub present; VM detected; unknown platform.

### SR-008 - Recovery readiness

**Condition:** for a bootchain write on a device without a safe A/B path, known-good
recovery assets are hash-verified on the host and a last-resort path is stated.

**FALSE:** assets missing or hash mismatch. Block; no override for bootchain.
**UNKNOWN:** recovery path not stated. Block; no override for bootchain.
**Source:** catalog recovery recipe; HF ID for device entry method.
**Test:** missing firmware; bad hash; no programmer; "test point only" path; A/B
device exempt per catalog.

### SR-009 - Vault before wipe or relock

**Condition:** readable critical partitions are backed up, encrypted, hashed, and
bound to this device identity before a wipe or relock.

**FALSE:** backup failed or identity mismatch. Block; no override.
**UNKNOWN:** readability unknown. Block; no override for wipe/relock.
**Source:** Vault and device identity probe.
**Test:** missing backup; cross-device restore; corrupt backup; same-device restore.

### SR-010 - Virtual A/B merge state

**Condition:** `snapshot-update-status` is `none`, or the job is an explicit
operator-approved merge/cancel flow with recovery readiness.

**FALSE:** `snapshotted`, `merging`, or `merge_pending` for a normal flash. Block; no
override.
**UNKNOWN:** state cannot be read, or the device reports an unrecognized value.
Block; no override.
**Source:** [AOSP-FASTBOOTD], [AOSP-FASTBOOT-SRC]. Observed values: `snapshotted`,
`merging`, `none`; a FAIL (including `not supported`) is `UNKNOWN`. Cairn never
auto-cancels; AOSP documents cancel as potentially unbootable until reflashed.
**Test:** each state, cancel flow with typed approval, merge flow, unknown state,
vendor-specific value.

### SR-011 - Dynamic partition state

**Condition:** `super` metadata is known and matches the job's expectations; mode is
correct (bootloader force for retrofit, fastbootd otherwise).

**FALSE:** metadata mismatch or wrong mode. Block; typed override only with catalog
proof.
**UNKNOWN:** metadata unreadable. Block; typed override.
**Source:** [AOSP-DYNPART], [AOSP-DYNPART-IMPL], [AOSP-FASTBOOTD].
**Test:** retrofit force; fastbootd create/resize/delete; unknown metadata;
`wipe-super`.

### SR-012 - Tool version

**Condition:** every external tool is pinned, hash-verified, at or above the package
minimum, and recorded in the journal.

**FALSE:** hash mismatch or below minimum. Block; no override.
**UNKNOWN:** version or hash unavailable. Block; no override.
**Source:** tool manifest, vendor package requirement.
**Test:** below minimum, missing hash, wrong tool, GPL tool invoked as a library.

### SR-013 - Lock state and AVB key

**Condition:** lock state is known; on a locked device the signing key matches the
trusted key.

**FALSE:** locked device with key mismatch. Block; no override.
**UNKNOWN:** lock state unknown. Block; typed override after an explicit unlock-state
check.
**Warning:** unlocked device with key mismatch is a warning, not a silent pass.
**Source:** [AOSP-AVB], device lock probe.
**Test:** locked/match, locked/mismatch, unlocked/mismatch, unknown.

### SR-014 - Verification level

**Condition:** achieved level is at least the job's required level.

**FALSE:** a write reported success with no acknowledgement. Block.
**UNKNOWN:** level not recorded. Block; typed override only if the catalog lowers the
job requirement.
**Source:** verification model, catalog maximum level.
**Test:** V0 vs required V1; fastboot general partition cannot claim V2; wipe job
cannot claim adb V3.

### SR-015 - Irreversible action

**Condition:** the operator typed the exact irreversible-action confirmation twice.

**FALSE:** confirmation absent or incorrect. Block; no override.
**UNKNOWN:** action classification unknown. Block.
**Source:** Irreversibles list.
**Test:** relock, fuse, calibration erase, wipe; wrong text; single confirmation.

### SR-016 - Samsung Knox

**Condition:** the operator accepts that an unauthorized binary may permanently trip
the Knox warranty bit.

**FALSE:** acceptance absent for an unauthorized binary. Block.
**UNKNOWN:** authorization status unknown. Block.
**Source:** [SAMSUNG-2026], [WIKI-ODIN], vendor docs; HF ID per model.
**Test:** official binary, unauthorized binary, unknown binary, typed acceptance.

### SR-017 - Programmer/DA match

**Condition:** user-supplied programmer/Download Agent hash and target match the
device and catalog entry.

**FALSE:** mismatch. Always veto; no override.
**UNKNOWN:** cannot verify. Block.
**Source:** vendor package, catalog, HF ID.
**Test:** wrong programmer, wrong device, hash mismatch, missing file.

### SR-018 - Approval binding

**Condition:** approval covers plan hash, snapshot hash, package hashes, device-bound
nonce, and tool versions.

**FALSE:** any mismatch. Block; no override.
**UNKNOWN:** binding incomplete. Block.
**Source:** approval design.
**Test:** TOCTOU plan edit; package swap; device swap; stale nonce; tool version
change.

### SR-019 - Evidence freshness

**Condition:** each evidence item is fresh relative to the decision time and not
invalidated by a reboot.

**FALSE:** a probe is known to predate a reboot. Block.
**UNKNOWN:** freshness cannot be established. Block; typed override only after
re-probing.
**Source:** evidence model.
**Test:** stale probe; reboot between probe and decision; inferred evidence; clock
skew.

### SR-020 - Untrusted input

**Condition:** device strings, logs, release notes, and package metadata are treated
as data; LLM output has no tool access and is validated against structured findings.

**FALSE:** any path lets untrusted text alter a plan or invoke a tool. Block; no
override.
**UNKNOWN:** provenance of the text is unclear. Block.
**Source:** security review.
**Test:** prompt injection in a device string; injected log line; fabricated finding
in release notes.

### SR-021 - Samsung recovery path

**Condition:** a recovery path is reachable, or the operator explicitly accepts
service-center risk.

**FALSE:** device cannot boot and Maintenance Mode is gated off. Block.
**UNKNOWN:** reachability unknown. Block; typed service-risk acceptance.
**Source:** [SAMSUNG-2026], [SAMSUNG-XDA], HF ID.
**Test:** bootable with Maintenance Mode; bootable without; unbootable; unknown
model.

---

## 4. Authoring checklist

Every new rule must:

1. have an ID and a one-sentence condition;
2. cite a source or an HF ID;
3. define FALSE, UNKNOWN, and override behavior;
4. consume evidence with provenance and freshness;
5. have at least three mutants that the test suite kills;
6. appear in the report with its evidence IDs;
7. be covered by a simulator scenario and, once available, a hardware scenario.
