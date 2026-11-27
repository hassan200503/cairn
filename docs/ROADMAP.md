# Cairn Roadmap

**Status as of 2026-11-27.** Milestones are cumulative. A milestone is complete only
when its acceptance test is reproducible from a clean checkout.

| Milestone | Scope | Acceptance | Status |
| --- | --- | --- | --- |
| M0 | Repo, CI, core models, errors, subprocess wrapper, tool pinning, fastboot simulator with transcript replay, sparse oracle tests against libsparse | CI green with strict types; simulator answers `getvar all` from a recorded transcript; sparse parser matches libsparse on fixtures | **In progress** - runner, manifest, simulator, and oracle harness landed; libsparse oracle green in CI (run 45500165412); journal primitives pending |
| M1 | Host Doctor, fastboot adapter, `fastboot-info.txt` and factory-zip parser, provenance skeleton | Soak test and driver checks work on Windows and Linux; Pixel-class package parses and dry-runs against the simulator; no real writes | **Partial** - read-only fastboot probe, Host Doctor MVP, `fastboot-info.txt` parser, factory/OTA zip inspection, and the provenance hash-index skeleton landed; real vendor fixtures and AVB verification pending |
| M2 | AVB chain-following verification and VBMeta digest, provenance checker, lock-state handling | Matches `avbtool` and `pixel_factory_image_verify.py` on a corpus of real images; chained VBMeta and per-location indexes covered | **Partial** - VBMeta parser, footer images, descriptors, AOSP digest, embedded-key RSA signature check, tri-state chain-of-trust verification with `cairn avb`, per-location rollback comparison with `cairn rollback`, and an offline lock-state-contextual expected-key check; a device lock/key binding and a real corpus remain pending |
| M3 | Planner with vendor-order baseline, commutation data, retrofit force case, fallback, dry run | Brute-force equivalence on commutable groups; golden plans for five devices; every deviation annotated | **Partial** - read-only planner v0 preserves vendor order, hashes plans, and gates executable on provenance; slot/retrofit modeling and five real golden plans pending |
| M4 | Safety engine, Rollback Oracle, approval binding with package hashes and device nonce | Mutation tests kill all rule mutants; TOCTOU test passes; FALSE never overridable | **Partial** - safety engine v0 evaluates SR-001/002/003/004/012/013, and `cairn plan` now binds its structural dry run to that report, refusing an executable result for FALSE or un-overridden UNKNOWN; Rollback Oracle v0 and `cairn rollback check` apply the AOSP rollback inequality with tri-state results and per-counter reasons; a vendor-specific device reader (`cairn rollback read`, `rollback check --device`) parses observed getvar forms and fails closed. Approval binding landed as `cairn approval keygen|issue|verify|inspect` over the plan hash, evidence-snapshot hash, archive hash, package entry hashes, a device binding, and tool identities, enforced as rule SR-018 (a consistency gate, not authorization). Catalog-bound preflight inputs, generic/OEM stored-index policy, and mutation and TOCTOU tests remain pending |
| M5 | Journal, executor, reconcile, failure classifier, adaptive transfer | Crash at every journal point; stateful model checks of the executor invariants; resume reaches same final state | **Partial** - the hash-chained write-ahead journal, idempotency classes, reconcile-on-resume, and the crash-at-every-point harness landed simulator-gated (ADR-027, `cairn execute`); the real-device transport and slot/Virtual A/B state machine remain blocked behind M6 |
| M6 | Recovery Kit, Critical Partition Vault, Virtual A/B and dynamic partition state machines | Simulator and hardware runs through merge, cancel, and wipe flows; Vault restores only to the same device; recovery drill passes | **Partial** - the recovery threat model, SR-008 asset verification, the encrypted device-bound vault with restore-only-same-device enforcement (never overridable), and the `cairn recovery backup\|verify\|restore\|drill` CLI landed simulator-gated (ADR-028); the M6 drill passes in the simulator and refuses cross-device restore; the Virtual A/B merge-state gate (`cairn vab status`, rule SR-010) classifies `snapshot-update-status` tri-state and blocks mid-merge flashes; the dynamic-partition mode gate (`cairn vab dynpart`, rule SR-011) refuses a fastbootd job from the bootloader and blocks on unreadable mode facts; modeled operator-approved snapshot cancel/merge flows (`cairn vab cancel|merge`) run only in the simulator behind an exact typed acknowledgment, recovery readiness, and a matching merge-state precondition. External crypto/safety review (KU-032), hardware drill runs, super metadata parsing oracles remain |
| M7 | CLI beta with three Verified devices and Shop Mode | Three real devices end to end; pilot with three repair shops; unrecoverable-state rate recorded | Not started |
| M8 | `adb sideload` and `update_engine` path with OTA metadata checks | Signed full OTA verified and applied through the native path; downgrade checks enforced | Not started |
| M9 | Samsung adapter with pluggable backend, Knox irreversibles, Maintenance Mode handling | Simulator suite plus two real models; detect/validate/dry-run only for new models until proven; SR-021 enforced | Not started |
| M10 | EDL and MediaTek adapters, Assisted tier | Programmer/DA mismatch always vetoed; no auth bypass; read-back used where permitted | Not started |
| M11 | Wizard, installer, signed catalog updates, explainer, link model | Link model beats the rule baseline offline; signed catalog rotation tested; installer consent-first | **Partial** - the read-only resumable wizard and session-bound approval handoff landed; installer, signed catalog rotation, explainer, and link model remain unstarted |
| M12 | Unisoc analysis-only support | Read-only analysis; no flashing claims | Not started |

---

## Milestone detail

### M0 - Foundations

Build the things that make every later mistake visible: the sparse oracle, the
evidence graph, the journal primitives, and a simulator that replays real
transcripts. No device writes.

Exit gate: G0.

### M1 - Know the host and the package

Host Doctor and the package parsers. The deliverable is a trustworthy dry run, not
a flash. A bad cable should already be catchable here.

### M2 - Know the package is what it claims

AVB chain following, VBMeta digest, provenance, lock state. This is the gate that
prevents "valid-looking but wrong" packages from reaching the planner.

Exit gate: G1.

### M3 - Prove the plan

Vendor baseline, commutation, fallback, and a dry run a technician can read. The
planner does not invent order to save a reboot.

### M4 - Refuse before write

Safety engine, Rollback Oracle, approval binding. This is the milestone where a
wrong package must be stopped with a named rule and evidence.

Exit gate: G2.

### M5 - Survive interruption

Journal, executor, reconcile, crash harness, stateful invariants. If this milestone
is weak, nothing else matters.

### M6 - Recovery and state machines

Vault, Recovery Kit, Virtual A/B, dynamic partitions, recovery drill. This is the
last gate before real-device writes.

Exit gate: G3.

### M7 - Prove it on hardware

Three Verified devices, Shop Mode, three-shop pilot, measured reliability. The first
release that may touch a real device, and only after G3.

Exit gate: G4.

### M8 - Native OTA path

`adb sideload` and `update_engine`, OTA metadata and signature checks. Cheap, safe,
and broad; it should have been earlier if the team has bandwidth.

### M9 - Samsung, carefully

Pluggable backend, Knox warnings, Maintenance Mode, SR-021. Start with detect,
validate, and dry-run. Two real models before any write claim.

### M10 - Assisted low-level modes

EDL and MediaTek with user-supplied programmer/DA. Verification-first, mismatch
always vetoed, no authentication bypass.

Exit gate: G5.

### M11 - Usability and catalog

The read-only `cairn wizard` now persists strict, canonical, bounded sessions and
chains doctor, package inspection/provenance, probe, AVB, rollback, planning, and
optional approval verification. Resume only reuses fresh successful observations
whose input fingerprints still match; session-based approval reloads the package,
hash index, entries, and plan before binding or checking a token. Simulations remain
non-device evidence, no stage writes a device, and unavailable safety evidence still
blocks. Installer, signed catalog updates, explainer, and link model remain pending.
The link model must beat the rule baseline offline or it does not ship.

### M12 - Unisoc analysis

Read-only analysis. No flash claims. Experimental tier.

---

## Release naming

- `0.1.x` - M0-M2, internal.
- `0.2.x` - M3-M5, dry-run and simulator.
- `0.3.x` - M6, recovery drill candidate.
- `0.4.x` - M7, first hardware-supported beta.
- `0.5.x` - M8-M9.
- `0.6.x` - M10.
- `1.0` - M11, only when the published reliability numbers hold.
