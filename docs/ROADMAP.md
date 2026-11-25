# Cairn Roadmap

**Status as of 2026-11-24.** Milestones are cumulative. A milestone is complete only
when its acceptance test is reproducible from a clean checkout.

| Milestone | Scope | Acceptance | Status |
| --- | --- | --- | --- |
| M0 | Repo, CI, core models, errors, subprocess wrapper, tool pinning, fastboot simulator with transcript replay, sparse oracle tests against libsparse | CI green with strict types; simulator answers `getvar all` from a recorded transcript; sparse parser matches libsparse on fixtures | **In progress** - runner, manifest, simulator, and oracle harness landed; libsparse oracle green in CI (run 45500165412); journal primitives pending |
| M1 | Host Doctor, fastboot adapter, `fastboot-info.txt` and factory-zip parser, provenance skeleton | Soak test and driver checks work on Windows and Linux; Pixel-class package parses and dry-runs against the simulator; no real writes | **Partial** - read-only fastboot probe, Host Doctor MVP, `fastboot-info.txt` parser, and factory/OTA zip inspection landed; provenance skeleton and real vendor fixtures pending |
| M2 | AVB chain-following verification and VBMeta digest, provenance checker, lock-state handling | Matches `avbtool` and `pixel_factory_image_verify.py` on a corpus of real images; chained VBMeta and per-location indexes covered | Not started |
| M3 | Planner with vendor-order baseline, commutation data, retrofit force case, fallback, dry run | Brute-force equivalence on commutable groups; golden plans for five devices; every deviation annotated | Not started |
| M4 | Safety engine, Rollback Oracle, approval binding with package hashes and device nonce | Mutation tests kill all rule mutants; TOCTOU test passes; FALSE never overridable | Not started |
| M5 | Journal, executor, reconcile, failure classifier, adaptive transfer | Crash at every journal point; stateful model checks of the executor invariants; resume reaches same final state | Not started |
| M6 | Recovery Kit, Critical Partition Vault, Virtual A/B and dynamic partition state machines | Simulator and hardware runs through merge, cancel, and wipe flows; Vault restores only to the same device; recovery drill passes | Not started |
| M7 | CLI beta with three Verified devices and Shop Mode | Three real devices end to end; pilot with three repair shops; unrecoverable-state rate recorded | Not started |
| M8 | `adb sideload` and `update_engine` path with OTA metadata checks | Signed full OTA verified and applied through the native path; downgrade checks enforced | Not started |
| M9 | Samsung adapter with pluggable backend, Knox irreversibles, Maintenance Mode handling | Simulator suite plus two real models; detect/validate/dry-run only for new models until proven; SR-021 enforced | Not started |
| M10 | EDL and MediaTek adapters, Assisted tier | Programmer/DA mismatch always vetoed; no auth bypass; read-back used where permitted | Not started |
| M11 | Wizard, installer, signed catalog updates, explainer, link model | Link model beats the rule baseline offline; signed catalog rotation tested; installer consent-first | Not started |
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

Wizard, installer, signed catalog updates, explainer, link model. The link model must
beat the rule baseline offline or it does not ship.

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
