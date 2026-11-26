# Architecture Decision Records

Decisions are append-only. To change one, add a new ADR that supersedes it.

| ID | Decision | Status | Date |
| --- | --- | --- | --- |
| ADR-001 | Name the tool Cairn and the project repo `cairn` | Accepted | 2026-11-24 |
| ADR-002 | Implement in Python 3.12+ with uv, ruff, mypy strict, pytest, Hypothesis | Accepted | 2026-11-24 |
| ADR-003 | License the core Apache-2.0; keep the signed catalog separate | Accepted | 2026-11-24 |
| ADR-004 | Vendor flash order is the baseline; deviate only with commutation proof | Accepted | 2026-11-24 |
| ADR-005 | Replace "verified" with V0-V3 levels everywhere | Accepted | 2026-11-24 |
| ADR-006 | Prefer the native-path ladder over low-level modes | Accepted | 2026-11-24 |
| ADR-007 | GPL-3.0 tools run as separate processes, never linked or vendored | Accepted | 2026-11-24 |
| ADR-008 | Build in public under `hassan200503/cairn`; open-source the core | Accepted | 2026-11-24 |
| ADR-009 | No real-device write before the M6 gate and a recovery drill | Accepted | 2026-11-24 |
| ADR-010 | Differential test parsers against official oracles in CI | Accepted | 2026-11-24 |
| ADR-011 | Samsung is third in scope, behind fastboot and OTA | Accepted | 2026-11-24 |
| ADR-012 | Distribution name `cairn-flash`, import package `cairn`, CLI `cairn` | Accepted | 2026-11-24 |
| ADR-013 | Every evidence item carries source, observation time, and freshness | Accepted | 2026-11-24 |
| ADR-014 | Approval is a consistency boundary, not a security boundary against a compromised host | Accepted | 2026-11-24 |
| ADR-015 | Package archives are untrusted and are never extracted | Accepted | 2026-11-25 |
| ADR-016 | A local hash-index match is a signal, not a signature | Accepted | 2026-11-25 |
| ADR-017 | Planner v0 never reorders or guesses | Accepted | 2026-11-25 |
| ADR-018 | AVB parsing is not AVB verification | Accepted | 2026-11-25 |
| ADR-019 | Embedded-key signature validity is not trust | Accepted | 2026-11-25 |
| ADR-020 | Chain verification is a consistency gate, not a trust gate | Accepted | 2026-11-26 |
| ADR-021 | Rollback verdicts use the documented inequality; unknown is a hard stop | Accepted | 2026-11-26 |
| ADR-022 | Device stored-index reads are vendor-specific claims, not AVB verification | Accepted | 2026-11-26 |
| ADR-023 | A caller-provided lock state is contextual input, not device-trust evidence | Accepted | 2026-11-26 |
| ADR-024 | Plan structure and safety authorization are separate gates | Accepted | 2026-11-26 |

---

## ADR-001 - Name: Cairn

**Context.** "Flashwright" described the v1 craft, but the v2 product is about
known state, evidence, and a path back, not only writing flash.

**Decision.** The tool is **Cairn**. A cairn is a stack of stones that marks a
proven path; each journal entry is a stone. The repo is `cairn`; the PyPI
distribution is `cairn-flash`; the import package and CLI are `cairn`.

**Consequences.** Clear metaphor for journaling and recovery. "Flashwright" remains
the name of the v1 spec lineage and can be used for the historical document.

---

## ADR-002 - Python 3.12+ and the toolchain

**Context.** The core is orchestration, parsing, state machines, and safety logic,
not a high-throughput binary codec. Fast paths call native tools. Python is strong
for evidence models and Hypothesis stateful testing.

**Decision.** Python 3.12+, uv for env/lock, ruff for lint/format, mypy strict for
`src`, pytest + Hypothesis for tests, GitHub Actions on Ubuntu and Windows.

**Consequences.** PEP 695 generics are available. Performance-critical transfer is
delegated to fastboot/EDL or a future native USB helper. Distribution is a Python
package; a standalone installer may wrap it later.

---

## ADR-003 - Apache-2.0 core, separate catalog

**Context.** The review recommends open-sourcing the core and keeping the signed
catalog as the commercial moat.

**Decision.** Core under Apache-2.0 (patent grant plus permissive use). The signed
catalog, curated per-device findings, and commercial support are separate assets.

**Consequences.** Contributions are easy. The catalog must be signed and versioned.
No GPL-3.0 code may enter the core; GPL tools stay as separate processes.

---

## ADR-004 - Vendor order is the baseline

**Context.** Exact planning is cheap, but the vendor-tested order encodes hardware
knowledge and is a safety asset. AOSP documents the bootloader/fastbootd split and
the bootloader's duty to refuse dynamic partitions.

**Decision.** Use vendor order by default. Deviate only where the catalog marks
groups commutative and a golden test proves equivalence. Optimize risk and time, not
reboot count alone.

**Consequences.** Fewer invented orders, easier review, and a clear explanation for
every deviation. Some theoretical speedups are intentionally left on the table.

---

## ADR-005 - Verification levels

**Context.** "Verified" hides whether the host, the transport, the device, or the
booted system confirmed the write.

**Decision.** Every operation reports V0-V3. A job reports the minimum level and a
per-operation table. The word "verified" never appears without a level.

**Consequences.** Fastboot jobs honestly report V1. Marketing copy cannot claim
device read-back on hardware that does not support it.

---

## ADR-006 - Native-path ladder

**Context.** The least invasive path is usually the safest: a signed full OTA lets
the device verify and switch slots itself.

**Decision.** Strategy order: signed OTA via sideload/update_engine, vendor
`fastboot-info.txt` flow, per-partition fastboot, then low-level modes. Every step
down the ladder is a recorded decision.

**Consequences.** More of the safety burden moves to the device where possible.
Low-level modes become Assisted tier, not the default.

---

## ADR-007 - GPL process boundary

**Context.** `bkerler/edl` and `bkerler/mtkclient` are GPL-3.0; Heimdall is MIT;
Thor is MPL-2.0.

**Decision.** GPL-3.0 tools run as separate processes with no code copying and no
linking. MPL-2.0 code is not copied into Cairn. The license audit pins each tool
version.

**Consequences.** Users can replace tools. Distribution must respect each license.
The core stays Apache-2.0.

---

## ADR-008 - Build in public

**Context.** The review recommends open-sourcing the core. A public repo also makes
safety claims auditable.

**Decision.** Develop in public at `github.com/hassan200503/cairn` under
Apache-2.0. The catalog remains separate.

**Consequences.** Issues and transcripts must be scrubbed before publication.
Security reports need a private channel (`SECURITY.md`).

---

## ADR-009 - No real writes before M6

**Context.** A flash tool that experiments on real phones before its recovery path
works is backwards.

**Decision.** No real-device write until M6 plus an external review and a recovery
drill. Read-only probes and simulator work may happen earlier.

**Consequences.** Slower demo flash; much lower chance of an avoidable brick.

---

## ADR-010 - Oracle-first parsers

**Context.** v1's sparse constants were scrambled. A parser that agrees only with
itself is dangerous.

**Decision.** Every parser (sparse, zip, `fastboot-info.txt`, AVB, OTA metadata) is
differentially tested against an official tool or a recorded real transcript before
its output can feed a safety rule.

**Consequences.** CI needs oracle tooling. Some tests skip locally when the oracle is
absent but must run in the dedicated CI job.

---

## ADR-011 - Samsung third

**Context.** Samsung's 2026 Maintenance Mode gate creates a recovery dead-end when
Android cannot boot. Heimdall is not a sufficient sole backend.

**Decision.** Sequence fastboot first, OTA second, Samsung third. Samsung starts with
detect/validate/dry-run, a pluggable backend, and SR-021.

**Consequences.** The largest consumer brand is not the first demo. The design is
more honest about recovery risk.

---

## ADR-012 - Naming of distribution, package, and CLI

**Context.** `cairn` is likely taken on PyPI; the repo name is free.

**Decision.** Distribution `cairn-flash`, import package `cairn`, CLI `cairn`.
Version starts at `0.1.0`.

**Consequences.** `pip install cairn-flash` yields the `cairn` command. The PyPI
name was free as of 2026-11-24.

---

## ADR-013 - Evidence provenance

**Context.** Tri-state facts are not enough if a stale or inferred fact can pass a
rule.

**Decision.** Evidence carries source, observation time, freshness bound, and value.
Inferred evidence is never usable; stale evidence becomes `UNKNOWN`; a reboot
invalidates pre-reboot probes.

**Consequences.** More plumbing, fewer silent wrong decisions. Safety rules can
explain themselves.

---

## ADR-014 - Approval is a consistency boundary

**Context.** A per-session key in the same process cannot defend against a malicious
local user.

**Decision.** Approval binds plan, package, snapshot, device nonce, and tool
versions. It protects against TOCTOU drift and bugs, not against a compromised host.
The spec says this plainly.

**Consequences.** No false security claims. Stronger host hardening is a separate
workstream if ever needed.

---

## ADR-015 - Package archives are untrusted and never extracted

**Context.** Factory and OTA packages are large, vendor-controlled zips. Extracting
them creates a second mutable copy and exposes path traversal, duplicate names,
symlinks, encryption, and zip bombs.

**Decision.** Inspect archives in place. Reject unsafe names, duplicate entries,
encrypted entries, symlinks, unsupported compression, and configured count/size
overflows. Report unknown files; never silently ignore them. Nested archives are
reported but not opened until a bounded streaming reader exists. OTA metadata is
read-only and not signature-verified until T09/M8.

**Consequences.** Real Pixel factory zips that keep `fastboot-info.txt` inside a
nested image zip produce an incomplete manifest. No package is treated as verified
from metadata alone.

---

## ADR-016 - Local hash index is a signal, not a signature

**Context.** Repair shops need offline provenance, but a locally editable JSON file
cannot establish authenticity.

**Decision.** Treat an index match as a positive tri-state signal only. Require the
archive SHA-256 and all indexed entry hashes to match. Unknown packages are UNKNOWN
and remain Assisted until AVB/signature verification lands. A mismatch is FALSE and
never overridable. The CLI says plainly that a match is not a signature check.

**Consequences.** Shops can pin known packages without a network, but the index must
later be signed and rotated (M11) before it can contribute to Verified status.

---

## ADR-017 - Planner v0 never reorders or guesses

**Context.** Vendor `fastboot-info.txt` order is the baseline, but slot resolution,
retrofit force mode, and fallback behavior are not yet verified per device.

**Decision.** Preserve vendor order exactly. Emit every skipped if-wipe command as a
deviation. A plan is executable only when provenance is TRUE, the package structure is
understood, every image is present, and requested options are modeled. Unmodeled slot
or retrofit requests produce an explicit non-executable dry run. The fallback is
stop-and-reprobe, not a speculative flash sequence. The plan hash covers the canonical
plan payload.

**Consequences.** The planner is useful for dry runs before slot/retrofit facts exist,
but it cannot authorize a write. Executable plans still require the safety engine and
approval binding.

---

## ADR-018 - AVB parsing is not AVB verification

**Context.** A VBMeta image can be parsed successfully while its RSA signature is
invalid, its chain does not match the device key, or its rollback index would be
rejected by the bootloader.

**Decision.** Keep parsing, digest calculation, signature verification, chain-of-trust
matching, and rollback evaluation as separate gates. `cairn avb` reports descriptors
and the AOSP digest only and always states that signatures and chain-of-trust are not
verified. Parse success never yields TRUE for SR-003 or SR-004.

**Consequences.** The parser is useful for inspection and oracle comparisons before
signature support lands, but it cannot authorize a write or contribute to Verified
status on its own.

---

## ADR-019 - Embedded-key signature validity is not trust

**Context.** A VBMeta signature can verify against the public key embedded in the
same image. An attacker can re-sign a modified image with a new key, so this only
proves internal consistency.

**Decision.** Report embedded-key signature validity as a self-consistency result,
never as authenticity. `cairn avb verify` exits 0 only for a valid signature, but
its output always says the embedded key is not a trust anchor. Authenticity requires
an expected key, a verified chain, or a device-bound key check, and those remain
separate gates. An unsigned image is UNKNOWN, not valid.

**Consequences.** The verifier is useful for corruption and oracle tests now, but
SR-003 stays UNKNOWN until chain-of-trust or lock-state key checks land.

---

## ADR-020 - Chain verification is a consistency gate, not a trust gate

**Context.** AVB chains let a top-level VBMeta authorize a chained partition by
naming the key that signed it. Following that chain proves the chain is
internally coherent. It does not prove the top-level key belongs to the device,
because the top-level key is still the one inside the image being checked.

**Decision.** Verify chains with `verify_vbmeta_chain` as a separate, tri-state,
fail-closed gate. Each chain descriptor's key must equal the chained image's
embedded key, the chained signature must validate, the descriptor's rollback index
location must be non-zero, and the chained VBMeta header's rollback index location
must be zero. Nested chains are followed recursively with cycle detection and a
maximum depth of 8. A missing chained image is UNKNOWN; a key mismatch, an invalid
chained signature, a bad rollback location, a cycle, or an excessive depth is
FALSE. Results combine as FALSE over UNKNOWN over TRUE. A TRUE chain result means
the chain is internally consistent; it is a trust anchor only when the top-level
key was compared against an expected key.

**Consequences.** `cairn avb verify --chain NAME=PATH` can now prove that a
package's VBMeta chain is coherent and can detect a substituted chained image.
It still cannot establish that the package came from the vendor, so SR-003 remains
UNKNOWN until a lock-state-aware or device-bound key check lands.

---

## ADR-021 - Rollback verdicts come from the documented inequality, and unknown is a hard stop

**Context.** AOSP defines rollback protection as the device rejecting an image
unless `rollback_index[n]` >= `stored_rollback_index[n]` for every location `n`,
with the stored value held in tamper-evident storage and differing between A/B
slots. The stored value lives on the device, and the catalog that might describe
it does not exist yet.

**Decision.** Implement the comparison once, in the Rollback Oracle, and derive
every verdict from that inequality. The device's stored value is authoritative
when it can be read, because the bootloader compares against the device. When it
cannot be read, a catalog bound is the only acceptable substitute: an upper bound
can prove the package is safe, a lower bound can prove the package lowers the
counter, and neither means the package may lower it. An unknown stored value is
UNKNOWN, which blocks, and it is never overridable. A verdict that evaluated no
counter at all is UNKNOWN, never TRUE. The oracle carries provenance for every
number it compares, and it ships no OEM counter policy, because the meaning and
direction of OEM counters are device-specific and still unknown (KU-005, KU-009).

**Consequences.** The oracle can be trusted to say "this package definitely
lowers a counter" or "this package cannot lower the counters that were
evaluated", and it refuses to guess in between. It follows nested chain
descriptors with a depth limit and treats missing or malformed chained counters
as unresolved. It parses chain images but does not verify their signatures; SR-003
must pass separately. It cannot yet produce a TRUE verdict on a real device,
because nothing reads the stored indexes; that gap is tracked as KU-030 and
blocks SR-004 until it is closed.

---

## ADR-022 - Device stored-index reads are vendor-specific claims, not AVB verification

**Context.** The Rollback Oracle needs the device's `stored_rollback_index[n]`,
but AOSP fastboot does not define a standard getvar for it. Devices that expose
the value do so through vendor-specific variables with different names and
formats. Observed examples include `stored_rollback_index:5 = 0` and
`avb_stored_rollback_indexes:0:1577836800`. Some devices expose only an OEM
anti-rollback signal such as `ap-ar-s`, whose mapping to AVB locations is unknown.
Some SKUs expose nothing and need a separate EDL path.

**Decision.** Add a narrow, read-only device reader in `rollback/device.py` and
expose it as `cairn rollback read` and `cairn rollback check --device`. It runs
one `fastboot getvar all`, parses only the observed AVB stored-index forms, accepts
decimal values or hex values prefixed with `0x` or containing `A-F`, and rejects
everything else as unresolved. Duplicate identical locations are accepted once;
conflicting, empty, malformed, out-of-range, absent, or truncated values are
unresolved. A failed command produces no trusted indexes. OEM anti-rollback
signals are recorded as warnings and are never mapped to AVB locations. The read
is a device claim; it is not AVB signature verification, and SR-003 remains a
separate gate. `--device` and `--stored` are mutually exclusive so provenance is
unambiguous. The reader never writes to the device.

**Consequences.** SR-004 can now be evaluated with device-reported AVB indexes on
devices that expose one of the observed variables, and it stays UNKNOWN
everywhere else. A successful read does not make a package safe; the oracle still
applies the AOSP inequality. OEM counter policy, the Pixel `ap-ar-s` mapping, and
the EDL fallback remain unresolved (KU-005, KU-009, KU-030). A TRUE verdict from
`rollback check --device` covers only the AVB counters that were evaluated.

---

## ADR-023 - A caller-provided lock state is contextual input, not device-trust evidence

**Context.** The AVB parser can validate an image signature and compare its embedded
key with a known raw AVB public key. The lock state changes how a key mismatch
should be read: a locked bootloader enforces the key, while an unlocked bootloader
does not. However, the current read-only adapter has no hardware finding that
binds a particular bootloader's lock-state signal or root key to the package.

**Decision.** `cairn avb key-check` accepts an explicit lock-state value and a
caller-provided expected key only as contextual inputs. It returns FALSE for an
invalid signature and for a locked mismatch; it returns UNKNOWN for unsigned
images, missing keys, unknown lock state, and unlocked mismatches. A matching key
in a supplied context can be TRUE for offline diagnosis, but it is never emitted
as device evidence and cannot satisfy SR-013. The output explicitly says it did
not read a device root of trust.

**Consequences.** Technicians can inspect the decisive AVB branches without the
tool inventing a hardware claim. A genuine device-bound key gate still requires a
fresh usable lock-state observation, a catalog or hardware finding that anchors
the key, and CLI-to-safety-engine wiring (KU-029, T11).

---

## ADR-024 - Plan structure and safety authorization are separate gates

**Context.** The planner can prove that a package has a well-formed vendor-order
dry run, present images, and modeled options. That does not establish device
identity, AVB authenticity, rollback safety, tool identity, or lock/key state.
Treating a structurally executable plan as authorization would silently convert
missing facts into a pass.

**Decision.** `cairn plan` constructs the candidate first, then evaluates the
SafetyEngine over the evidence the command actually obtained. `PlanAssessment`
exposes `structurally_executable`, the full `SafetyReport`, and a final
`executable` value that is true only when both gates pass. The structural plan hash
and the safety evidence-snapshot hash remain separate inputs for T13 approval
binding. The CLI supplies no placeholder evidence: absent identity, AVB, rollback,
tool, or lock/key inputs remain UNKNOWN and block.

**Consequences.** A dry run remains useful and inspectable, while no caller can
mistake it for permission to execute. A later catalog-bound preflight must collect
and bind the missing evidence before a plan can be executable (KU-031). No write
path is introduced.
