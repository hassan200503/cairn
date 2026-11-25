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
