# Research Notes

**Checked:** 2026-11-24
**Status:** working notes, not a substitute for hardware findings.
**Rule:** a device-dependent claim is a hypothesis until a `HARDWARE_FINDINGS.md`
entry records a real run.

The v1 review was directionally right. This page records what was actually checked,
what changed as a result, and what remains unknown.

---

## 1. Verification summary

| Claim | Finding | Status | Consequence for v2 |
| --- | --- | --- | --- |
| Sparse file magic | `0xED26FF3A` | Confirmed | v2 uses the AOSP value; CI pins it |
| Sparse chunk types | RAW `0xCAC1`, FILL `0xCAC2`, DONT_CARE `0xCAC3`, CRC32 `0xCAC4` | Confirmed | Same |
| Sparse header sizes | 28-byte file header, 12-byte chunk header | Confirmed | Parser enforces minimums |
| Heimdall license | MIT | Confirmed; v1's GPL claim was wrong | Separate process is optional; attribution required |
| `bkerler/edl` license | GPL-3.0 | Confirmed | Separate process only |
| `bkerler/mtkclient` license | GPL-3.0 | Confirmed | Separate process only |
| Thor license | MPL-2.0 | Confirmed | Separate process; do not copy code into Cairn |
| Samsung Maintenance Mode gate | Required before Download Mode on One UI 8.5 (2026) | Confirmed by multiple reports | Samsung recovery risk; not a first target |
| Samsung Download Mode "removed" | Initially reported as removed; clarified as hidden behind Maintenance Mode | Confirmed nuance | Model as gated, not gone |
| Samsung recovery dead-end | If Android cannot boot, Maintenance Mode may be unreachable | Reported, not yet hardware-confirmed | SR-021 service-risk gate |
| Fastboot generic read-back | Not available | Confirmed | Fastboot tops out at V1 for general partitions |
| `fetch` availability | Only `vendor_boot`, debuggable build, unlocked (orange), size <= `max-fetch-size` | Confirmed in AOSP docs | Cannot be general V2; narrow exception only |
| Dynamic partitions | Bootloader must refuse them; fastbootd handles them; retrofit uses `--force` in bootloader | Confirmed | Planner must respect mode and retrofit case |
| AVB hash vs hashtree descriptors | Both exist; chain partitions delegate to other VBMeta images | Confirmed conceptually | Replace v1 chain-of-trust rule with chain-following + digest |
| AVB rollback indexes per location | Documented | Confirmed conceptually | Rollback Oracle; do not assume one global index |
| `pixel_factory_image_verify.py` | AOSP ships it for Pixel 3+ | Reported in AVB README | Use as a second oracle in M2 |
| Fastboot HAL battery threshold | AOSP includes a minimum flashing battery voltage | Reported | Read device threshold where possible |
| Virtual A/B merge states | Framework/OTA state exists | Partially confirmed | Abstract state machine; pin exact property names in M6 |
| Xiaomi anti-rollback values | Community knowledge | Unverified | Catalog research; never guess |
| Samsung binary version / SWREV | Community knowledge | Unverified | Catalog research; never guess |
| Qualcomm fuse-based counters | Community knowledge | Unverified | Catalog research; never guess |
| MediaTek/Unisoc download auth | Vendor authentication required on many devices | Unverified | Assisted tier only; no bypass |
| Thor session-reuse warning | Reported by the project | Unverified here | Confirm at M9 |
| Heimdall failures on newer devices | Community reports | Unverified here | Pluggable backend required |
| Odin/Thor protocol overview | Wikipedia and project docs | Confirmed at overview level | Not enough for a write path |

---

## 2. Source register

| Tag | Source | URL | Notes |
| --- | --- | --- | --- |
| AOSP-SPARSE | AOSP `system/core/libsparse/sparse_format.h` | https://android.googlesource.com/platform/system/core/+/refs/heads/main/libsparse/sparse_format.h | Header is authoritative; values above are copied from it |
| AOSP-AVB | AOSP AVB 2.0 README | https://android.googlesource.com/platform/external/avb/+/refs/heads/main/README.md | Descriptors, chained partitions, rollback indexes, digest tooling |
| AOSP-FASTBOOTD | AOSP: Move fastboot to userspace | https://source.android.com/docs/core/architecture/bootloader/fastbootd | Bootloader/fastbootd split, dynamic partitions, `fetch` restrictions |
| AOSP-DYNPART | AOSP: Dynamic partitions | https://source.android.com/docs/core/ota/dynamic_partitions | `super`, groups, retrofit, metadata |
| AOSP-DYNPART-IMPL | AOSP: Implement dynamic partitions | https://source.android.com/docs/core/ota/dynamic_partitions/implement | Retrofit flags and bootloader behavior |
| GH-HEIMDALL | Heimdall repository | https://github.com/Benjamin-Dobell/Heimdall | MIT license confirmed via GitHub API |
| GH-THOR | Thor repository | https://github.com/Samsung-Loki/Thor | "An alternative to Heimdall"; MPL-2.0 confirmed via GitHub API |
| GH-EDL | `bkerler/edl` | https://github.com/bkerler/edl | GPL-3.0 confirmed via GitHub API |
| GH-MTKCLIENT | `bkerler/mtkclient` | https://github.com/bkerler/mtkclient | GPL-3.0 confirmed via GitHub API |
| SAMSUNG-2026 | Android Authority, 2026-03-12 | https://www.androidauthority.com/samsung-disables-odin-removes-download-mode-3648469 | Maintenance Mode required before Download Mode; original "removed" report corrected |
| WIKI-ODIN | Wikipedia: Odin (firmware flashing software) | https://en.wikipedia.org/wiki/Odin_(firmware_flashing_software) | Odin/Thor protocol overview; 2026 Maintenance Mode note |
| SAMSUNG-XDA | XDA, April-May 2026 | https://xdaforums.com/t/samsung-s26-ultra-one-ui-8-5-enter-download-mode.4785569 | Community procedure; "create log" must be disabled |
| SAMSUNG-RECOVERY | Aberto até de Madrugada, 2026-09-25 | https://abertoatedemadrugada.com/2026/09/samsung-estraga-modo-de-recuperacao-nos.html | Reported recovery dead-end when Android cannot boot; needs hardware confirmation |
| AOSP-FASTBOOT-SRC | AOSP `system/core/fastboot` (host + `device/` fastbootd), pinned 2026-11-25 | https://android.googlesource.com/platform/system/core/+/refs/heads/main/fastboot | Gitiles tree `c66af46cc55138dd6ee70b51cbeb4501b83d23ec`; every downloaded file verified blob-for-blob with `git hash-object` against the Gitiles listing |
| AOSP-AVBSRC | AOSP `external/avb` README and `avbtool.py` | https://android.googlesource.com/platform/external/avb/+/refs/heads/main | Chain partitions, per-location rollback indexes, VBMeta digest, `verify_image --follow_chain_partitions`, `calculate_vbmeta_digest` |
| PLATFORM-TOOLS-37.0.3 | Android SDK platform-tools 37.0.3 (Windows) | https://developer.android.com/tools/releases/platform-tools | `source.properties`: `Pkg.Revision=37.0.3`; `fastboot.exe` SHA-256 `F8335C9F07A945AA5226418906F0BE42C6349DEF16643343549174E55AC7C789`; `fastboot --version`: `37.0.3-16887417` |
| USB-DRIVER-13 | Android USB driver package r13 (Windows) | https://developer.android.com/studio/run/win-usb | `usb_driver/source.properties`: `Pkg.Revision=13` |

AOSP `main` branches move. Before M2, pin the exact commit hashes used for the
sparse and AVB oracles in the tool manifest.

---

## 3. What changed in the plan because of research

### 3.1 Sparse

The parser is now seeded with the correct AOSP constants and a test that pins them.
The libsparse differential harness remains an M0 acceptance criterion. The values in
v1 would have produced a parser that rejects every real sparse image.

### 3.2 Fastboot read-back

The AOSP `fetch` constraints are stronger than "the bootloader might not implement
it." `fetch` is only for `vendor_boot` on a debuggable, unlocked device. A locked
production phone cannot use it. Therefore:

- fastboot verification is V1 for general partitions, full stop;
- V2 is an EDL/MediaTek capability, or the narrow `vendor_boot` case;
- catalog entries must not advertise V2 for fastboot jobs.

This removes a class of overconfident reports before it existed.

### 3.3 Samsung

Samsung has become a recovery-risk market, not just a protocol-risk market. The
Maintenance Mode gate is real, and the reported dead-end when Android cannot boot is
exactly the scenario a recovery tool exists for. Consequences:

- Samsung is third in scope, not first.
- M9 starts with detect/validate/dry-run.
- A Samsung job requires a stated recovery path or a typed service-risk acceptance
  (SR-021).
- The backend must be pluggable; Heimdall alone is not enough.

### 3.4 Licensing

Corrections are normative:

- Heimdall is MIT, not GPL.
- Thor is MPL-2.0, not GPL.
- `bkerler/edl` and `bkerler/mtkclient` are GPL-3.0; separate-process isolation stays.

### 3.5 AVB

The v1 "every image hash is in vbmeta" rule is replaced by chain-following
verification, VBMeta digest comparison, and lock-state-aware key checks. Exact
`avbtool` flags are pinned in M2. The rule must handle chained VBMeta images and
per-location rollback indexes.

### 3.6 Planner

AOSP confirms the bootloader/fastbootd split and the bootloader's duty to refuse
dynamic partition writes. Vendor order is the baseline; `--force` is for retrofit
factory flows, and AOSP warns against using it casually. The planner treats force
mode as catalog-gated.

---

## 4. Research still open

These are tracked in [KNOWN_UNKNOWNS.md](KNOWN_UNKNOWNS.md). The highest-impact ones:

1. Which devices expose `max-fetch-size` / meaningful battery getvars, and under
   which lock states.
2. Exact `avbtool` invocation and digest algorithm for each package generation.
3. Virtual A/B merge property names and fastbootd command behavior across Android
   13-16.
4. Per-OEM rollback counters: Xiaomi ARB, Samsung SWREV/binary version, Qualcomm
   fuses, and whether any can be read safely before writing.
5. Samsung Maintenance Mode reachability when Android is unbootable, and whether a
   service path exists on each model.
6. MediaTek DA / Unisoc authentication matrix; which official flows accept
   user-supplied files without bypass.
7. Fastboot binary behavior changes across platform-tools releases, especially
   `fastboot-info.txt` support.
8. Link soak thresholds: throughput and error rates that predict a failed write on
   USB 2 vs USB 3, hubs, and Windows driver stacks.
9. Post-wipe V3 signals per device; which slot getvars are trustworthy.
10. Catalog signature design and key rotation.

---

## 5. Method notes

- License checks used the GitHub license API on 2026-11-24, not memory.
- AOSP sparse values were decoded from the raw `sparse_format.h` source.
- Samsung reporting was cross-checked across Android Authority, Wikipedia,
  PiunikaWeb, SammyFans, and XDA. The "removed" headline was corrected in the same
  reporting cycle; the spec models the gate, not removal.
- No real devices were touched for these notes. Nothing here constitutes a hardware
  finding.

---

## 6. Fastboot primary-source verification (2026-11-25)

The claims below were checked against the pinned AOSP source, not memory. Downloaded
files were verified blob-for-blob against the Gitiles tree listing with
`git hash-object`, so the notes describe exactly the code that was read.

### 6.1 Protocol and host driver

- Protocol version is `0.4`. Responses are `OKAY`, `FAIL`, `DATA`, `INFO`, `TEXT`.
  `INFO` and `TEXT` reset the host's 30-second response timer
  (`RESP_TIMEOUT = 30` in `fastboot_driver.h`).
- `download:%08x` is the wire command; the device answers `DATA%08x`. The `flash`
  ack (`OKAY`) is the only write acknowledgement. There is **no automatic retry** in
  the host driver; resume and retry are Cairn's responsibility.
- The host resparses images to the device's `max-download-size` and caps each
  respit at `RESPARSE_LIMIT = 1 GiB`. fastbootd reports
  `kMaxDownloadSizeDefault = 0x10000000` (256 MiB) from `device/commands.h`.
- `getvar all` output is emitted on stderr as `(bootloader) name:value` lines
  (`InfoMessage` in `fastboot.cpp`). The adapter parser must key on that prefix.
- `fetch` is compile-time disabled on user builds, refuses locked devices, and its
  allowlist is exactly `vendor_boot`, `vendor_boot_a`, `vendor_boot_b`
  (`kAllowedPartitions` in `device/commands.cpp`). The size cap is
  `kMaxFetchSizeDefault = 0x10000000` (256 MiB), and the host fetches in
  `max-fetch-size` chunks. General fastboot read-back remains impossible.

### 6.2 getvar facts

- Battery variables in fastbootd: `battery-voltage` (millivolts),
  `battery-soc` (state of charge), and `battery-soc-ok`. **Correction:**
  `battery-soc-ok` compares battery voltage against the fastboot HAL's
  `getBatteryVoltageFlashingThreshold`; it is not a state-of-charge percentage.
- `snapshot-update-status` returns `snapshotted`, `merging`, or `none`; it fails
  with `not supported` when the boot-control 1.1 HAL is absent. The commands
  `snapshot-update:cancel` and `snapshot-update:merge` exist; the help text warns
  that cancel may make the device unbootable until reflashed.
- The fastbootd getvar map also exposes `is-userspace`, `max-fetch-size`,
  `super-partition-name`, `dynamic-partition`, `system-fingerprint`,
  `vendor-fingerprint`, `security-patch-level`, `first-api-level`,
  `battery-serial-number`, and `battery-part-status`.
- **Trap:** fastbootd's `slot-successful:<slot>` implementation returns `no` when
  the slot is marked successful, the inverse of the natural reading of the name.
  AOSP code is the source of truth here, but a bootloader may differ. Slot
  signals are therefore recorded as raw values with `UNKNOWN` semantics until a
  hardware finding confirms them.

### 6.3 fastboot-info.txt and flashall

- `fastboot-info.txt` version is `1` (`FASTBOOT_INFO_VERSION = 1`). Parsed lines:
  `version N` (N <= host version), `if-wipe <command>`, `flash PART [IMG]
  [--apply-vbmeta] [--slot-other]`, `reboot [bootloader|fastboot|recovery]`,
  `update-super`, and `erase PART`. `#` starts a comment. Unknown commands fail
  the parse. Default image name is `<partition>.img`.
- `update-super` requires a `lpmake` image, not a sparse image. Without `wipe` it
  merges metadata, creates missing partitions with zero size, and preserves the
  other slot; with `wipe` it deletes all logical partitions.
- Official `flashall` calls `set_active` **before** flashing and auto-sends
  `snapshot-update:cancel` when a merge or snapshot is in progress. Both behaviors
  are unsafe to mirror blindly. Cairn must journal an explicit `set_active` and
  must never auto-cancel a merge.
- Official fastboot refuses dynamic-partition writes in bootloader fastboot unless
  it is in fastbootd or `--force` is set. Retrofit/super flows use
  `oem allow-flash-super` around a generated super image.
- Super optimization pattern: `reboot fastboot` + `update-super` + dynamic
  `flash` lines are replaced by one optimized sparse `super` write when the device
  is A/B, `super_empty.img` exists, and the super size is known. This avoids the
  fastbootd reboot but is not available for `--slot all`.
- The host and fastbootd both move an AVB footer to the end of the partition when
  flashing a shorter `boot`/`init_boot` image. The bytes written are not just the
  image file; the journal must record the actual padded size.

### 6.4 AVB

- AVB 2.0 uses hash descriptors, hashtree descriptors, and chained partition
  descriptors. Rollback indexes are per location (`rollback_index[n]` versus
  `stored_rollback_index[n]`) and can differ per slot.
- `avbtool verify_image` supports `--expected_chain_partition` and
  `--follow_chain_partitions`; `avbtool calculate_vbmeta_digest` computes the
  digest over the root and all chained VBMeta structs. `pixel_factory_image_verify.py`
  is a convenience tool in `tools/transparency` for Pixel 3 and later factory
  images, not part of the AVB repository itself.

### 6.5 Consequences for the plan

- Planner/executor: do not wrap `flashall`/`update` as a black box. Drive explicit
  commands so `set_active`, snapshot state, and per-piece writes are journaled.
- Safety: never infer slot success from the getvar name; `battery-soc-ok` is a
  voltage gate; merge cancel requires explicit typed approval and a recovery path.
- Verification: fastboot remains V1 for general partitions; only the narrow
  `vendor_boot` fetch case can reach V2.
- Tool pinning: platform-tools 37.0.3 hash is recorded above; the Windows USB
  driver package is r13. These are host artifacts, not device facts.
