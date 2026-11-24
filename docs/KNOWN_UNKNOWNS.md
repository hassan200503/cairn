# Known Unknowns

**Status as of 2026-11-24.** No item here may be quietly assumed in code. If a fact is
unknown, the rule result is `UNKNOWN`, and `UNKNOWN` blocks.

| ID | Unknown | Impact | How to resolve | Gate |
| --- | --- | --- | --- | --- |
| KU-001 | Which devices expose `max-fetch-size`, and under which lock/build states | Determines whether any fastboot V2 is possible | Read-only probes across Tier A/B devices | M1 |
| KU-002 | Which devices expose `battery-soc-ok`, `battery-voltage`, and `battery-soc`, in what units, and with which HAL thresholds. AOSP semantics are now confirmed (`battery-soc-ok` is voltage vs. flashing threshold) | Battery rule false blocks or false passes | Probe matrix; compare with AOSP fastboot HAL | M1 |
| KU-003 | Exact `avbtool` flags and digest algorithms per package generation | Provenance and AVB verification may reject valid packages | Pin AOSP tools; corpus tests; compare with `pixel_factory_image_verify.py` | M2 |
| KU-004 | Whether bootloaders and fastbootd on Android 13-16 report `snapshot-update-status` with the AOSP strings (`snapshotted`, `merging`, `none`) or vendor variants | Merge-state rule may misclassify | OTA docs, emulator, hardware probes | M6 |
| KU-005 | OEM rollback counters: Xiaomi ARB, Samsung SWREV/binary version, Qualcomm fuses | Anti-brick rule may be blind | Community docs + hardware findings; never guess | M4/M9 |
| KU-006 | Samsung Maintenance Mode reachability when Android cannot boot | Samsung recovery may be impossible; SR-021 | Hardware tests on sacrificial devices; service docs | M9 |
| KU-007 | Samsung binary version / SWREV mapping to package versions | Downgrade detection | Vendor metadata, hardware findings | M9 |
| KU-008 | Knox warranty bit detection and which binaries trip it | Irreversible warning accuracy | Vendor/community docs, hardware findings | M9 |
| KU-009 | Xiaomi anti-rollback values and region differences | Wrong-package brick risk | Community docs, read-only probes, catalog | M4 |
| KU-010 | MediaTek DA authentication matrix and which official flows accept user files | Assisted-tier scope | Vendor docs, hardware findings, legal review | M10 |
| KU-011 | Unisoc download/recovery behavior | Experimental scope only | Read-only research | M12 |
| KU-012 | Which vendor packages ship `fastboot-info.txt` v1 versus an image list, and whether any vendor extends the AOSP grammar. The AOSP v1 grammar itself is now pinned from source | Planner baseline may be wrong | Vendor packages, pinned fastboot differential tests | M1/M3 |
| KU-013 | Fastboot binary behavior changes across platform-tools releases | Silent protocol drift | Pin versions, differential tests, changelog review | M1 |
| KU-014 | Link soak thresholds that predict write failure | Host Doctor false pass/fail | Lab calibration on USB 2/3, hubs, bad cables | M1 |
| KU-015 | Trustworthy post-wipe V3 signals per device. AOSP fastbootd's `slot-successful` is inverted relative to its name, so semantics must be confirmed per device | V3 may be overclaimed | Read-only and wipe drills on sacrificial devices | M6 |
| KU-016 | Dynamic partition metadata versions and edge cases | Wrong create/resize/delete behavior | AOSP docs, `lpmake`/`lpdump` oracles, hardware | M6 |
| KU-017 | Retrofit force-mode behavior per bootloader | Wrong mode for retrofit devices | Vendor docs, hardware findings | M3/M6 |
| KU-018 | Catalog signature format, key rotation, and revocation | Supply-chain trust | Design review, crypto review | M11 |
| KU-019 | Windows driver packaging, signing, and uninstall behavior | Host Doctor setup friction | Lab testing, legal review | M1/M11 |
| KU-020 | Telemetry privacy and consent requirements by market | Legal risk | Counsel review, data minimization | M11 |
| KU-021 | Thor session-reuse limits and device coverage | Samsung backend selection | Repo docs, hardware tests | M9 |
| KU-022 | Heimdall model coverage and failure modes | Samsung backend selection | Hardware tests | M9 |
| KU-023 | OTA payload metadata fields for downgrade checks | Native-path safety | AOSP OTA docs, payload dumps, hardware | M2/M8 |
| KU-024 | EDL programmer/DA matching rules per OEM | Assisted safety | Vendor docs, hardware findings | M10 |
| KU-025 | EDL/MediaTek partition read-back reliability | V2 claims | Hardware tests | M10 |

---

## Promotion rule

An unknown becomes a catalog fact only when:

1. it has a hardware finding ID;
2. the observation is reproducible on a second run or a second device of the same
   model;
3. the source and method are recorded;
4. a safety rule that uses it cites the finding;
5. the finding has a review date and an expiry or re-check trigger.

Until then, it stays here and the rule stays `UNKNOWN`.
