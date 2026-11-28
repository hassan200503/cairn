# Hardware Findings

**Status:** no hardware findings yet. This file starts empty on purpose.

Every real-device run produces a finding, even a boring one. Findings feed the
catalog, the simulators, and the safety rules. A rule that depends on device behavior
and has no finding ID is `UNKNOWN`.

---

## 1. Safety and privacy rules

- Never publish IMEI, serial numbers, MAC addresses, phone numbers, account names, or
  personal data. Use a lab ID and a model/codename.
- Store device-bound identity only in the local Vault, not in this file.
- Scrub screenshots, logs, and transcripts before committing. Replace unique
  identifiers with stable placeholders.
- Use sacrificial devices. Never a daily driver.
- Read-only probes are allowed before M6. Writes are not.

---

## 2. Finding template

Copy this block into the table below and fill every field. Unknown fields are written
as `unknown`, not omitted.

```yaml
id: HF-0001
date: 2026-11-24
status: observed | reproduced | confirmed | retired
category: capability | identity | rollback | recovery | quirk | failure
device:
  model: Pixel 8
  codename: shiba
  region: US
  firmware_build: AP1A.xxxx
  bootloader_lock: locked | unlocked | unknown
  slots: 2
  dynamic_partitions: true
host:
  os: Windows 11 24H2
  platform_tools: 36.0.0
  cable_port: rear USB 3, direct
commands:
  - cmd: getvar max-fetch-size
    expected: unknown
    observed: "0"
result:
  max_verification_level: V1
  writes_performed: none
  artifacts: [scrubbed transcript path]
safety_impact: >
  Fastboot V2 is not available; catalog must not advertise it.
source_refs: [AOSP-FASTBOOTD]
notes: >
  Reproduced twice. Serial redacted.
```

---

## 3. Status definitions

| Status | Meaning |
| --- | --- |
| observed | Seen once, on one device, by one operator |
| reproduced | Seen again on a second run or a second device of the same model |
| confirmed | Reproduced and reviewed; may feed a catalog entry and a safety rule |
| retired | No longer true for the pinned firmware/tool versions |

Promotion to the catalog requires `confirmed`. A safety rule may cite an `observed`
finding only as a warning, never as a pass.

---

## 4. Findings

| ID | Date | Device | Category | Summary | Status |
| --- | --- | --- | --- | --- | --- |
| - | - | - | - | No findings recorded yet | - |

---

## 5. Read-only probe checklist

For the first pass on any device, record:

- `getvar all` (scrubbed)
- `getvar current-slot`
- `getvar slot-count`
- `getvar slot-successful:*`
- `getvar slot-unbootable:*`
- `getvar slot-retry-count:*`
- `getvar unlocked` / lock-state equivalent
- `getvar max-download-size`
- `getvar max-fetch-size` (presence and value)
- `getvar battery-voltage`, `battery-soc`, `battery-status` (whatever exists)
- `getvar is-userspace`
- `getvar super-partition-name`
- `getvar partition-size:*` for key partitions
- `getvar product`, `variant`, `version-bootloader`, `version-baseband`
- dynamic partition capability, if exposed

`cairn probe --capture DIR` runs this checklist automatically: it journals every
invocation in a transcript, scrubs serials, and writes a §2-template finding
draft (`finding.yaml`) next to the transcript with its SHA-256. Review the draft
before promoting it into §4 — a capture is one observation; a finding needs
reproduction (§3).

Do not run `fetch` on a locked production device: AOSP restricts it to `vendor_boot`
on debuggable, unlocked devices. Record the refusal if you test it.

---

## 6. From finding to catalog

1. Add the finding here with a scrubbed transcript.
2. Open a catalog change that cites the finding ID.
3. Add or update a simulator fixture.
4. If a safety rule changes, add a mutation test.
5. Link the finding in the release report.
