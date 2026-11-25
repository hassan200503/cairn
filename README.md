# Cairn

**Mark the path. Verify the state.**

Cairn is a fail-safe Android flashing workbench. It refuses unsafe jobs before the
first write, verifies every write at a stated level, journals every step so an
interrupted job can resume or roll back to a known state, and checks that a recovery
path exists before taking risk.

> Cairn (n.): a stack of stones that marks a proven path across uncertain ground.
> Every flash leaves a cairn behind: evidence of where you have been and how to get
> back.

**Status:** pre-alpha. The v2 specification and execution plan are complete; the M0
foundation is in progress. Cairn does not flash a real device yet.

[![CI](https://github.com/hassan200503/cairn/actions/workflows/ci.yml/badge.svg)](https://github.com/hassan200503/cairn/actions/workflows/ci.yml)

## The promise

Phones are physical devices on cables. "Almost impossible to fail" is a direction,
not a state. Cairn measures and reports:

- unsafe jobs refused before any write;
- every write verified at a named level (V0-V3);
- every interruption resumable or rolled back to a known state;
- a recovery path checked before risk is taken.

It does not promise that nothing can go wrong. It promises to **fail safe, not fail
never**, and to never hide which of the two happened.

## What Cairn is

- A planner that uses the vendor's tested flash order as the baseline and deviates
  only for catalog-proven commutations.
- A safety engine over tri-state facts (`TRUE`, `FALSE`, `UNKNOWN`) with provenance,
  observation time, and freshness bounds.
- A transactional executor with a write-ahead journal, crash-safe resume, and
  reconciliation after every interruption.
- A provenance and AVB checker that establishes what a package is before trusting
  what it contains.
- A Host Doctor for the most common real-world failure: the host, cable, driver, or
  link, not the phone.
- A Recovery Kit and encrypted, device-bound Critical Partition Vault.
- Simulators driven by recorded real-device transcripts, plus fault injection.

## What Cairn is not

Cairn will never include FRP bypass, IMEI changes, carrier-lock circumvention, loader
authentication bypass, or signature-check defeat. Cross-device data transplant is
not allowed. Restoring a device's own backed-up data to that same device is allowed.

## Verification levels

The word "verified" is never printed without a level.

| Level | Meaning |
| --- | --- |
| V0 | Transport acknowledged the write. |
| V1 | Host-side source hash matched the manifest, and the device acknowledged. |
| V2 | Device read-back hash matched the source (where the device supports it). |
| V3 | Post-boot identity was confirmed (bootloader slot signals, adb fingerprint, or a user-confirmed first boot). |

Fastboot tops out at V1 for general partitions: there is no generic partition
read-back in the fastboot protocol, and AOSP's `fetch` is restricted to `vendor_boot`
on debuggable, unlocked devices. The report says so instead of pretending otherwise.

## The native-path ladder

Cairn selects the least invasive path that satisfies the job:

1. Signed full OTA through `adb sideload` or `update_engine` (device-side
   verification and slot logic).
2. Vendor flashing flow driven by `fastboot-info.txt`.
3. Per-partition fastboot flashing.
4. Low-level modes (EDL, MediaTek preloader, Samsung download mode) as Assisted
   tier, with user-supplied programmer/DA files where required.

## Quickstart

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```console
uv sync
uv run cairn version
uv run cairn levels
uv run cairn doctor
uv run cairn probe --serial <serial>
uv run cairn inspect <package.zip>
uv run cairn provenance <package.zip> --index <index.json>
uv run cairn plan <package.zip> --index <index.json>
uv run cairn avb info <vbmeta.img>
uv run cairn avb digest <vbmeta.img> [--chain boot=<boot.img>]
uv run cairn avb verify <vbmeta.img> [--key <key.avbpubkey>]
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest -q
```

`cairn doctor` runs read-only host checks (WSL/VM, USB controllers, tool versions,
power policy, antivirus heuristics) and a bounded `getvar` link soak. `cairn probe`
performs a read-only `getvar all`. Both can replay a recorded transcript with
`--simulate`, which is labeled as simulated and never treated as device evidence.
`cairn inspect` parses a factory or OTA zip without extracting it, reports unknown
entries and nested archives, and can hash every entry with `--hash`. The `cairn
provenance` command hashes a package and compares it with a local JSON index; a match
is a signal, not a signature check. `cairn plan` emits a read-only vendor-order dry
run with a canonical plan hash and refuses to mark it executable unless provenance is
TRUE and every requested option is modeled. `cairn avb` parses standalone, padded,
or footer-embedded VBMeta images, computes the AOSP digest including supplied
chained images, and verifies the RSA signature against the embedded key or an
expected raw AVB public key. Embedded-key validity is not a trust anchor, and
chain-of-trust and rollback are not checked yet. None of these commands writes to a
device.

## Repository map

```text
src/cairn/
  core/          tri-state logic, evidence graph, verification levels, errors
  tools/         bounded subprocess runner and pinned tool manifest
  sparse/        AOSP sparse format primitives, validation, and the libsparse oracle
  adapters/      read-only device transports (fastboot first)
  host/          Host Doctor: drivers, USB, power, virtualization, link soak
  package/       fastboot-info and factory/OTA package inspection
  plan/          read-only vendor-order planner and plan hash
  provenance/    offline hash index and AVB VBMeta parsing (partial)
  safety/        safety rule engine and override policy
  sim/           transcript schema and fault-injecting fastboot simulator
docs/
  SPEC_V2.md          the reviewed, corrected v2 specification
  EXECUTION_PLAN.md   workstreams, phases, gates, first tasks
  ROADMAP.md          M0-M12 with acceptance criteria
  RESEARCH_NOTES.md   verified sources and open research questions
  SAFETY_RULES.md     rule IDs, defaults, provenance requirements
  DECISIONS.md        architecture decision records
  KNOWN_UNKNOWNS.md   what we do not know yet
  HARDWARE_FINDINGS.md findings from real device runs
```

## Scope order

1. Qualcomm/fastboot class (AOSP-documented; proves the core).
2. `adb sideload` and `update_engine` (cheap, safe, broad).
3. Samsung with a pluggable backend and explicit Knox warnings.
4. EDL and MediaTek as Assisted tier.
5. Unisoc analysis only.

Samsung's 2026 Maintenance Mode gate, and the fact that Download Mode may be
unreachable when Android cannot boot, make Samsung a recovery-risk market rather
than a first target. That is recorded, not hand-waved.

## License

Apache-2.0 for the core. The signed device catalog is intended to be a separate
commercial asset. Tools invoked as separate processes keep their own licenses:
Heimdall is MIT, Thor is MPL-2.0, and bkerler/edl and mtkclient are GPL-3.0.

## Documentation

Start with [the v2 specification](docs/SPEC_V2.md) and [the execution plan](docs/EXECUTION_PLAN.md).
