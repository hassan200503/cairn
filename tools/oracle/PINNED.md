# AOSP partition-tools oracle (lpmake) for differential testing

AGENTS.md rule 9 requires parser output to be differentially tested against an
official tool before it feeds a safety rule. No distro package ships
`lpmake`/`lpunpack`/`lpdump` (KU-033), so this directory builds the official
AOSP host tool from pinned source.

## Pinned sources (shallow-clone HEADs, recorded 2026-11-27)

| Repo | Commit |
| --- | --- |
| platform/system/core | `a3b721a32242006b59cb12bd62c9133632af3a2d` |
| platform/system/libbase | `6d19b5c690fa4220c10e42c2326150bbd4d4b7bb` |
| platform/system/logging | `bcac7c30d88a3773a7c0bc9f5617a23a886331fd` |
| platform/system/extras | `fc2494a2abd7ab21774d03deb09c1362bbb0bba8` |
| madler/zlib | `a28e8d5acad59823917e4e556a87584a803ac15e` |

`build_lpmake.sh` clones these into `$CAIRN_AOSP_ROOT`
(default `~/.cache/cairn-aosp-oracle`) if absent, checks out the pinned
commits, and compiles `lpmake` with a per-object static link.

## Shims (our code, not AOSP modifications)

- `sha256_shim.h`: liblp uses libcrypto only for SHA-256 checksums. We
  force-include an independent FIPS 180-4 implementation with the OpenSSL
  call shapes (`SHA256_Init/Update/Final`, one-shot `SHA256`). Correctness is
  policed by the differential tests themselves: the Python parser recomputes
  every checksum with `hashlib` and must match the oracle-built image.
- `liblog_stub.c`: host logging only. Logging has no effect on emitted
  metadata bytes.

The AOSP sources are never vendored into this repository and are never
modified; they are fetched at build time and pinned by commit.
