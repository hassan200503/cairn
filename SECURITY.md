# Security Policy

## Reporting

Report vulnerabilities privately through GitHub Security Advisories:

https://github.com/hassan200503/cairn/security/advisories/new

Do not open a public issue for an unpatched vulnerability. Include:

- affected version or commit;
- a reproduction, with secrets and device identifiers removed;
- impact on the safety rules, journal, approval binding, or write path;
- whether a real device could be bricked or data could cross devices.

## Scope

In scope:

- bypassing a safety rule or approval binding;
- causing a write without a valid approval;
- verification-level misreporting;
- journal/reconcile bugs that can re-run a non-idempotent operation;
- cross-device Vault restore or data leakage;
- prompt injection that changes a plan or invokes a tool;
- supply-chain issues in pinned tools or the catalog.

Out of scope:

- requests for FRP bypass, IMEI changes, carrier-lock circumvention, loader
  authentication bypass, or signature-check defeat;
- attacks that require a already-fully-compromised host with the same privileges as
  Cairn; approval is a consistency boundary, not a defense against a malicious local
  user;
- physical attacks on the device.

## Design boundaries

- The per-session approval key protects against bugs and TOCTOU drift, not against a
  malicious local user.
- The signed catalog is a trust root; its signing keys must be protected and rotated.
- GPL-3.0 tools are separate processes; their vulnerabilities are reported upstream
  and mitigated with version pinning where possible.

## Disclosure

We aim to acknowledge a report within 72 hours and to publish an advisory after a fix
is available. Credit is given unless the reporter asks otherwise.
