# Recovery Kit threat model (T15)

Status: **implemented in the simulator, externally unreviewed** (KU-032). Nothing
here is device evidence; every restore path is transcript-simulator only
(ADR-027) until the M6 gate (G3) passes an external safety review.

## 1. What the recovery kit protects

The kit answers one question: *if this flash bricks the device, can we put the
operator back where they started?* It has three parts:

1. **Asset verification** (`cairn.recovery.assets`) — tri-state SR-008 check that
   the declared recovery assets exist and hash-match.
2. **Critical-partition vault** (`cairn.recovery.vault`) — an encrypted,
   device-bound backup of readable critical partitions (SR-009).
3. **The M6 drill** (`cairn.recovery.drill`) — a scripted proof that the vault
   round-trips and that cross-device restore is refused.

## 2. Assets and adversaries

| Asset | Harm if lost or forged |
| --- | --- |
| Critical partition images (e.g. `persist`, modem NVRAM) | Unrecoverable device: IMEI/calibration Wi-Fi keys gone |
| Vault decryption passphrase | Backup is unreadable exactly when it is needed |
| Device identity binding | A backup restored onto the wrong device corrupts *two* devices |

Adversaries considered: a careless operator (wrong file, wrong device, skipped
backup); a malicious or corrupted package that wants a wipe to proceed without a
backup; an attacker with read access to the vault file or the host filesystem.
**Out of scope:** an attacker who controls the host before the backup is made,
and physical extraction from the device after a successful flash — no host-side
tool can defend those.

## 3. Vault design and its threats

The vault (`VaultDocument`) is canonical JSON: device binding (`product`,
`serial_sha256`, `fingerprint_sha256`), per-partition entries (nonce, ciphertext,
plaintext sha256), creation timestamp.

- **Key derivation.** Two domain-separated 256-bit keys are derived from the
  passphrase and a random 16-byte per-vault salt with HMAC-SHA256 in an HKDF-style
  extract/expand (info strings `cairn-vault-enc-v1` / `cairn-vault-mac-v1`). An
  encryption key and a MAC key are never the same key.
- **Encryption.** HMAC-SHA256 in counter mode generates a keystream; the image is
  XORed with it. Per-entry random 16-byte nonces; a repeated nonce would reuse the
  keystream, so nonces are random and entries are single-writer.
- **Integrity.** Encrypt-then-MAC: the HMAC covers the entire canonical document,
  including the device binding and every recorded plaintext hash. Any byte change
  anywhere makes `load_vault` raise `VaultTamperedError`.
- **Plaintext check.** On decrypt, the plaintext sha256 is recomputed against the
  recorded hash; a MAC-valid entry whose plaintext does not hash correctly raises
  `VaultError` rather than being staged.
- **Unsafe names refused.** Vault partition names are validated (`..`, path
  separators, and duplicate entries are refused) so a vault entry can never name
  a partition outside the intended namespace.

Known limitations, deliberately recorded rather than hidden (KU-032):

- No memory hardening: HMAC-SHA256 derivation is fast; an offline dictionary
  attack on a stolen vault file is feasible for weak passphrases. Mitigation is
  operational (long generated passphrases in a file, never a shell argument).
- The CTR construction is hand-rolled. It is small, MAC-covered, and reviewed
  only by this project's own tests; an external crypto review is an explicit
  acceptance condition (KU-032) before any real-device use.
- No KDF stretch (iterations) yet; adding one is a format-version change.

## 4. Restore-only-same-device

`restore_check(vault, device)` compares all three identity fields and raises
`VaultDeviceMismatch` on **any** difference. This check is a hard refusal, never
overridable: a backup for one device restored onto another transplants
device-specific calibration or identity data and can brick both. The CLI enforces
the same identity on the operator's command line — raw serials are never
accepted, only their sha256, so no serial is copied into logs, sessions, or
transcripts.

## 5. The drill

`cairn recovery drill` runs the whole chain and fails unless every step passes:

asset hash verification → a stated last-resort recovery path (empty text is a
refused job) → vault backup → reload-and-decrypt integrity → **cross-device
restore attempt must be refused** → same-device restore write through the journaled
simulator only. The report is labelled `SIMULATED` and `verdict: TRUE` from a
drill is not device evidence; the drill's value is proving the refusal paths fire,
not proving hardware recovery.

The drill demands the simulator (`--simulate TRANSCRIPT`); there is no argument
that points it at a real fastboot binary, matching ADR-027.

## 6. What the M6 gate still requires before any real-device write

- External crypto review of the vault format (KU-032).
- External safety review of the SR-008/SR-009 enforcement and the drill.
- Real scrubbed device transcripts and hardware findings (G0 remains unmet).
- The Virtual A/B / dynamic-partition state machines (M6 scope, unstarted).
