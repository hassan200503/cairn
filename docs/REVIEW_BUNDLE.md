# External Review Bundle (KU-032)

**Status:** prepared, awaiting reviewers. This bundle exists so that an external
cryptographer and a safety reviewer can audit the recovery-vault and M6-drill
design without hunting through the repository. The M6 gate (no real-device
writes) stays closed until both sign-offs exist; this file records what is
offered for review and what a sign-off must state.

## 1. Scope

| Item | What it is | Why it needs review |
| --- | --- | --- |
| `src/cairn/recovery/vault.py` | Encrypted, device-bound backup container (format v2, ADR-028/ADR-029) | Hand-rolled encrypt-then-MAC over HMAC-SHA256-CTR; PBKDF2-HMAC-SHA256 stretch at 600,000 iterations; device binding via `product` + `serial_sha256` + `fingerprint_sha256` |
| `src/cairn/recovery/assets.py` | SR-008 recovery-asset verification (tri-state) | A FALSE/UNKNOWN here must never let a wipe or relock proceed |
| `src/cairn/recovery/drill.py` | The M6 drill: verify → backup → same-device restore → cross-device refusal | The drill is the evidence the M6 gate requires; its logic must match the threat model |
| `docs/RECOVERY_THREAT_MODEL.md` | The threat model the above implement | Reviewers check the code against the model, not against marketing |
| `docs/SAFETY_RULES.md` SR-008/SR-009 | The rules the safety engine evaluates | Check the FALSE/UNKNOWN/block defaults |

## 2. What a sign-off must state

A review sign-off (recorded in `docs/KNOWN_UNKNOWNS.md` and `docs/STATE.md`) must
state, explicitly:

1. **Scope and version.** The exact commit SHA and files reviewed.
2. **Verdict per finding.** Each finding classified as `blocker`, `advisory`, or
   `informational`, with a recommended fix.
3. **Crypto verdict.** Whether the vault construction is acceptable for its
   stated boundary (casual access and tampering, NOT a compromised host —
   ADR-014), or must be replaced (e.g., move to AES-256-GCM with a reviewed
   dependency before M6).
4. **Safety verdict.** Whether the drill proves what the M6 gate requires, and
   whether the same-device-only restore refusal is correctly never-overridable.
5. **Residual risk.** What the reviewers could not check (they have no hardware).

## 3. How to reproduce the claims

```console
uv sync
uv run pytest -q                       # full suite; recovery tests in tests/test_recovery.py, tests/test_cli_recovery.py
python tools/mutation_check.py         # 48/48 safety-rule and approval-binding mutants killed
uv run ruff check . && uv run ruff format --check . && uv run mypy src
```

The vault round trip, wrong-passphrase refusal, every-byte tamper refusal,
kdf-edit tamper refusal, v1-file refusal, and same-device-only restore are
pinned by tests in `tests/test_recovery.py`. The drill's cross-device refusal is
pinned in the same file.

## 4. Known limitations (stated up front)

- The keystream is HMAC-SHA256-CTR, not AES-GCM: stdlib-only by policy (ADR-028).
  A reviewed `cryptography` dependency adoption is a separate decision record.
- The device binding hashes identity strings; it is as strong as the probe that
  produced them, and a probed identity is evidence, not proof (ADR-013).
- The passphrase is the user's; PBKDF2 at 600,000 iterations raises the offline
  cost but cannot save a one-word passphrase.
- The drill writes only through the transcript simulator (ADR-027); it proves the
  flow, not flash hardware behavior.
