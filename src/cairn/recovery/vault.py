"""Critical Partition Vault.

Before a wipe or relock, readable critical partitions (``persist``, modem/EFS-class
data, calibration, nvdata-class data) are backed up encrypted, hashed, and bound to
the device identity (SPEC_V2 3.7, SR-009). A vault entry can ever be restored only
to the device identity it was bound to; any mismatch is FALSE and is never
overridable. Cross-device restore is refused unconditionally — this preserves the
IMEI/data-transplant non-goals.

Crypto, v0 (ADR-028): the vault uses only Python-stdlib primitives. A per-vault
random salt and a passphrase are expanded with an HMAC-SHA256 HKDF-style
extract-and-expand into two domain-separated keys (encryption, MAC); payload bytes
are encrypted with an HMAC-SHA256-CTR keystream and authenticated encrypt-then-MAC
over the canonical header plus ciphertexts. This construction is deliberately
conservative and its external cryptographic review is still pending (KU-032); the
vault is a confidentiality-and-integrity container against casual access and
tampering, not a defence against a compromised host (same boundary as ADR-014).
When a reviewed ``cryptography`` dependency is adopted (a decision record is
required for that), the scheme should move to AES-256-GCM.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from cairn.core.errors import RecoveryError

VAULT_KIND: Final = "cairn.vault"
VAULT_SCHEMA_VERSION: Final = 1
MAX_VAULT_BYTES: Final = 512 * 1024 * 1024
MAX_ENTRY_NAME_CHARS: Final = 128
_SALT_BYTES: Final = 16
_NONCE_BYTES: Final = 16
_MAC_BYTES: Final = 32
_PARTITION_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")

_ENTRY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "partition",
        "sha256",
        "size",
        "nonce_b64",
        "ciphertext_b64",
    }
)


class VaultError(RecoveryError):
    code = "VAULT_ERROR"


class VaultTamperedError(VaultError):
    code = "VAULT_TAMPERED"


class VaultDeviceMismatch(VaultError):
    code = "VAULT_DEVICE_MISMATCH"


@dataclass(frozen=True, slots=True)
class VaultDevice:
    """The device identity a vault is bound to; hashes only, never a raw serial."""

    product: str
    serial_sha256: str
    fingerprint_sha256: str

    def __post_init__(self) -> None:
        if not self.product.strip() or len(self.product) > MAX_ENTRY_NAME_CHARS:
            raise VaultError("vault device product must be 1-128 characters")
        for name, value in (
            ("serial_sha256", self.serial_sha256),
            ("fingerprint_sha256", self.fingerprint_sha256),
        ):
            if _HEX64_RE.fullmatch(value) is None:
                raise VaultError(f"vault device {name} must be 64 lowercase hex characters")

    def to_dict(self) -> dict[str, str]:
        return {
            "product": self.product,
            "serial_sha256": self.serial_sha256,
            "fingerprint_sha256": self.fingerprint_sha256,
        }

    @classmethod
    def from_dict(cls, raw: object) -> VaultDevice:
        if not isinstance(raw, dict):
            raise VaultError("vault device must be a JSON object")
        if set(raw) != {"product", "serial_sha256", "fingerprint_sha256"}:
            raise VaultError("vault device has unknown or missing keys")
        return cls(
            product=_string(raw["product"], "vault device product"),
            serial_sha256=_string(raw["serial_sha256"], "vault device serial_sha256"),
            fingerprint_sha256=_string(
                raw["fingerprint_sha256"], "vault device fingerprint_sha256"
            ),
        )

    def matches(self, other: VaultDevice) -> bool:
        return hmac.compare_digest(self.serial_sha256, other.serial_sha256) and (
            hmac.compare_digest(self.fingerprint_sha256, other.fingerprint_sha256)
        )


@dataclass(frozen=True, slots=True)
class VaultEntry:
    partition: str
    plaintext_sha256: str
    size: int
    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        if _PARTITION_RE.fullmatch(self.partition) is None:
            raise VaultError(f"unsafe vault partition name {self.partition!r}")
        if len(self.partition) > MAX_ENTRY_NAME_CHARS:
            raise VaultError(f"vault partition name {self.partition!r} is too long")
        if _HEX64_RE.fullmatch(self.plaintext_sha256) is None:
            raise VaultError(f"vault entry {self.partition!r} sha256 must be 64 lowercase hex")
        if self.size < 0:
            raise VaultError("vault entry size must not be negative")
        if len(self.nonce) != _NONCE_BYTES:
            raise VaultError("vault entry nonce must be 16 bytes")
        if self.size != len(self.ciphertext):
            raise VaultError(f"vault entry {self.partition!r} size does not match its ciphertext")


@dataclass(frozen=True, slots=True)
class Vault:
    """An encrypted, device-bound container of critical partition backups."""

    created_at: datetime
    device: VaultDevice
    salt: bytes
    entries: tuple[VaultEntry, ...]

    def __post_init__(self) -> None:
        if self.created_at.tzinfo is None:
            raise VaultError("vault created_at must be timezone-aware")
        if len(self.salt) != _SALT_BYTES:
            raise VaultError("vault salt must be 16 bytes")
        if not self.entries:
            raise VaultError("vault must contain at least one entry")
        names = [entry.partition for entry in self.entries]
        if len(names) != len(set(names)):
            raise VaultError("vault repeats a partition entry")

    @property
    def partitions(self) -> tuple[str, ...]:
        return tuple(entry.partition for entry in self.entries)

    def entry(self, partition: str) -> VaultEntry | None:
        for entry in self.entries:
            if entry.partition == partition:
                return entry
        return None

    def to_document(self) -> dict[str, object]:
        return {
            "kind": VAULT_KIND,
            "schema_version": VAULT_SCHEMA_VERSION,
            "created_at": self.created_at.astimezone(UTC).isoformat(),
            "device": self.device.to_dict(),
            "salt_b64": base64.b64encode(self.salt).decode("ascii"),
            "entries": [
                {
                    "partition": entry.partition,
                    "sha256": entry.plaintext_sha256,
                    "size": entry.size,
                    "nonce_b64": base64.b64encode(entry.nonce).decode("ascii"),
                    "ciphertext_b64": base64.b64encode(entry.ciphertext).decode("ascii"),
                }
                for entry in self.entries
            ],
        }

    def to_json(self, *, passphrase: str) -> str:
        document = self.to_document()
        mac = _document_mac(document, passphrase)
        payload = dict(document)
        payload["mac_b64"] = base64.b64encode(mac).decode("ascii")
        return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _derive_keys(passphrase: str, salt: bytes) -> tuple[bytes, bytes]:
    """HMAC-SHA256 HKDF-style extract-and-expand; domain-separated per use."""
    if not passphrase:
        raise VaultError("vault passphrase must not be empty")
    prk = hmac.new(salt, passphrase.encode("utf-8"), hashlib.sha256).digest()
    encryption_key = hmac.new(prk, b"cairn-vault-encrypt\x01", hashlib.sha256).digest()
    mac_key = hmac.new(prk, b"cairn-vault-mac\x01", hashlib.sha256).digest()
    return encryption_key, mac_key


def _keystream(encryption_key: bytes, nonce: bytes, length: int) -> bytes:
    blocks: list[bytes] = []
    counter = 0
    produced = 0
    while produced < length:
        block = hmac.new(
            encryption_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        blocks.append(block)
        produced += len(block)
        counter += 1
    return b"".join(blocks)[:length]


def _xor(bytes_a: bytes, bytes_b: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(bytes_a, bytes_b, strict=True))


def _document_mac(document: dict[str, object], passphrase: str) -> bytes:
    salt = base64.b64decode(document["salt_b64"], validate=True)  # type: ignore[arg-type]
    _, mac_key = _derive_keys(passphrase, salt)
    canonical = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hmac.new(mac_key, canonical, hashlib.sha256).digest()


def create_vault(
    *,
    device: VaultDevice,
    entries: dict[str, bytes],
    passphrase: str,
    now: datetime | None = None,
) -> Vault:
    """Encrypt and bind partition images into a new vault."""
    if now is None:
        now = datetime.now(UTC)
    if now.tzinfo is None:
        raise VaultError("vault creation time must be timezone-aware")
    salt = os.urandom(_SALT_BYTES)
    encryption_key, _ = _derive_keys(passphrase, salt)
    built: list[VaultEntry] = []
    for partition in sorted(entries):
        plaintext = entries[partition]
        nonce = os.urandom(_NONCE_BYTES)
        built.append(
            VaultEntry(
                partition=partition,
                plaintext_sha256=hashlib.sha256(plaintext).hexdigest(),
                size=len(plaintext),
                nonce=nonce,
                ciphertext=_xor(plaintext, _keystream(encryption_key, nonce, len(plaintext))),
            )
        )
    return Vault(created_at=now, device=device, salt=salt, entries=tuple(built))


def save_vault(path: Path, vault: Vault, *, passphrase: str) -> None:
    text = vault.to_json(passphrase=passphrase)
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_VAULT_BYTES:
        raise VaultError(f"vault is {len(encoded)} bytes, above the {MAX_VAULT_BYTES}-byte limit")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise VaultError(f"cannot write vault {path}: {exc}") from exc


def load_vault(path: Path, *, passphrase: str) -> Vault:
    try:
        size = path.stat().st_size
        if size > MAX_VAULT_BYTES:
            raise VaultError(f"vault is {size} bytes, above the {MAX_VAULT_BYTES}-byte limit")
        document: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise VaultError(f"cannot read vault {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise VaultError(f"vault {path} is not valid JSON: {exc}") from exc
    return _parse_vault(document, passphrase=passphrase)


def _parse_vault(document: object, *, passphrase: str) -> Vault:
    if not isinstance(document, dict):
        raise VaultError("vault must be a JSON object")
    if document.get("kind") != VAULT_KIND or document.get("schema_version") != VAULT_SCHEMA_VERSION:
        raise VaultError("vault kind or schema_version is not supported")
    if document.get("mac_b64") is None:
        raise VaultError("vault is missing its MAC")
    if document.get("salt_b64") is None:
        raise VaultError("vault is missing its salt")

    expected_mac = _document_mac(
        {key: value for key, value in document.items() if key != "mac_b64"},
        passphrase,
    )
    try:
        stored_mac = base64.b64decode(document["mac_b64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise VaultTamperedError(f"vault MAC is malformed: {exc}") from exc
    if not hmac.compare_digest(expected_mac, stored_mac):
        raise VaultTamperedError(
            "vault MAC does not verify; the file was edited, corrupted, or the passphrase is wrong"
        )

    try:
        salt = base64.b64decode(document["salt_b64"], validate=True)
        created_at = datetime.fromisoformat(_string(document["created_at"], "vault created_at"))
    except (ValueError, TypeError) as exc:
        raise VaultError(f"vault header is malformed: {exc}") from exc
    if created_at.tzinfo is None:
        raise VaultError("vault created_at must include a timezone")
    if not isinstance(salt, bytes) or len(salt) != _SALT_BYTES:
        raise VaultTamperedError("vault salt has the wrong length")

    device = VaultDevice.from_dict(document["device"])
    entries_raw = document.get("entries")
    if not isinstance(entries_raw, list) or not entries_raw:
        raise VaultError("vault entries must be a non-empty list")

    encryption_key, _ = _derive_keys(passphrase, salt)
    entries: list[VaultEntry] = []
    for index, item in enumerate(entries_raw):
        if not isinstance(item, dict) or set(item) != _ENTRY_KEYS:
            raise VaultError(f"vault entry {index} has unknown or missing keys")
        try:
            nonce = base64.b64decode(_string(item["nonce_b64"], "nonce"), validate=True)
            ciphertext = base64.b64decode(
                _string(item["ciphertext_b64"], "ciphertext"), validate=True
            )
        except (ValueError, TypeError) as exc:
            raise VaultTamperedError(f"vault entry payload is malformed: {exc}") from exc
        size_raw = item["size"]
        if isinstance(size_raw, bool) or not isinstance(size_raw, int):
            raise VaultError("vault entry size must be an integer")
        partition = _string(item["partition"], "partition")
        entry = VaultEntry(
            partition=partition,
            plaintext_sha256=_string(item["sha256"], "sha256"),
            size=size_raw,
            nonce=nonce,
            ciphertext=ciphertext,
        )
        # Defense in depth beyond the MAC: the plaintext must hash to the
        # recorded value after decryption.
        plaintext = _xor(ciphertext, _keystream(encryption_key, nonce, len(ciphertext)))
        if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), entry.plaintext_sha256):
            raise VaultTamperedError(
                f"decrypted partition {partition!r} does not match its recorded hash"
            )
        entries.append(entry)
    return Vault(created_at=created_at, device=device, salt=salt, entries=tuple(entries))


def decrypt_entry(vault: Vault, partition: str, *, passphrase: str) -> bytes:
    """Decrypt one entry and verify it against its recorded plaintext hash."""
    entry = vault.entry(partition)
    if entry is None:
        raise VaultError(f"vault has no entry for partition {partition!r}")
    encryption_key, _ = _derive_keys(passphrase, vault.salt)
    plaintext = _xor(
        entry.ciphertext,
        _keystream(encryption_key, entry.nonce, len(entry.ciphertext)),
    )
    if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), entry.plaintext_sha256):
        raise VaultTamperedError(
            f"decrypted partition {partition!r} does not match its recorded hash"
        )
    return plaintext


def restore_check(vault: Vault, target: VaultDevice) -> bool:
    """Restore-only-same-device rule (SR-009).

    Returns True only when the target identity matches the vault binding. Any
    mismatch raises and is a hard refusal, never overridable.
    """
    if vault.device.matches(target):
        return True
    raise VaultDeviceMismatch(
        "vault is bound to a different device identity; cross-device restore is "
        "refused and is never overridable"
    )


def _string(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise VaultError(f"{what} must be a string")
    return value
