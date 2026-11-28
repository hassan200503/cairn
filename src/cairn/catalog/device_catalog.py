"""Device catalog: locally-managed, strictly-validated anchoring records.

The catalog binds a device identity (product plus a sha256 device fingerprint)
to its expected trusted AVB public key and an expected lock state, and a
package archive hash to a known-good label. Every entry must cite a source —
a hardware finding ID or a vendor document — because a safety input without a
source is UNKNOWN by rule (AGENTS.md rule 2); the loader refuses an
uncited entry instead of loading it as fact.

Trust boundary: the catalog is caller-supplied input, not device evidence
(ADR-013). It anchors *which key* is expected; it can never turn a
caller-supplied lock state into a device observation. Raw serials are never
accepted — only their sha256 — and there is no field that could carry one.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cairn.core.errors import CairnError

CATALOG_KIND: Final = "cairn.catalog"
CATALOG_SCHEMA_VERSION: Final = 2
MAX_CATALOG_BYTES: Final = 4 * 1024 * 1024
MAX_TRUSTED_KEY_BYTES: Final = 8192
MAX_SOURCE_CHARS: Final = 512
# AOSP AVB rollback index locations and values are unsigned; 2**63 is far above
# any real counter and keeps arithmetic inside signed-integer comfort.
MAX_ROLLBACK_VALUE: Final = 2**63 - 1
MAX_ROLLBACK_LOCATIONS: Final = 64

_HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_NAME_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

_DEVICE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "product",
        "fingerprint_sha256",
        "serial_sha256",
        "trusted_key_sha256",
        "trusted_key_b64",
        "expected_lock_state",
        "rollback_bounds",
        "source",
        "notes",
    }
)
_PACKAGE_KEYS: Final[frozenset[str]] = frozenset({"archive_sha256", "label", "source", "notes"})
_LOCK_STATES: Final[frozenset[str]] = frozenset({"locked", "unlocked", "unknown"})


class CatalogError(CairnError):
    code = "CATALOG_ERROR"


@dataclass(frozen=True, slots=True)
class RollbackBound:
    """A caller-cited bound on one AVB rollback-index location's stored value.

    Both ends are optional, but at least one must be present: a bound that
    bounds nothing is not a fact. The rollback oracle consults a bound only
    when the device's stored value is unavailable; a stored read outranks it.
    """

    minimum: int | None = None
    maximum: int | None = None

    def to_dict(self) -> dict[str, int | None]:
        return {"minimum": self.minimum, "maximum": self.maximum}


@dataclass(frozen=True, slots=True)
class DeviceEntry:
    """One device's anchoring record; every field is caller-supplied."""

    product: str
    fingerprint_sha256: str
    serial_sha256: str | None
    trusted_key_sha256: str
    trusted_key: bytes | None
    expected_lock_state: str | None
    rollback_bounds: Mapping[int, RollbackBound]
    source: str
    notes: str | None

    def matches_fingerprint(self, fingerprint_sha256: str) -> bool:
        return self.fingerprint_sha256 == fingerprint_sha256.lower()

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "product": self.product,
            "fingerprint_sha256": self.fingerprint_sha256,
            "serial_sha256": self.serial_sha256,
            "trusted_key_sha256": self.trusted_key_sha256,
            "trusted_key_b64": (
                None
                if self.trusted_key is None
                else base64.b64encode(self.trusted_key).decode("ascii")
            ),
            "expected_lock_state": self.expected_lock_state,
            "rollback_bounds": {
                str(location): bound.to_dict()
                for location, bound in sorted(self.rollback_bounds.items())
            },
            "source": self.source,
            "notes": self.notes,
        }
        return data


@dataclass(frozen=True, slots=True)
class PackageEntry:
    archive_sha256: str
    label: str
    source: str
    notes: str | None


@dataclass(frozen=True, slots=True)
class DeviceCatalog:
    devices: tuple[DeviceEntry, ...]
    packages: tuple[PackageEntry, ...]

    def device_by_fingerprint(self, fingerprint_sha256: str) -> DeviceEntry | None:
        for entry in self.devices:
            if entry.matches_fingerprint(fingerprint_sha256):
                return entry
        return None

    def device_by_product(self, product: str) -> DeviceEntry | None:
        for entry in self.devices:
            if entry.product == product:
                return entry
        return None

    def package_by_archive(self, archive_sha256: str) -> PackageEntry | None:
        for entry in self.packages:
            if entry.archive_sha256 == archive_sha256.lower():
                return entry
        return None


def _string(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise CatalogError(f"catalog {what} must be a string")
    return value


def _hex64(value: object, what: str) -> str:
    text = _string(value, what)
    if not _HEX64_RE.fullmatch(text):
        raise CatalogError(f"catalog {what} must be 64 lowercase hex characters")
    return text


def _source(value: object, what: str) -> str:
    text = _string(value, what).strip()
    if not text:
        raise CatalogError(f"catalog {what} is required: an uncited entry is UNKNOWN, not fact")
    if len(text) > MAX_SOURCE_CHARS:
        raise CatalogError(f"catalog {what} is above the {MAX_SOURCE_CHARS}-character limit")
    return text


def _optional(value: object, limit: int, what: str) -> str | None:
    if value is None:
        return None
    text = _string(value, what)
    if len(text) > limit:
        raise CatalogError(f"catalog {what} is above the {limit}-character limit")
    return text


def _decode_rollback_bounds(raw: object, what: str) -> dict[int, RollbackBound]:
    """Decode per-location rollback bounds; ``None`` means the entry has none.

    JSON object keys are strings, so each must name a non-negative integer
    location. A bound entry must carry at least one end, both ends must be
    non-negative integers within range, and a minimum may not exceed its
    maximum.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise CatalogError(f"catalog {what} must be an object or null")
    if len(raw) > MAX_ROLLBACK_LOCATIONS:
        raise CatalogError(f"catalog {what} has more than {MAX_ROLLBACK_LOCATIONS} locations")
    bounds: dict[int, RollbackBound] = {}
    for key, value in raw.items():
        key_text = _string(key, f"{what} location key")
        if not key_text.isdecimal():
            raise CatalogError(
                f"catalog {what} location {key_text!r} is not a non-negative integer"
            )
        location = int(key_text)
        if not isinstance(value, dict) or set(value) - {"minimum", "maximum"}:
            raise CatalogError(
                f"catalog {what} location {location} must have only 'minimum' and 'maximum'"
            )
        minimum = value.get("minimum")
        maximum = value.get("maximum")
        for name, bound in (("minimum", minimum), ("maximum", maximum)):
            if bound is None:
                continue
            if isinstance(bound, bool) or not isinstance(bound, int):
                raise CatalogError(
                    f"catalog {what} location {location} {name} must be an integer or null"
                )
            if not 0 <= bound <= MAX_ROLLBACK_VALUE:
                raise CatalogError(
                    f"catalog {what} location {location} {name} is outside 0..{MAX_ROLLBACK_VALUE}"
                )
        if minimum is None and maximum is None:
            raise CatalogError(f"catalog {what} location {location} must bound at least one end")
        if minimum is not None and maximum is not None and minimum > maximum:
            raise CatalogError(f"catalog {what} location {location} minimum exceeds its maximum")
        bounds[location] = RollbackBound(minimum=minimum, maximum=maximum)
    return bounds


def _decode_device_entry(raw: object, index: int) -> DeviceEntry:
    if not isinstance(raw, dict) or set(raw) != _DEVICE_KEYS:
        raise CatalogError(
            f"catalog device {index} has unknown or missing keys; expected "
            + ", ".join(sorted(_DEVICE_KEYS))
        )
    product = _string(raw["product"], f"device {index} product")
    if not _NAME_RE.fullmatch(product):
        raise CatalogError(f"catalog device {index} product {product!r} is not a safe name")
    fingerprint = _hex64(raw["fingerprint_sha256"], f"device {index} fingerprint_sha256")
    serial_raw = raw["serial_sha256"]
    serial = None if serial_raw is None else _hex64(serial_raw, f"device {index} serial_sha256")
    key_sha = _hex64(raw["trusted_key_sha256"], f"device {index} trusted_key_sha256")
    key_b64 = raw["trusted_key_b64"]
    trusted_key: bytes | None = None
    if key_b64 is not None:
        if not isinstance(key_b64, str):
            raise CatalogError(f"catalog device {index} trusted_key_b64 must be a string")
        try:
            trusted_key = base64.b64decode(key_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CatalogError(
                f"catalog device {index} trusted_key_b64 is not valid base64"
            ) from exc
        if not trusted_key or len(trusted_key) > MAX_TRUSTED_KEY_BYTES:
            raise CatalogError(
                f"catalog device {index} trusted key is empty or above the "
                f"{MAX_TRUSTED_KEY_BYTES}-byte limit"
            )
        actual = hashlib.sha256(trusted_key).hexdigest()
        if actual != key_sha:
            raise CatalogError(
                f"catalog device {index} trusted key does not hash to trusted_key_sha256"
            )
    lock_raw = raw["expected_lock_state"]
    if lock_raw is not None and (not isinstance(lock_raw, str) or lock_raw not in _LOCK_STATES):
        raise CatalogError(
            f"catalog device {index} expected_lock_state must be one of "
            + ", ".join(sorted(_LOCK_STATES))
        )
    return DeviceEntry(
        product=product,
        fingerprint_sha256=fingerprint,
        serial_sha256=serial,
        trusted_key_sha256=key_sha,
        trusted_key=trusted_key,
        expected_lock_state=lock_raw if isinstance(lock_raw, str) else None,
        rollback_bounds=_decode_rollback_bounds(
            raw["rollback_bounds"], f"device {index} rollback_bounds"
        ),
        source=_source(raw["source"], f"device {index} source"),
        notes=_optional(raw["notes"], 1024, f"device {index} notes"),
    )


def _decode_package_entry(raw: object, index: int) -> PackageEntry:
    if not isinstance(raw, dict) or set(raw) != _PACKAGE_KEYS:
        raise CatalogError(
            f"catalog package {index} has unknown or missing keys; expected "
            + ", ".join(sorted(_PACKAGE_KEYS))
        )
    return PackageEntry(
        archive_sha256=_hex64(raw["archive_sha256"], f"package {index} archive_sha256"),
        label=_optional(raw["label"], 256, f"package {index} label") or "",
        source=_source(raw["source"], f"package {index} source"),
        notes=_optional(raw["notes"], 1024, f"package {index} notes"),
    )


def parse_catalog(document: object) -> DeviceCatalog:
    if not isinstance(document, dict):
        raise CatalogError("catalog must be a JSON object")
    if (
        document.get("kind") != CATALOG_KIND
        or document.get("schema_version") != CATALOG_SCHEMA_VERSION
    ):
        raise CatalogError("catalog kind or schema_version is not supported")
    extra = set(document) - {"kind", "schema_version", "devices", "packages"}
    if extra:
        raise CatalogError(f"catalog has unknown keys: {', '.join(sorted(extra))}")
    devices_raw = document.get("devices", [])
    packages_raw = document.get("packages", [])
    if not isinstance(devices_raw, list) or not isinstance(packages_raw, list):
        raise CatalogError("catalog devices and packages must be lists")
    devices = tuple(_decode_device_entry(item, i) for i, item in enumerate(devices_raw))
    packages = tuple(_decode_package_entry(item, i) for i, item in enumerate(packages_raw))
    seen_fingerprints: set[str] = set()
    for entry in devices:
        if entry.fingerprint_sha256 in seen_fingerprints:
            raise CatalogError(
                f"catalog has two devices with fingerprint {entry.fingerprint_sha256}"
            )
        seen_fingerprints.add(entry.fingerprint_sha256)
    return DeviceCatalog(devices=devices, packages=packages)


def load_catalog(path: Path) -> DeviceCatalog:
    try:
        size = path.stat().st_size
        if size > MAX_CATALOG_BYTES:
            raise CatalogError(f"catalog is {size} bytes, above the {MAX_CATALOG_BYTES}-byte limit")
        document: object = json.loads(path.read_text(encoding="utf-8"))
    except CatalogError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise CatalogError(f"cannot read catalog {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CatalogError(f"catalog {path} is not valid JSON: {exc}") from exc
    return parse_catalog(document)
