"""Offline vendor package hash index (provenance skeleton).

A match means the package bytes match an entry in this local file. It does not
authenticate the package or the index; signature and AVB verification are separate
gates.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

from cairn.core.errors import ConfigurationError
from cairn.core.tristate import Tri
from cairn.package.archive import PackageError, PackageManifest, validate_entry_name

SCHEMA_VERSION: Final = 1
MAX_INDEX_BYTES: Final = 8 * 1024 * 1024
_HEX_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset({"schema_version", "packages"})
_REQUIRED_PACKAGE_KEYS: Final[frozenset[str]] = frozenset({"id", "archive_sha256", "entries"})
_OPTIONAL_PACKAGE_KEYS: Final[frozenset[str]] = frozenset({"device", "build"})


class HashIndexError(ConfigurationError):
    code = "HASH_INDEX_ERROR"


@dataclass(frozen=True, slots=True)
class KnownPackage:
    package_id: str
    archive_sha256: str
    entries: tuple[tuple[str, str], ...]
    device: str | None = None
    build: str | None = None

    def entry_hashes(self) -> dict[str, str]:
        return dict(self.entries)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.package_id,
            "device": self.device,
            "build": self.build,
            "archive_sha256": self.archive_sha256,
            "entries": dict(self.entries),
        }


@dataclass(frozen=True, slots=True)
class HashIndex:
    source: Path
    packages: Mapping[str, KnownPackage]


@dataclass(frozen=True, slots=True)
class ProvenanceResult:
    state: Tri
    package_id: str | None = None
    device: str | None = None
    build: str | None = None
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.name,
            "package_id": self.package_id,
            "device": self.device,
            "build": self.build,
            "reasons": list(self.reasons),
        }


def load_hash_index(path: Path, *, max_bytes: int = MAX_INDEX_BYTES) -> HashIndex:
    """Load and strictly validate a local hash index."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if not path.is_file():
        raise HashIndexError(f"hash index not found at {path}")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise HashIndexError(f"cannot stat hash index {path}: {exc}") from exc
    if size > max_bytes:
        raise HashIndexError(f"hash index is {size} bytes, above the {max_bytes}-byte limit")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise HashIndexError(f"cannot read hash index {path}: {exc}") from exc

    try:
        document = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise HashIndexError(f"hash index is not valid JSON: {exc}") from exc

    top = _as_mapping(document, "index")
    _check_keys(top, _TOP_LEVEL_KEYS, frozenset(), "index")
    schema_version = top["schema_version"]
    if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
        raise HashIndexError(
            f"hash index schema_version must be {SCHEMA_VERSION}, got {schema_version!r}"
        )

    raw_packages = top["packages"]
    if not isinstance(raw_packages, list):
        raise HashIndexError("hash index packages must be a list")

    packages: dict[str, KnownPackage] = {}
    package_ids: set[str] = set()
    for position, raw_package in enumerate(raw_packages):
        where = f"packages[{position}]"
        package = _parse_package(raw_package, where)
        if package.archive_sha256 in packages:
            raise HashIndexError(f"{where} repeats archive_sha256 {package.archive_sha256}")
        if package.package_id in package_ids:
            raise HashIndexError(f"{where} repeats package id {package.package_id!r}")
        packages[package.archive_sha256] = package
        package_ids.add(package.package_id)

    return HashIndex(source=path, packages=MappingProxyType(packages))


def verify_manifest(index: HashIndex, manifest: PackageManifest) -> ProvenanceResult:
    """Compare a hashed package manifest against the local index."""
    if manifest.archive_sha256 is None:
        return ProvenanceResult(
            Tri.UNKNOWN,
            reasons=("archive sha256 was not computed",),
        )
    archive_hash = manifest.archive_sha256.lower()
    known = index.packages.get(archive_hash)
    if known is None:
        return ProvenanceResult(
            Tri.UNKNOWN,
            reasons=(f"archive sha256 {archive_hash} is not in the local index",),
        )

    index_entries = known.entry_hashes()
    manifest_entries = {entry.name: entry.sha256 for entry in manifest.entries}
    missing = sorted(set(index_entries) - set(manifest_entries))
    extra = sorted(set(manifest_entries) - set(index_entries))
    if missing or extra:
        reasons: list[str] = []
        if missing:
            reasons.append("missing entries: " + ", ".join(missing))
        if extra:
            reasons.append("unexpected entries: " + ", ".join(extra))
        return _result(Tri.FALSE, known, tuple(reasons))

    mismatched: list[str] = []
    unhashed: list[str] = []
    for name, expected in sorted(index_entries.items()):
        actual = manifest_entries[name]
        if actual is None:
            unhashed.append(name)
        elif actual.lower() != expected:
            mismatched.append(name)
    if mismatched:
        return _result(
            Tri.FALSE,
            known,
            ("entry hash mismatch: " + ", ".join(mismatched),),
        )
    if unhashed:
        return _result(
            Tri.UNKNOWN,
            known,
            ("entry hash not computed: " + ", ".join(unhashed),),
        )
    return _result(
        Tri.TRUE,
        known,
        (f"archive and {len(index_entries)} entry hashes match the local index",),
    )


def _result(
    state: Tri,
    known: KnownPackage,
    reasons: tuple[str, ...],
) -> ProvenanceResult:
    return ProvenanceResult(
        state=state,
        package_id=known.package_id,
        device=known.device,
        build=known.build,
        reasons=reasons,
    )


def _parse_package(raw: object, where: str) -> KnownPackage:
    package = _as_mapping(raw, where)
    _check_keys(package, _REQUIRED_PACKAGE_KEYS, _OPTIONAL_PACKAGE_KEYS, where)

    package_id = _expect_str(package["id"], f"{where}.id")
    archive_sha256 = _expect_hash(package["archive_sha256"], f"{where}.archive_sha256")
    device = _optional_str(package.get("device"), f"{where}.device")
    build = _optional_str(package.get("build"), f"{where}.build")

    raw_entries = package["entries"]
    if not isinstance(raw_entries, dict):
        raise HashIndexError(f"{where}.entries must be an object")
    if not raw_entries:
        raise HashIndexError(f"{where}.entries must not be empty")

    entries: list[tuple[str, str]] = []
    for name, raw_hash in raw_entries.items():
        if not isinstance(name, str):
            raise HashIndexError(f"{where}.entries keys must be strings")
        if name.endswith("/"):
            raise HashIndexError(f"{where}.entries must list files, not {name!r}")
        try:
            validate_entry_name(name)
        except PackageError as exc:
            raise HashIndexError(f"{where}.entries: {exc}") from exc
        entries.append((name, _expect_hash(raw_hash, f"{where}.entries[{name!r}]")))

    return KnownPackage(
        package_id=package_id,
        archive_sha256=archive_sha256,
        entries=tuple(entries),
        device=device,
        build=build,
    )


def _as_mapping(value: object, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HashIndexError(f"{where} must be an object")
    result: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise HashIndexError(f"{where} keys must be strings")
        result[key] = item
    return result


def _check_keys(
    mapping: Mapping[str, Any],
    required: frozenset[str],
    optional: frozenset[str],
    where: str,
) -> None:
    missing = sorted(required - set(mapping))
    if missing:
        raise HashIndexError(f"{where} is missing keys: {', '.join(missing)}")
    extra = sorted(set(mapping) - required - optional)
    if extra:
        raise HashIndexError(f"{where} has unknown keys: {', '.join(extra)}")


def _expect_str(value: object, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise HashIndexError(f"{where} must be a non-empty string")
    return value


def _optional_str(value: object, where: str) -> str | None:
    if value is None:
        return None
    return _expect_str(value, where)


def _expect_hash(value: object, where: str) -> str:
    text = _expect_str(value, where).lower()
    if _HEX_RE.fullmatch(text) is None:
        raise HashIndexError(f"{where} must be a 64-character hex SHA-256")
    return text


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HashIndexError(f"hash index repeats JSON key {key!r}")
        result[key] = value
    return result
