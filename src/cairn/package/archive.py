"""Read-only Android package inspection.

A package is an untrusted archive. Cairn never extracts it to disk and never trusts
entry names. Malformed, ambiguous, encrypted, or path-traversing archives fail
closed; unrecognized files are reported by name instead of ignored.
"""

from __future__ import annotations

import hashlib
import re
import stat
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from cairn.core.errors import ConfigurationError
from cairn.package.fastboot_info import (
    EraseCommand,
    FastbootCommand,
    FastbootInfo,
    FastbootInfoError,
    FlashCommand,
    RebootCommand,
    UpdateSuperCommand,
    parse_fastboot_info,
)

GIB: Final = 1024 * 1024 * 1024
DEFAULT_MAX_ENTRIES: Final = 10_000
DEFAULT_MAX_TOTAL_UNCOMPRESSED: Final = 16 * GIB
DEFAULT_MAX_TEXT_BYTES: Final = 1024 * 1024
HASH_CHUNK_BYTES: Final = 1024 * 1024

FASTBOOT_INFO_NAME: Final = "fastboot-info.txt"
OTA_METADATA_NAME: Final = "META-INF/com/android/metadata"
PAYLOAD_PROPERTIES_NAME: Final = "payload_properties.txt"
PAYLOAD_NAME: Final = "payload.bin"

_DRIVE_RE: Final = re.compile(r"^[A-Za-z]:")
_SUPPORTED_COMPRESSION: Final[frozenset[int]] = frozenset(
    {
        zipfile.ZIP_STORED,
        zipfile.ZIP_DEFLATED,
        zipfile.ZIP_BZIP2,
        zipfile.ZIP_LZMA,
    }
)
_SIGNATURE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "META-INF/CERT.RSA",
        "META-INF/CERT.SF",
        "META-INF/com/android/otacert",
    }
)
_METADATA_NAMES: Final[frozenset[str]] = frozenset(
    {
        "care_map.pb",
        "apex_info.pb",
        "META-INF/MANIFEST.MF",
    }
)


class PackageError(ConfigurationError):
    code = "PACKAGE_ERROR"


class PackageKind(StrEnum):
    FACTORY = "factory"
    OTA = "ota"
    UNKNOWN = "unknown"


class EntryKind(StrEnum):
    IMAGE = "image"
    NESTED_ARCHIVE = "nested-archive"
    FASTBOOT_INFO = "fastboot-info"
    FLASH_SCRIPT = "flash-script"
    OTA_METADATA = "ota-metadata"
    PAYLOAD = "payload"
    PAYLOAD_PROPERTIES = "payload-properties"
    SIGNATURE = "signature"
    METADATA = "metadata"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class PackageEntry:
    name: str
    size: int
    compressed_size: int
    kind: EntryKind
    sha256: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "size": self.size,
            "compressed_size": self.compressed_size,
            "kind": self.kind.value,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class OtaMetadata:
    """Key/value pairs from OTA metadata, preserving duplicate keys."""

    entries: tuple[tuple[str, str], ...]

    def values(self, key: str) -> tuple[str, ...]:
        return tuple(value for name, value in self.entries if name == key)

    def first(self, key: str) -> str | None:
        values = self.values(key)
        return values[0] if values else None

    def to_dict(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for key, value in self.entries:
            result.setdefault(key, []).append(value)
        return result


@dataclass(frozen=True, slots=True)
class PackageManifest:
    path: Path
    kind: PackageKind
    archive_size: int
    archive_sha256: str | None
    entries: tuple[PackageEntry, ...]
    fastboot_info: FastbootInfo | None
    fastboot_info_name: str | None
    ota_metadata: OtaMetadata | None
    payload_properties: Mapping[str, str] | None
    unknown_entries: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "kind": self.kind.value,
            "archive_size": self.archive_size,
            "archive_sha256": self.archive_sha256,
            "entries": [entry.to_dict() for entry in self.entries],
            "fastboot_info": _fastboot_info_summary(self.fastboot_info),
            "issues": {
                "unknown_entries": list(self.unknown_entries),
                "warnings": list(self.warnings),
            },
            "ota_metadata": (None if self.ota_metadata is None else self.ota_metadata.to_dict()),
            "payload_properties": (
                None if self.payload_properties is None else dict(self.payload_properties)
            ),
        }


def load_package(
    path: Path,
    *,
    hash_files: bool = False,
    hash_archive: bool = False,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    max_total_uncompressed: int = DEFAULT_MAX_TOTAL_UNCOMPRESSED,
    max_text_bytes: int = DEFAULT_MAX_TEXT_BYTES,
) -> PackageManifest:
    """Inspect a factory or OTA zip without extracting it."""
    if not path.is_file():
        raise PackageError(f"package not found at {path}")
    if max_entries <= 0 or max_total_uncompressed <= 0 or max_text_bytes <= 0:
        raise ValueError("package limits must be positive")

    try:
        archive_size = path.stat().st_size
    except OSError as exc:
        raise PackageError(f"cannot stat package {path}: {exc}") from exc

    try:
        with zipfile.ZipFile(path) as archive:
            entries, warnings = _inspect_entries(
                archive,
                hash_files=hash_files,
                max_entries=max_entries,
                max_total_uncompressed=max_total_uncompressed,
            )
            by_name = {entry.name: entry for entry in entries}

            fastboot_info: FastbootInfo | None = None
            fastboot_info_name: str | None = None
            info_entry = by_name.get(FASTBOOT_INFO_NAME)
            if info_entry is not None:
                text = _read_text(archive, FASTBOOT_INFO_NAME, max_text_bytes)
                try:
                    fastboot_info = parse_fastboot_info(text)
                except FastbootInfoError as exc:
                    raise PackageError(f"{FASTBOOT_INFO_NAME} is malformed: {exc}") from exc
                fastboot_info_name = FASTBOOT_INFO_NAME

            for entry in entries:
                if entry.name.endswith("/" + FASTBOOT_INFO_NAME):
                    warnings.append(f"{entry.name} is not at the archive root and was not parsed")

            ota_metadata: OtaMetadata | None = None
            if OTA_METADATA_NAME in by_name:
                text = _read_text(archive, OTA_METADATA_NAME, max_text_bytes)
                ota_metadata = _parse_ota_metadata(text)

            payload_properties: Mapping[str, str] | None = None
            if PAYLOAD_PROPERTIES_NAME in by_name:
                text = _read_text(archive, PAYLOAD_PROPERTIES_NAME, max_text_bytes)
                payload_properties = _parse_key_value_file(text, PAYLOAD_PROPERTIES_NAME)

            nested = [entry.name for entry in entries if entry.kind is EntryKind.NESTED_ARCHIVE]
            if nested:
                warnings.append("nested archive contents were not inspected: " + ", ".join(nested))
            if entries and not hash_files:
                warnings.append(
                    "entry CRCs are not fully verified; use --hash to read and verify every entry"
                )

            kind = _classify_package(entries, ota_metadata, warnings)
            unknown = tuple(entry.name for entry in entries if entry.kind is EntryKind.UNKNOWN)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError) as exc:
        raise PackageError(f"cannot read package {path}: {exc}") from exc
    except RuntimeError as exc:
        raise PackageError(f"cannot read package {path}: {exc}") from exc

    archive_hash: str | None = None
    if hash_archive:
        try:
            archive_hash = sha256_file(path)
        except OSError as exc:
            raise PackageError(f"cannot hash package {path}: {exc}") from exc

    return PackageManifest(
        path=path,
        kind=kind,
        archive_size=archive_size,
        archive_sha256=archive_hash,
        entries=entries,
        fastboot_info=fastboot_info,
        fastboot_info_name=fastboot_info_name,
        ota_metadata=ota_metadata,
        payload_properties=payload_properties,
        unknown_entries=unknown,
        warnings=tuple(warnings),
    )


def _inspect_entries(
    archive: zipfile.ZipFile,
    *,
    hash_files: bool,
    max_entries: int,
    max_total_uncompressed: int,
) -> tuple[tuple[PackageEntry, ...], list[str]]:
    infos = archive.infolist()
    if len(infos) > max_entries:
        raise PackageError(f"archive has {len(infos)} entries, above the limit of {max_entries}")

    warnings: list[str] = []
    seen: set[str] = set()
    entries: list[PackageEntry] = []
    total_uncompressed = 0

    for info in infos:
        _validate_entry(info)
        if info.filename in seen:
            raise PackageError(f"duplicate archive entry {info.filename!r}")
        seen.add(info.filename)

        total_uncompressed += info.file_size
        if total_uncompressed > max_total_uncompressed:
            raise PackageError("archive expands beyond the configured uncompressed-size limit")

        if info.is_dir():
            continue

        digest: str | None = None
        if hash_files:
            digest = _hash_entry(archive, info)
        entries.append(
            PackageEntry(
                name=info.filename,
                size=info.file_size,
                compressed_size=info.compress_size,
                kind=classify_entry(info.filename),
                sha256=digest,
            )
        )

    return tuple(entries), warnings


def _validate_entry(info: zipfile.ZipInfo) -> None:
    name = info.filename
    if not name:
        raise PackageError("archive contains an empty entry name")
    if "\x00" in name:
        raise PackageError(f"archive entry {name!r} contains a NUL byte")
    if "\\" in name:
        raise PackageError(f"archive entry {name!r} uses a backslash path")
    if name.startswith("/"):
        raise PackageError(f"archive entry {name!r} is an absolute path")
    if _DRIVE_RE.match(name):
        raise PackageError(f"archive entry {name!r} contains a drive letter")

    trimmed = name[:-1] if name.endswith("/") else name
    parts = trimmed.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise PackageError(f"archive entry {name!r} has an unsafe path segment")

    if info.flag_bits & 0x1:
        raise PackageError(f"archive entry {name!r} is encrypted")
    if info.compress_type not in _SUPPORTED_COMPRESSION:
        raise PackageError(
            f"archive entry {name!r} uses unsupported compression {info.compress_type}"
        )

    mode = (info.external_attr >> 16) & 0o170000
    if mode == stat.S_IFLNK:
        raise PackageError(f"archive entry {name!r} is a symlink")


def classify_entry(name: str) -> EntryKind:
    if name == FASTBOOT_INFO_NAME:
        return EntryKind.FASTBOOT_INFO
    if name in ("flash-all.sh", "flash-all.bat"):
        return EntryKind.FLASH_SCRIPT
    if name == OTA_METADATA_NAME:
        return EntryKind.OTA_METADATA
    if name == PAYLOAD_NAME:
        return EntryKind.PAYLOAD
    if name == PAYLOAD_PROPERTIES_NAME:
        return EntryKind.PAYLOAD_PROPERTIES
    if name in _SIGNATURE_NAMES:
        return EntryKind.SIGNATURE
    if name in _METADATA_NAMES or (name.startswith("META-INF/") and name.count("/") <= 1):
        return EntryKind.METADATA
    if name.lower().endswith(".img"):
        return EntryKind.IMAGE
    if name.lower().endswith(".zip"):
        return EntryKind.NESTED_ARCHIVE
    return EntryKind.UNKNOWN


def _classify_package(
    entries: tuple[PackageEntry, ...],
    ota_metadata: OtaMetadata | None,
    warnings: list[str],
) -> PackageKind:
    names = {entry.name for entry in entries}
    ota_markers = (
        ota_metadata is not None or PAYLOAD_NAME in names or PAYLOAD_PROPERTIES_NAME in names
    )
    factory_markers = any(
        entry.kind
        in (
            EntryKind.FASTBOOT_INFO,
            EntryKind.FLASH_SCRIPT,
            EntryKind.NESTED_ARCHIVE,
            EntryKind.IMAGE,
        )
        for entry in entries
    )
    if ota_markers and factory_markers:
        warnings.append("package contains both OTA and factory markers; kind is UNKNOWN")
        return PackageKind.UNKNOWN
    if ota_markers:
        return PackageKind.OTA
    if factory_markers:
        return PackageKind.FACTORY
    warnings.append("package contains no recognized factory or OTA markers")
    return PackageKind.UNKNOWN


def _hash_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    try:
        with archive.open(info) as handle:
            while chunk := handle.read(HASH_CHUNK_BYTES):
                digest.update(chunk)
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise PackageError(f"cannot hash entry {info.filename!r}: {exc}") from exc
    return digest.hexdigest()


def _read_text(archive: zipfile.ZipFile, name: str, limit: int) -> str:
    info = archive.getinfo(name)
    if info.file_size > limit:
        raise PackageError(f"{name} is {info.file_size} bytes, above the {limit}-byte text limit")
    try:
        with archive.open(info) as handle:
            data = handle.read(limit + 1)
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise PackageError(f"cannot read {name}: {exc}") from exc
    if len(data) > limit:
        raise PackageError(f"{name} exceeds the {limit}-byte text limit")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackageError(f"{name} is not valid UTF-8") from exc


def _parse_ota_metadata(text: str) -> OtaMetadata:
    entries: list[tuple[str, str]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not key:
            raise PackageError(f"{OTA_METADATA_NAME} line {line_number} is not key=value")
        entries.append((key, value.strip()))
    return OtaMetadata(entries=tuple(entries))


def _parse_key_value_file(text: str, name: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not key:
            raise PackageError(f"{name} line {line_number} is not key=value")
        if key in result:
            raise PackageError(f"{name} line {line_number} repeats key {key!r}")
        result[key] = value.strip()
    return result


def _fastboot_info_summary(info: FastbootInfo | None) -> dict[str, Any] | None:
    if info is None:
        return None
    return {
        "version": info.version,
        "command_count": len(info.commands),
        "commands": [_command_dict(command) for command in info.commands],
    }


def _command_dict(command: FastbootCommand) -> dict[str, Any]:
    if isinstance(command, FlashCommand):
        return {
            "type": "flash",
            "partition": command.partition,
            "image": command.image_name,
            "apply_vbmeta": command.apply_vbmeta,
            "slot_other": command.slot_other,
            "if_wipe": command.if_wipe,
            "line": command.line,
        }
    if isinstance(command, RebootCommand):
        return {
            "type": "reboot",
            "target": command.target_name,
            "if_wipe": command.if_wipe,
            "line": command.line,
        }
    if isinstance(command, UpdateSuperCommand):
        return {"type": "update-super", "if_wipe": command.if_wipe, "line": command.line}
    if isinstance(command, EraseCommand):
        return {
            "type": "erase",
            "partition": command.partition,
            "if_wipe": command.if_wipe,
            "line": command.line,
        }
    raise TypeError(f"unknown fastboot command type: {type(command)!r}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()
