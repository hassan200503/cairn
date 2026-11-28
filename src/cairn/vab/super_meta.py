"""Super image (dynamic partition) metadata parsing (SR-011 metadata half).

Implements the Android logical-partition metadata format documented in AOSP
``fs_mgr/liblp/include/liblp/metadata_format.h`` (pinned: system/core
``a3b721a32242006b59cb12bd62c9133632af3a2d``). The parser is deliberately
strict: every structural anomaly raises :class:`SuperMetadataError`, which
callers must classify as UNKNOWN (an unreadable layout must never become a
guess that feeds the write path). Outputs are differentially tested against
the official ``lpmake`` built from pinned AOSP source (tools/oracle/, KU-033);
per AGENTS.md rule 9 this testing is a precondition before any safety rule
consumes this module.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Final

from cairn.core.errors import CairnError

# All constants below are from the pinned metadata_format.h ([AOSP-LIBLP]).
GEOMETRY_MAGIC: Final = 0x616C4467
GEOMETRY_SIZE: Final = 4096
HEADER_MAGIC: Final = 0x414C5030
MAJOR_VERSION: Final = 10
MINOR_VERSION_MIN: Final = 0
MINOR_VERSION_MAX: Final = 2
VERSION_FOR_EXPANDED_HEADER: Final = 2
SECTOR_SIZE: Final = 512

# liblp reserves 4096 bytes at the start of a super partition to avoid an
# accidental boot sector; the geometry follows it (utility.cpp:
# GetPrimaryGeometryOffset returns LP_PARTITION_RESERVED_BYTES).
RESERVED_BYTES: Final = 4096

HEADER_V1_0_SIZE: Final = 128
HEADER_V1_2_SIZE: Final = 256

PARTITION_ATTR_READONLY: Final = 0x1
PARTITION_ATTR_SLOT_SUFFIXED: Final = 0x2
PARTITION_ATTR_UPDATED: Final = 0x4
PARTITION_ATTR_DISABLED: Final = 0x8
PARTITION_ATTRIBUTE_MASK: Final = 0xF

GROUP_SLOT_SUFFIXED: Final = 0x1
BLOCK_DEVICE_SLOT_SUFFIXED: Final = 0x1

HEADER_FLAG_VIRTUAL_AB_DEVICE: Final = 0x1
HEADER_FLAG_OVERLAYS_ACTIVE: Final = 0x2

TARGET_TYPE_LINEAR: Final = 0
TARGET_TYPE_ZERO: Final = 1

_PARTITION_STRUCT: Final = struct.Struct("<36sIIII")
_EXTENT_STRUCT: Final = struct.Struct("<QIQI")
_GROUP_STRUCT: Final = struct.Struct("<36sIQ")
_BLOCK_DEVICE_STRUCT: Final = struct.Struct("<QIIQ36sI")
_GEOMETRY_STRUCT: Final = struct.Struct("<II32sIII")
_TABLE_DESCRIPTOR_STRUCT: Final = struct.Struct("<III")


class SuperMetadataError(CairnError):
    code = "SUPER_METADATA_ERROR"


@dataclass(frozen=True, slots=True)
class Geometry:
    metadata_max_size: int
    metadata_slot_count: int
    logical_block_size: int


@dataclass(frozen=True, slots=True)
class Extent:
    num_sectors: int
    target_type: int
    target_data: int
    target_source: int


@dataclass(frozen=True, slots=True)
class Partition:
    name: str
    attributes: int
    group_index: int
    extents: tuple[Extent, ...]

    @property
    def size_bytes(self) -> int:
        return sum(e.num_sectors for e in self.extents) * SECTOR_SIZE


@dataclass(frozen=True, slots=True)
class Group:
    name: str
    flags: int
    maximum_size: int


@dataclass(frozen=True, slots=True)
class BlockDevice:
    first_logical_sector: int
    alignment: int
    alignment_offset: int
    size: int
    partition_name: str
    flags: int


@dataclass(frozen=True, slots=True)
class SlotMetadata:
    header_flags: int
    major_version: int
    minor_version: int
    partitions: tuple[Partition, ...]
    groups: tuple[Group, ...]
    block_devices: tuple[BlockDevice, ...]
    extents: tuple[Extent, ...]


@dataclass(frozen=True, slots=True)
class SuperImage:
    geometry: Geometry
    slots: tuple[SlotMetadata, ...]
    """The parsed metadata of each metadata slot, in slot order."""
    primary_backup_match: bool
    """True when every slot's primary and backup metadata copy are byte-equal."""

    @property
    def virtual_ab(self) -> bool:
        return any(slot.header_flags & HEADER_FLAG_VIRTUAL_AB_DEVICE for slot in self.slots)


def _cstr(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("ascii")


def _parse_geometry(blob: bytes, origin: str) -> Geometry:
    if len(blob) < _GEOMETRY_STRUCT.size:
        raise SuperMetadataError(f"{origin}: geometry truncated ({len(blob)} bytes)")
    magic, struct_size, checksum, metadata_max_size, slot_count, logical_block_size = (
        _GEOMETRY_STRUCT.unpack_from(blob, 0)
    )
    if magic != GEOMETRY_MAGIC:
        raise SuperMetadataError(f"{origin}: bad geometry magic {magic:#x}")
    if struct_size > _GEOMETRY_STRUCT.size:
        raise SuperMetadataError(f"{origin}: geometry struct_size {struct_size} too large")
    stored = checksum
    computed = hashlib.sha256(
        bytes(blob[0:8]) + b"\x00" * 32 + bytes(blob[40 : _GEOMETRY_STRUCT.size])
    ).digest()
    if stored != computed:
        raise SuperMetadataError(f"{origin}: geometry checksum mismatch")
    if struct_size != _GEOMETRY_STRUCT.size:
        raise SuperMetadataError(
            f"{origin}: geometry struct_size {struct_size} != {_GEOMETRY_STRUCT.size}",
        )
    if slot_count == 0:
        raise SuperMetadataError(f"{origin}: metadata_slot_count is 0")
    if metadata_max_size % SECTOR_SIZE != 0:
        raise SuperMetadataError(
            f"{origin}: metadata_max_size {metadata_max_size} not sector-aligned",
        )
    if logical_block_size < SECTOR_SIZE or logical_block_size % SECTOR_SIZE != 0:
        raise SuperMetadataError(
            f"{origin}: logical_block_size {logical_block_size} invalid",
        )
    return Geometry(metadata_max_size, slot_count, logical_block_size)


def _validate_table(
    descriptor: tuple[int, int, int], tables_size: int, expected_entry_size: int, name: str
) -> tuple[int, int, int]:
    offset, num_entries, entry_size = descriptor
    table_size = num_entries * entry_size
    if offset > tables_size or tables_size - offset < table_size:
        raise SuperMetadataError(
            f"{name} table out of bounds (offset={offset}, entries={num_entries}, "
            f"entry_size={entry_size}, tables_size={tables_size})",
        )
    if entry_size != expected_entry_size:
        raise SuperMetadataError(
            f"{name} table entry_size {entry_size} != {expected_entry_size}",
        )
    return (offset, num_entries, entry_size)


def _parse_slot(blob: bytes, origin: str) -> SlotMetadata:
    if len(blob) < HEADER_V1_0_SIZE:
        raise SuperMetadataError(f"{origin}: metadata truncated ({len(blob)} bytes)")
    magic, major, minor, header_size = struct.unpack_from("<IHHI", blob, 0)
    header_checksum = blob[12:44]
    tables_size = struct.unpack_from("<I", blob, 44)[0]
    if magic != HEADER_MAGIC:
        raise SuperMetadataError(f"{origin}: bad header magic {magic:#x}")
    if major != MAJOR_VERSION or not MINOR_VERSION_MIN <= minor <= MINOR_VERSION_MAX:
        raise SuperMetadataError(f"{origin}: unsupported metadata version {major}.{minor}")
    expected_header_size = (
        HEADER_V1_2_SIZE if minor >= VERSION_FOR_EXPANDED_HEADER else HEADER_V1_0_SIZE
    )
    if header_size != expected_header_size:
        raise SuperMetadataError(
            f"{origin}: header_size {header_size} != {expected_header_size}",
        )
    computed = hashlib.sha256(
        bytes(blob[0:12]) + b"\x00" * 32 + bytes(blob[44:header_size])
    ).digest()
    if header_checksum != computed:
        raise SuperMetadataError(f"{origin}: header checksum mismatch")

    tables = blob[header_size : header_size + tables_size]
    if len(tables) != tables_size:
        raise SuperMetadataError(f"{origin}: tables truncated")
    tables_checksum = hashlib.sha256(tables).digest()
    if tables_checksum != blob[48:80]:
        raise SuperMetadataError(f"{origin}: tables checksum mismatch")

    partitions_d = _TABLE_DESCRIPTOR_STRUCT.unpack_from(blob, 80)
    extents_d = _TABLE_DESCRIPTOR_STRUCT.unpack_from(blob, 92)
    groups_d = _TABLE_DESCRIPTOR_STRUCT.unpack_from(blob, 104)
    block_devices_d = _TABLE_DESCRIPTOR_STRUCT.unpack_from(blob, 116)

    _validate_table(partitions_d, tables_size, _PARTITION_STRUCT.size, "partitions")
    _validate_table(extents_d, tables_size, _EXTENT_STRUCT.size, "extents")
    _validate_table(groups_d, tables_size, _GROUP_STRUCT.size, "groups")
    _validate_table(block_devices_d, tables_size, _BLOCK_DEVICE_STRUCT.size, "block_devices")

    def table(descriptor: tuple[int, int, int], s: struct.Struct) -> list[bytes]:
        offset, num_entries, entry_size = descriptor
        base = header_size + offset
        return [
            blob[base + i * entry_size : base + (i + 1) * entry_size] for i in range(num_entries)
        ]

    extent_entries = [Extent(*_EXTENT_STRUCT.unpack(e)) for e in table(extents_d, _EXTENT_STRUCT)]
    group_entries = []
    for raw in table(groups_d, _GROUP_STRUCT):
        name_raw, flags, maximum_size = _GROUP_STRUCT.unpack(raw)
        group_entries.append(Group(_cstr(name_raw), flags, maximum_size))
    device_entries = []
    for raw in table(block_devices_d, _BLOCK_DEVICE_STRUCT):
        first_logical_sector, alignment, alignment_offset, size, part_name, flags = (
            _BLOCK_DEVICE_STRUCT.unpack(raw)
        )
        device_entries.append(
            BlockDevice(
                first_logical_sector, alignment, alignment_offset, size, _cstr(part_name), flags
            )
        )
    if not device_entries:
        raise SuperMetadataError(f"{origin}: no block devices")

    partition_entries = []
    seen_names: set[str] = set()
    for raw in table(partitions_d, _PARTITION_STRUCT):
        name_raw, attributes, first_extent_index, num_extents, group_index = (
            _PARTITION_STRUCT.unpack(raw)
        )
        name = _cstr(name_raw)
        if not name or len(name) > 36 or not all(c.isalnum() or c == "_" for c in name):
            raise SuperMetadataError(f"{origin}: invalid partition name {name!r}")
        if name in seen_names:
            raise SuperMetadataError(f"{origin}: duplicate partition name {name!r}")
        seen_names.add(name)
        if attributes & ~PARTITION_ATTRIBUTE_MASK:
            raise SuperMetadataError(
                f"{origin}: partition {name!r} has unknown attributes {attributes:#x}",
            )
        if num_extents < 1:
            raise SuperMetadataError(f"{origin}: partition {name!r} has no extents")
        if first_extent_index + num_extents > len(extent_entries):
            raise SuperMetadataError(f"{origin}: partition {name!r} extents out of range")
        if group_index >= len(group_entries):
            raise SuperMetadataError(
                f"{origin}: partition {name!r} group index {group_index} out of range",
            )
        extents = extent_entries[first_extent_index : first_extent_index + num_extents]
        for extent in extents:
            if extent.target_type == TARGET_TYPE_LINEAR:
                if extent.target_source >= len(device_entries):
                    raise SuperMetadataError(
                        f"{origin}: partition {name!r} extent targets unknown block device",
                    )
            elif extent.target_type != TARGET_TYPE_ZERO:
                raise SuperMetadataError(
                    f"{origin}: partition {name!r} unknown target type {extent.target_type}",
                )
        partition_entries.append(Partition(name, attributes, group_index, tuple(extents)))

    flags = 0
    if minor >= VERSION_FOR_EXPANDED_HEADER:
        (flags,) = struct.unpack_from("<I", blob, 128)
    return SlotMetadata(
        header_flags=flags,
        major_version=major,
        minor_version=minor,
        partitions=tuple(partition_entries),
        groups=tuple(group_entries),
        block_devices=tuple(device_entries),
        extents=tuple(extent_entries),
    )


def _magic_at(data: bytes, offset: int) -> int | None:
    if len(data) < offset + 4:
        return None
    return int(struct.unpack_from("<I", data, offset)[0])


def parse_super_image(data: bytes) -> SuperImage:
    """Parse a raw (non-sparse) super image or super_empty.img.

    Full super layout ([AOSP-LIBLP] utility.cpp): 4096 reserved bytes;
    geometry at ``4096`` and backup at ``8192``; metadata copies start at
    ``12288``; slot i primary at ``12288 + i*metadata_max_size``, backup at
    ``12288 + slot_count*metadata_max_size + i*metadata_max_size``.

    Empty-super layout (``WriteToImageFile`` without images, as produced by
    ``lpmake --device-size auto``; images.cpp): geometry at ``0`` padded to
    ``4096``, exactly one metadata blob at ``4096``, no backup copies.
    """
    full = _magic_at(data, RESERVED_BYTES) == GEOMETRY_MAGIC
    empty = _magic_at(data, 0) == GEOMETRY_MAGIC
    if not full and not empty:
        raise SuperMetadataError(
            "no LP geometry magic at the reserved offset (4096) or at offset 0; "
            "is this a raw super image or a sparse image that needs simg2img?"
        )
    if full:
        return _parse_full_super(data)
    return _parse_empty_super(data)


def _parse_full_super(data: bytes) -> SuperImage:
    geometry = _parse_geometry(
        data[RESERVED_BYTES : RESERVED_BYTES + GEOMETRY_SIZE], "primary geometry"
    )
    try:
        backup = _parse_geometry(
            data[RESERVED_BYTES + GEOMETRY_SIZE : RESERVED_BYTES + 2 * GEOMETRY_SIZE],
            "backup geometry",
        )
    except SuperMetadataError:
        backup = None
    if backup is not None and backup != geometry:
        raise SuperMetadataError("primary and backup geometry disagree")

    base = RESERVED_BYTES + 2 * GEOMETRY_SIZE
    slots: list[SlotMetadata] = []
    primary_backup_match = True
    for i in range(geometry.metadata_slot_count):
        primary = data[base + i * geometry.metadata_max_size :]
        primary = primary[: geometry.metadata_max_size]
        backup_off = base + geometry.metadata_slot_count * geometry.metadata_max_size
        backup_copy = data[backup_off + i * geometry.metadata_max_size :]
        backup_copy = backup_copy[: geometry.metadata_max_size]
        slot = _parse_slot(primary, f"slot {i} primary")
        _parse_slot(backup_copy, f"slot {i} backup")
        if primary != backup_copy:
            primary_backup_match = False
        slots.append(slot)
    return SuperImage(
        geometry=geometry, slots=tuple(slots), primary_backup_match=primary_backup_match
    )


def _parse_empty_super(data: bytes) -> SuperImage:
    geometry = _parse_geometry(data[0:GEOMETRY_SIZE], "empty-super geometry")
    slot = _parse_slot(data[GEOMETRY_SIZE : GEOMETRY_SIZE + geometry.metadata_max_size], "slot 0")
    return SuperImage(geometry=geometry, slots=(slot,), primary_backup_match=True)
