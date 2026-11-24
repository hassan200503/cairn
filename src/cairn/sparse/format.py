"""Android sparse image format primitives.

The constants here are taken from AOSP ``system/core/libsparse/sparse_format.h``.
Parsers must be differentially tested against AOSP libsparse (``simg2img`` and
``img2simg``) before they are trusted on a device.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cairn.core.errors import ProtocolError

SPARSE_MAGIC = 0xED26FF3A
CHUNK_TYPE_RAW = 0xCAC1
CHUNK_TYPE_FILL = 0xCAC2
CHUNK_TYPE_DONT_CARE = 0xCAC3
CHUNK_TYPE_CRC32 = 0xCAC4

FILE_HEADER_SIZE = 28
CHUNK_HEADER_SIZE = 12
SUPPORTED_MAJOR_VERSION = 1

CHUNK_TYPE_NAMES = {
    CHUNK_TYPE_RAW: "RAW",
    CHUNK_TYPE_FILL: "FILL",
    CHUNK_TYPE_DONT_CARE: "DONT_CARE",
    CHUNK_TYPE_CRC32: "CRC32",
}

_FILE_HEADER = struct.Struct("<IHHHHIIII")
_CHUNK_HEADER = struct.Struct("<HHII")


class SparseError(ProtocolError):
    code = "SPARSE_FORMAT_ERROR"


@dataclass(frozen=True, slots=True)
class SparseFileHeader:
    """Header of a sparse file, excluding any extension bytes."""

    major_version: int
    minor_version: int
    file_header_size: int
    chunk_header_size: int
    block_size: int
    total_blocks: int
    total_chunks: int
    image_checksum: int


@dataclass(frozen=True, slots=True)
class SparseChunkHeader:
    """Header of one sparse chunk."""

    chunk_type: int
    chunk_size: int
    total_size: int

    @property
    def type_name(self) -> str:
        return CHUNK_TYPE_NAMES[self.chunk_type]

    @property
    def data_blocks(self) -> int:
        """Blocks this chunk contributes to the expanded image."""
        if self.chunk_type == CHUNK_TYPE_CRC32:
            return 0
        return self.chunk_size


@dataclass(frozen=True, slots=True)
class SparseImage:
    """A fully validated sparse image: header plus every chunk."""

    header: SparseFileHeader
    chunks: tuple[SparseChunkHeader, ...]

    @property
    def total_data_blocks(self) -> int:
        return sum(chunk.data_blocks for chunk in self.chunks)


def parse_file_header(data: bytes) -> SparseFileHeader:
    """Parse and validate the 28-byte sparse file header."""
    if len(data) < FILE_HEADER_SIZE:
        raise SparseError(f"sparse file header needs {FILE_HEADER_SIZE} bytes, got {len(data)}")

    (
        magic,
        major_version,
        minor_version,
        file_header_size,
        chunk_header_size,
        block_size,
        total_blocks,
        total_chunks,
        image_checksum,
    ) = _FILE_HEADER.unpack_from(data)

    if magic != SPARSE_MAGIC:
        raise SparseError(f"bad sparse magic {magic:#010x}, expected {SPARSE_MAGIC:#010x}")
    if major_version != SUPPORTED_MAJOR_VERSION:
        raise SparseError(
            f"unsupported sparse major version {major_version}, expected {SUPPORTED_MAJOR_VERSION}"
        )
    if file_header_size < FILE_HEADER_SIZE:
        raise SparseError(f"file_header_size {file_header_size} is smaller than {FILE_HEADER_SIZE}")
    if chunk_header_size < CHUNK_HEADER_SIZE:
        raise SparseError(
            f"chunk_header_size {chunk_header_size} is smaller than {CHUNK_HEADER_SIZE}"
        )
    if block_size == 0 or block_size % 4 != 0:
        raise SparseError(f"block_size {block_size} must be a positive multiple of 4")

    return SparseFileHeader(
        major_version=major_version,
        minor_version=minor_version,
        file_header_size=file_header_size,
        chunk_header_size=chunk_header_size,
        block_size=block_size,
        total_blocks=total_blocks,
        total_chunks=total_chunks,
        image_checksum=image_checksum,
    )


def parse_chunk_header(data: bytes, offset: int = 0) -> SparseChunkHeader:
    """Parse and validate a 12-byte sparse chunk header at ``offset``."""
    if offset < 0:
        raise SparseError(f"chunk offset must not be negative, got {offset}")
    if len(data) < offset + CHUNK_HEADER_SIZE:
        raise SparseError(
            f"chunk header at {offset} needs {CHUNK_HEADER_SIZE} bytes, got {len(data) - offset}"
        )

    chunk_type, _reserved, chunk_size, total_size = _CHUNK_HEADER.unpack_from(data, offset)

    if chunk_type not in CHUNK_TYPE_NAMES:
        raise SparseError(f"unknown sparse chunk type {chunk_type:#06x}")
    if total_size < CHUNK_HEADER_SIZE:
        raise SparseError(f"chunk total_size {total_size} is smaller than {CHUNK_HEADER_SIZE}")

    return SparseChunkHeader(
        chunk_type=chunk_type,
        chunk_size=chunk_size,
        total_size=total_size,
    )


def validate_sparse_image(data: bytes) -> SparseImage:
    """Walk and validate every chunk, block count, and length.

    Fails closed on anything AOSP's writer does not produce: truncated chunks,
    inconsistent ``total_size``, non-zero CRC chunk size, a block-count mismatch,
    or trailing bytes after the last chunk.
    """
    header = parse_file_header(data)
    if len(data) < header.file_header_size:
        raise SparseError(
            f"file header claims {header.file_header_size} bytes, file has {len(data)}"
        )

    chunks: list[SparseChunkHeader] = []
    offset = header.file_header_size
    data_blocks = 0

    for index in range(header.total_chunks):
        if offset + header.chunk_header_size > len(data):
            raise SparseError(
                f"chunk {index} at offset {offset} is truncated: "
                f"needs {header.chunk_header_size} header bytes, "
                f"only {len(data) - offset} remain"
            )

        chunk = parse_chunk_header(data, offset)
        if chunk.total_size < header.chunk_header_size:
            raise SparseError(
                f"chunk {index} total_size {chunk.total_size} is smaller than "
                f"chunk_header_size {header.chunk_header_size}"
            )

        if chunk.chunk_type == CHUNK_TYPE_RAW:
            payload = chunk.chunk_size * header.block_size
        elif chunk.chunk_type == CHUNK_TYPE_FILL:
            payload = 4
        elif chunk.chunk_type == CHUNK_TYPE_DONT_CARE:
            payload = 0
        else:
            if chunk.chunk_size != 0:
                raise SparseError(
                    f"chunk {index} is CRC32 with non-zero chunk_size {chunk.chunk_size}"
                )
            payload = 4

        expected_total = header.chunk_header_size + payload
        if chunk.total_size != expected_total:
            raise SparseError(
                f"chunk {index} total_size {chunk.total_size} does not match "
                f"expected {expected_total} for {chunk.type_name}"
            )

        end = offset + chunk.total_size
        if end > len(data):
            raise SparseError(f"chunk {index} ends at {end}, beyond file length {len(data)}")

        data_blocks += chunk.data_blocks
        chunks.append(chunk)
        offset = end

    if data_blocks != header.total_blocks:
        raise SparseError(
            f"chunks expand to {data_blocks} blocks, header declares {header.total_blocks}"
        )
    if offset != len(data):
        raise SparseError(f"{len(data) - offset} trailing bytes after the last sparse chunk")

    return SparseImage(header=header, chunks=tuple(chunks))
