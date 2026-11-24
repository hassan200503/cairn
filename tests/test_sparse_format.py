from __future__ import annotations

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cairn.sparse.format import (
    CHUNK_HEADER_SIZE,
    CHUNK_TYPE_CRC32,
    CHUNK_TYPE_DONT_CARE,
    CHUNK_TYPE_FILL,
    CHUNK_TYPE_RAW,
    FILE_HEADER_SIZE,
    SPARSE_MAGIC,
    SparseError,
    parse_chunk_header,
    parse_file_header,
)

FILE_HEADER = struct.Struct("<IHHHHIIII")
CHUNK_HEADER = struct.Struct("<HHII")


def build_file_header(
    *,
    magic: int = SPARSE_MAGIC,
    major: int = 1,
    minor: int = 0,
    file_header_size: int = FILE_HEADER_SIZE,
    chunk_header_size: int = CHUNK_HEADER_SIZE,
    block_size: int = 4096,
    total_blocks: int = 1024,
    total_chunks: int = 8,
    checksum: int = 0xDEADBEEF,
) -> bytes:
    return FILE_HEADER.pack(
        magic,
        major,
        minor,
        file_header_size,
        chunk_header_size,
        block_size,
        total_blocks,
        total_chunks,
        checksum,
    )


def test_sparse_constants_match_aosp() -> None:
    assert SPARSE_MAGIC == 0xED26FF3A
    assert CHUNK_TYPE_RAW == 0xCAC1
    assert CHUNK_TYPE_FILL == 0xCAC2
    assert CHUNK_TYPE_DONT_CARE == 0xCAC3
    assert CHUNK_TYPE_CRC32 == 0xCAC4
    assert FILE_HEADER_SIZE == 28
    assert CHUNK_HEADER_SIZE == 12


def test_parse_file_header() -> None:
    header = parse_file_header(build_file_header())

    assert header.major_version == 1
    assert header.minor_version == 0
    assert header.file_header_size == FILE_HEADER_SIZE
    assert header.chunk_header_size == CHUNK_HEADER_SIZE
    assert header.block_size == 4096
    assert header.total_blocks == 1024
    assert header.total_chunks == 8
    assert header.image_checksum == 0xDEADBEEF


def test_parse_file_header_ignores_trailing_bytes() -> None:
    header = parse_file_header(build_file_header() + b"\x00" * 16)
    assert header.total_blocks == 1024


def test_short_file_header_is_rejected() -> None:
    with pytest.raises(SparseError, match="needs 28 bytes"):
        parse_file_header(b"\x00" * 27)


def test_bad_magic_is_rejected() -> None:
    with pytest.raises(SparseError, match="bad sparse magic"):
        parse_file_header(build_file_header(magic=0xCAC2))


def test_future_major_version_is_rejected() -> None:
    with pytest.raises(SparseError, match="major version"):
        parse_file_header(build_file_header(major=2))


def test_zero_block_size_is_rejected() -> None:
    with pytest.raises(SparseError, match="block_size"):
        parse_file_header(build_file_header(block_size=0))


def test_unaligned_block_size_is_rejected() -> None:
    with pytest.raises(SparseError, match="multiple of 4"):
        parse_file_header(build_file_header(block_size=4095))


def test_short_chunk_header_is_rejected() -> None:
    with pytest.raises(SparseError, match="needs 12 bytes"):
        parse_chunk_header(b"\x00" * 11)


def test_parse_raw_chunk() -> None:
    chunk = parse_chunk_header(CHUNK_HEADER.pack(CHUNK_TYPE_RAW, 0, 16, 12 + 16 * 4096))
    assert chunk.type_name == "RAW"
    assert chunk.chunk_size == 16
    assert chunk.total_size == 12 + 16 * 4096


def test_unknown_chunk_type_is_rejected() -> None:
    with pytest.raises(SparseError, match="unknown sparse chunk type"):
        parse_chunk_header(CHUNK_HEADER.pack(0xCAC5, 0, 1, 12))


def test_chunk_total_size_must_include_header() -> None:
    with pytest.raises(SparseError, match="total_size"):
        parse_chunk_header(CHUNK_HEADER.pack(CHUNK_TYPE_RAW, 0, 1, 11))


@given(
    minor=st.integers(min_value=0, max_value=0xFFFF),
    total_blocks=st.integers(min_value=0, max_value=0xFFFFFFFF),
    total_chunks=st.integers(min_value=0, max_value=0xFFFFFFFF),
    checksum=st.integers(min_value=0, max_value=0xFFFFFFFF),
    block_size=st.integers(min_value=1, max_value=1024).map(lambda n: n * 4),
)
def test_file_header_roundtrip(
    minor: int,
    total_blocks: int,
    total_chunks: int,
    checksum: int,
    block_size: int,
) -> None:
    data = build_file_header(
        minor=minor,
        total_blocks=total_blocks,
        total_chunks=total_chunks,
        checksum=checksum,
        block_size=block_size,
    )
    header = parse_file_header(data)

    assert header.minor_version == minor
    assert header.total_blocks == total_blocks
    assert header.total_chunks == total_chunks
    assert header.image_checksum == checksum
    assert header.block_size == block_size
