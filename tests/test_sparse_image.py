from __future__ import annotations

import struct

import pytest

from cairn.sparse.format import (
    CHUNK_HEADER_SIZE,
    CHUNK_TYPE_CRC32,
    CHUNK_TYPE_DONT_CARE,
    CHUNK_TYPE_FILL,
    CHUNK_TYPE_RAW,
    FILE_HEADER_SIZE,
    SPARSE_MAGIC,
    SparseError,
    validate_sparse_image,
)

FILE_HEADER = struct.Struct("<IHHHHIIII")
CHUNK_HEADER = struct.Struct("<HHII")
BLOCK = 4096


def file_header(
    *,
    total_blocks: int,
    total_chunks: int,
    block_size: int = BLOCK,
    file_header_size: int = FILE_HEADER_SIZE,
    chunk_header_size: int = CHUNK_HEADER_SIZE,
) -> bytes:
    return FILE_HEADER.pack(
        SPARSE_MAGIC,
        1,
        0,
        file_header_size,
        chunk_header_size,
        block_size,
        total_blocks,
        total_chunks,
        0,
    )


def chunk(chunk_type: int, blocks: int, payload: bytes) -> bytes:
    return CHUNK_HEADER.pack(chunk_type, 0, blocks, CHUNK_HEADER_SIZE + len(payload)) + payload


def valid_image() -> bytes:
    return (
        file_header(total_blocks=4, total_chunks=4)
        + chunk(CHUNK_TYPE_RAW, 1, b"\xaa" * BLOCK)
        + chunk(CHUNK_TYPE_FILL, 1, b"\x11\x22\x33\x44")
        + chunk(CHUNK_TYPE_DONT_CARE, 2, b"")
        + chunk(CHUNK_TYPE_CRC32, 0, b"\x00\x00\x00\x00")
    )


def test_valid_image_is_accepted() -> None:
    image = validate_sparse_image(valid_image())
    assert image.header.block_size == BLOCK
    assert image.header.total_blocks == 4
    assert image.header.total_chunks == 4
    assert len(image.chunks) == 4
    assert [item.type_name for item in image.chunks] == ["RAW", "FILL", "DONT_CARE", "CRC32"]
    assert image.total_data_blocks == 4


def test_empty_image_with_no_chunks_is_accepted() -> None:
    image = validate_sparse_image(file_header(total_blocks=0, total_chunks=0))
    assert image.chunks == ()
    assert image.total_data_blocks == 0


def test_block_count_mismatch_is_rejected() -> None:
    data = file_header(total_blocks=5, total_chunks=4) + valid_image()[FILE_HEADER_SIZE:]
    with pytest.raises(SparseError, match="header declares 5"):
        validate_sparse_image(data)


def test_chunk_total_size_mismatch_is_rejected() -> None:
    bad_chunk = CHUNK_HEADER.pack(CHUNK_TYPE_RAW, 0, 1, CHUNK_HEADER_SIZE + BLOCK - 1)
    data = file_header(total_blocks=1, total_chunks=1) + bad_chunk + b"\xaa" * BLOCK
    with pytest.raises(SparseError, match="does not match expected"):
        validate_sparse_image(data)


def test_fill_payload_size_is_enforced() -> None:
    data = file_header(total_blocks=1, total_chunks=1) + chunk(CHUNK_TYPE_FILL, 1, b"\x00" * 8)
    with pytest.raises(SparseError, match="does not match expected"):
        validate_sparse_image(data)


def test_trailing_bytes_are_rejected() -> None:
    with pytest.raises(SparseError, match="trailing bytes"):
        validate_sparse_image(valid_image() + b"\x00")


def test_truncated_chunk_header_is_rejected() -> None:
    data = file_header(total_blocks=4, total_chunks=5) + valid_image()[FILE_HEADER_SIZE:]
    with pytest.raises(SparseError, match="truncated"):
        validate_sparse_image(data)


def test_truncated_payload_is_rejected() -> None:
    bad_chunk = CHUNK_HEADER.pack(CHUNK_TYPE_RAW, 0, 1, CHUNK_HEADER_SIZE + BLOCK)
    data = file_header(total_blocks=1, total_chunks=1) + bad_chunk + b"\xaa" * (BLOCK - 6)
    with pytest.raises(SparseError, match="beyond file length"):
        validate_sparse_image(data)


def test_crc32_chunk_must_have_zero_blocks() -> None:
    data = file_header(total_blocks=1, total_chunks=1) + chunk(
        CHUNK_TYPE_CRC32, 1, b"\x00\x00\x00\x00"
    )
    with pytest.raises(SparseError, match="non-zero chunk_size"):
        validate_sparse_image(data)


def test_file_header_size_beyond_file_is_rejected() -> None:
    header = file_header(
        total_blocks=0,
        total_chunks=0,
        file_header_size=FILE_HEADER_SIZE + 4,
    )
    with pytest.raises(SparseError, match="file header claims"):
        validate_sparse_image(header)


def test_extended_headers_are_accepted() -> None:
    file_header_size = FILE_HEADER_SIZE + 4
    chunk_header_size = CHUNK_HEADER_SIZE + 4
    payload = b"\xbb" * BLOCK
    extended_chunk = (
        CHUNK_HEADER.pack(
            CHUNK_TYPE_RAW,
            0,
            1,
            chunk_header_size + len(payload),
        )
        + b"\x00" * 4
        + payload
    )
    data = (
        file_header(
            total_blocks=1,
            total_chunks=1,
            file_header_size=file_header_size,
            chunk_header_size=chunk_header_size,
        )
        + b"\x00" * 4
        + extended_chunk
    )
    image = validate_sparse_image(data)
    assert image.header.file_header_size == file_header_size
    assert image.header.chunk_header_size == chunk_header_size
    assert len(image.chunks) == 1
