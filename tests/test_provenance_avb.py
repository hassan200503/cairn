from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from cairn.provenance.avb import (
    AVB_MAGIC,
    AvbChainPartition,
    AvbError,
    AvbHashDescriptor,
    AvbHashtreeDescriptor,
    AvbKernelCmdline,
    AvbProperty,
    AvbUnknownDescriptor,
    calculate_vbmeta_digest,
    load_vbmeta,
    parse_vbmeta,
)

FIXTURE = Path(__file__).parent / "fixtures" / "avb" / "unsigned_vbmeta.img"
FIXTURE_SHA256 = "df3d0b84fce2abbf0ebdcebbec571cbc2d4b089dca88cf3ab8214c610059b405"
HEADER_FORMAT = ">4s2L2QL2Q2Q2Q2Q2QQLL47sx80x"


def _round8(value: int) -> int:
    return (value + 7) // 8 * 8


def _build_vbmeta(
    descriptors: tuple[bytes, ...] = (),
    *,
    descriptor_block: bytes | None = None,
    descriptors_size: int | None = None,
    algorithm_type: int = 0,
    version_major: int = 1,
    version_minor: int = 0,
    rollback_index: int = 0,
    flags: int = 0,
    rollback_index_location: int = 0,
    release: str = "avbtool 1.3.0",
    magic: bytes = AVB_MAGIC,
    trailing: bytes = b"",
) -> bytes:
    block = b"".join(descriptors) if descriptor_block is None else descriptor_block
    size = len(block) if descriptors_size is None else descriptors_size
    header = struct.pack(
        HEADER_FORMAT,
        magic,
        version_major,
        version_minor,
        0,
        len(block),
        algorithm_type,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        size,
        rollback_index,
        flags,
        rollback_index_location,
        release.encode("utf-8"),
    )
    return header + block + trailing


def _property(key: str = "test.key", value: bytes = b"test-value") -> bytes:
    key_bytes = key.encode("utf-8")
    following = _round8(16 + len(key_bytes) + 1 + len(value) + 1)
    fixed = struct.pack(">QQQQ", 0, following, len(key_bytes), len(value))
    payload = fixed + key_bytes + b"\0" + value + b"\0"
    return payload + b"\0" * (following - (len(payload) - 16))


def _hash_descriptor(
    *,
    name: str = "boot",
    algorithm: str = "sha256",
    salt: bytes = b"salt",
    digest: bytes = b"d" * 32,
    image_size: int = 4096,
    flags: int = 0,
) -> bytes:
    name_bytes = name.encode("utf-8")
    following = _round8(116 + len(name_bytes) + len(salt) + len(digest))
    fixed = struct.pack(
        ">QQQ32sLLLL60s",
        2,
        following,
        image_size,
        algorithm.encode("ascii").ljust(32, b"\0"),
        len(name_bytes),
        len(salt),
        len(digest),
        flags,
        b"\0" * 60,
    )
    payload = fixed + name_bytes + salt + digest
    return payload + b"\0" * (following - (len(payload) - 16))


def _hashtree_descriptor(
    *,
    name: str = "system",
    algorithm: str = "sha256",
    salt: bytes = b"salt",
    root_digest: bytes = b"r" * 32,
    image_size: int = 8192,
    tree_offset: int = 4096,
    tree_size: int = 4096,
    data_block_size: int = 4096,
    hash_block_size: int = 4096,
    flags: int = 0,
) -> bytes:
    name_bytes = name.encode("utf-8")
    following = _round8(164 + len(name_bytes) + len(salt) + len(root_digest))
    fixed = struct.pack(
        ">QQLQQQLLLQQ32sLLLL60s",
        1,
        following,
        1,
        image_size,
        tree_offset,
        tree_size,
        data_block_size,
        hash_block_size,
        0,
        0,
        0,
        algorithm.encode("ascii").ljust(32, b"\0"),
        len(name_bytes),
        len(salt),
        len(root_digest),
        flags,
        b"\0" * 60,
    )
    payload = fixed + name_bytes + salt + root_digest
    return payload + b"\0" * (following - (len(payload) - 16))


def _kernel_cmdline(cmdline: str = "androidboot.test=1", flags: int = 0) -> bytes:
    cmdline_bytes = cmdline.encode("utf-8")
    following = _round8(8 + len(cmdline_bytes))
    fixed = struct.pack(">QQLL", 3, following, flags, len(cmdline_bytes))
    payload = fixed + cmdline_bytes
    return payload + b"\0" * (following - (len(payload) - 16))


def _chain_partition(
    *,
    name: str = "boot",
    public_key: bytes = b"public-key",
    rollback_index_location: int = 2,
    flags: int = 0,
) -> bytes:
    name_bytes = name.encode("utf-8")
    following = _round8(76 + len(name_bytes) + len(public_key))
    fixed = struct.pack(
        ">QQLLLL60s",
        4,
        following,
        rollback_index_location,
        len(name_bytes),
        len(public_key),
        flags,
        b"\0" * 60,
    )
    payload = fixed + name_bytes + public_key
    return payload + b"\0" * (following - (len(payload) - 16))


def test_parse_avbtool_fixture() -> None:
    image = load_vbmeta(FIXTURE)
    assert image.source == FIXTURE
    assert image.trailing_bytes == 0
    assert image.header.algorithm.name == "NONE"
    assert image.header.authentication_data_block_size == 0
    assert image.header.auxiliary_data_block_size == 128
    assert image.header.release_string == "avbtool 1.3.0"
    assert image.header.rollback_index == 0
    assert len(image.descriptors) == 2

    prop = image.properties[0]
    assert prop.key == "test.key"
    assert prop.value == b"test-value"

    cmdline = image.kernel_cmdlines[0]
    assert cmdline.cmdline == "androidboot.test=1"
    assert cmdline.flags == 0
    assert image.hash_descriptors == ()
    assert image.hashtree_descriptors == ()
    assert image.chain_partitions == ()
    assert image.unknown_descriptors == ()


def test_avbtool_fixture_digest_matches_sha256() -> None:
    image = load_vbmeta(FIXTURE)
    assert calculate_vbmeta_digest(image) == FIXTURE_SHA256
    assert calculate_vbmeta_digest(image, hash_name="sha256") == FIXTURE_SHA256


def test_padded_vbmeta_records_trailing_bytes() -> None:
    data = FIXTURE.read_bytes()
    image = parse_vbmeta(data + b"\0" * 32)
    assert image.trailing_bytes == 32
    assert calculate_vbmeta_digest(image) == FIXTURE_SHA256


def test_parse_all_descriptor_kinds() -> None:
    image = parse_vbmeta(
        _build_vbmeta(
            (
                _property(),
                _hash_descriptor(),
                _hashtree_descriptor(),
                _kernel_cmdline(),
                _chain_partition(),
            ),
            rollback_index=7,
            rollback_index_location=3,
        )
    )
    assert image.header.rollback_index == 7
    assert image.header.rollback_index_location == 3

    prop = image.properties[0]
    assert prop.key == "test.key"
    assert prop.value == b"test-value"

    hash_desc = image.hash_descriptors[0]
    assert isinstance(hash_desc, AvbHashDescriptor)
    assert hash_desc.partition_name == "boot"
    assert hash_desc.hash_algorithm == "sha256"
    assert hash_desc.image_size == 4096
    assert hash_desc.digest == b"d" * 32

    tree = image.hashtree_descriptors[0]
    assert isinstance(tree, AvbHashtreeDescriptor)
    assert tree.partition_name == "system"
    assert tree.image_size == 8192
    assert tree.tree_offset == 4096
    assert tree.root_digest == b"r" * 32

    cmdline = image.kernel_cmdlines[0]
    assert isinstance(cmdline, AvbKernelCmdline)
    assert cmdline.cmdline == "androidboot.test=1"

    chain = image.chain_partitions[0]
    assert isinstance(chain, AvbChainPartition)
    assert chain.partition_name == "boot"
    assert chain.rollback_index_location == 2
    assert chain.public_key == b"public-key"


def test_unknown_descriptor_is_preserved() -> None:
    raw = struct.pack(">QQ", 99, 8) + b"12345678"
    image = parse_vbmeta(_build_vbmeta((raw,)))
    assert len(image.unknown_descriptors) == 1
    unknown = image.unknown_descriptors[0]
    assert isinstance(unknown, AvbUnknownDescriptor)
    assert unknown.tag == 99
    assert unknown.payload == raw


def test_chain_digest_includes_supplied_chained_images() -> None:
    chained = parse_vbmeta(_build_vbmeta((_property(),)))
    main = parse_vbmeta(_build_vbmeta((_chain_partition(name="boot"),)))
    expected = hashlib.sha256(main.blob + chained.blob).hexdigest()
    assert calculate_vbmeta_digest(main, chain={"boot": chained}) == expected


def test_chain_digest_requires_the_chained_image() -> None:
    main = parse_vbmeta(_build_vbmeta((_chain_partition(name="boot"),)))
    with pytest.raises(AvbError, match="chained partition"):
        calculate_vbmeta_digest(main)


def test_unsupported_digest_hash_is_rejected() -> None:
    image = parse_vbmeta(_build_vbmeta())
    with pytest.raises(AvbError, match="unsupported digest hash"):
        calculate_vbmeta_digest(image, hash_name="md5")


def test_bad_magic_is_rejected() -> None:
    with pytest.raises(AvbError, match="magic"):
        parse_vbmeta(_build_vbmeta(magic=b"AVB1"))


def test_short_image_is_rejected() -> None:
    with pytest.raises(AvbError, match="below the 256-byte header"):
        parse_vbmeta(b"AVB0")


def test_unsupported_version_is_rejected() -> None:
    with pytest.raises(AvbError, match="major version"):
        parse_vbmeta(_build_vbmeta(version_major=2))


def test_unsupported_algorithm_is_rejected() -> None:
    with pytest.raises(AvbError, match="algorithm type"):
        parse_vbmeta(_build_vbmeta(algorithm_type=99))


def test_algorithm_sizes_must_match() -> None:
    with pytest.raises(AvbError, match="requires a 32-byte hash"):
        parse_vbmeta(_build_vbmeta(algorithm_type=1))


def test_header_flags_must_be_known() -> None:
    with pytest.raises(AvbError, match="unknown flags"):
        parse_vbmeta(_build_vbmeta(flags=4))


def test_descriptor_block_must_fit_the_auxiliary_block() -> None:
    with pytest.raises(AvbError, match="descriptors range"):
        parse_vbmeta(_build_vbmeta(descriptor_block=b"", descriptors_size=8))


def test_descriptor_must_be_aligned() -> None:
    raw = struct.pack(">QQ", 99, 7) + b"1234567"
    with pytest.raises(AvbError, match="8-byte aligned"):
        parse_vbmeta(_build_vbmeta((raw,)))


def test_truncated_descriptor_header_is_rejected() -> None:
    raw = _property() + b"\0" * 4
    with pytest.raises(AvbError, match="truncated descriptor header"):
        parse_vbmeta(_build_vbmeta(descriptor_block=raw))


def test_property_descriptor_size_mismatch_is_rejected() -> None:
    raw = bytearray(_property())
    struct.pack_into(">Q", raw, 8, 16)
    with pytest.raises(AvbError, match="property descriptor size"):
        parse_vbmeta(_build_vbmeta((bytes(raw),)))


def test_property_key_must_not_be_empty() -> None:
    with pytest.raises(AvbError, match="empty key"):
        parse_vbmeta(_build_vbmeta((_property(key=""),)))


def test_hash_descriptor_digest_length_must_match_algorithm() -> None:
    with pytest.raises(AvbError, match="digest is 16 bytes"):
        parse_vbmeta(_build_vbmeta((_hash_descriptor(digest=b"d" * 16),)))


def test_hash_descriptor_rejects_unknown_algorithm() -> None:
    with pytest.raises(AvbError, match="unsupported descriptor hash algorithm"):
        parse_vbmeta(_build_vbmeta((_hash_descriptor(algorithm="md5"),)))


def test_hashtree_block_sizes_must_be_powers_of_two() -> None:
    with pytest.raises(AvbError, match="powers of two"):
        parse_vbmeta(_build_vbmeta((_hashtree_descriptor(data_block_size=3000),)))


def test_hashtree_tree_must_fit_the_image() -> None:
    with pytest.raises(AvbError, match="tree overruns"):
        parse_vbmeta(_build_vbmeta((_hashtree_descriptor(image_size=4096, tree_offset=4096),)))


def test_kernel_cmdline_flags_must_be_known() -> None:
    with pytest.raises(AvbError, match="unknown flags"):
        parse_vbmeta(_build_vbmeta((_kernel_cmdline(flags=4),)))


def test_chain_partition_key_must_not_be_empty() -> None:
    with pytest.raises(AvbError, match="empty public key"):
        parse_vbmeta(_build_vbmeta((_chain_partition(public_key=b""),)))


def test_load_vbmeta_rejects_missing_and_oversized_files(tmp_path: Path) -> None:
    with pytest.raises(AvbError, match="not found"):
        load_vbmeta(tmp_path / "missing.img")
    with pytest.raises(AvbError, match="above the"):
        load_vbmeta(FIXTURE, max_bytes=100)


def test_vbmeta_to_dict_is_json_serializable() -> None:
    image = load_vbmeta(FIXTURE)
    encoded = json.dumps(image.to_dict(), sort_keys=True)
    assert '"algorithm": "NONE"' in encoded
    assert '"key": "test.key"' in encoded
    assert '"cmdline": "androidboot.test=1"' in encoded
    assert '"source"' in encoded
    assert AvbProperty("k", b"v").to_dict()["value_text"] == "v"
