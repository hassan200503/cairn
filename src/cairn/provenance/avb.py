"""Strict, read-only AVB VBMeta parsing.

This module parses the VBMeta container and its descriptors. It does not verify
RSA signatures or follow partition chains yet; those are separate gates. Parsing
is intentionally fail-closed: unknown algorithms, inconsistent sizes, overlapping
blocks, and malformed descriptors are rejected.
"""

from __future__ import annotations

import hashlib
import itertools
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cairn.core.errors import ConfigurationError

AVB_MAGIC: Final = b"AVB0"
HEADER_SIZE: Final = 256
DESCRIPTOR_HEADER_SIZE: Final = 16
MAX_VBMETA_BYTES: Final = 64 * 1024 * 1024
MAX_DESCRIPTORS: Final = 4096
_HASH_SIZES: Final[Mapping[str, int]] = {"sha256": 32, "sha512": 64}
_HEADER_STRUCT: Final = struct.Struct(">4s2L2QL2Q2Q2Q2Q2QQLL47sx80x")
_DESCRIPTOR_HEADER_STRUCT: Final = struct.Struct(">QQ")
_PROPERTY_STRUCT: Final = struct.Struct(">QQQQ")
_HASHTREE_STRUCT: Final = struct.Struct(">QQLQQQLLLQQ32sLLLL60s")
_HASH_STRUCT: Final = struct.Struct(">QQQ32sLLLL60s")
_KERNEL_CMDLINE_STRUCT: Final = struct.Struct(">QQLL")
_CHAIN_STRUCT: Final = struct.Struct(">QQLLLL60s")

assert _HEADER_STRUCT.size == HEADER_SIZE
assert _PROPERTY_STRUCT.size == 32
assert _HASHTREE_STRUCT.size == 180
assert _HASH_STRUCT.size == 132
assert _KERNEL_CMDLINE_STRUCT.size == 24
assert _CHAIN_STRUCT.size == 92


class AvbError(ConfigurationError):
    code = "AVB_ERROR"


@dataclass(frozen=True, slots=True)
class AvbAlgorithm:
    name: str
    algorithm_type: int
    hash_name: str
    hash_size: int
    signature_size: int
    public_key_size: int


ALGORITHMS_BY_TYPE: Final[Mapping[int, AvbAlgorithm]] = {
    0: AvbAlgorithm("NONE", 0, "", 0, 0, 0),
    1: AvbAlgorithm("SHA256_RSA2048", 1, "sha256", 32, 256, 8 + 2 * 2048 // 8),
    2: AvbAlgorithm("SHA256_RSA4096", 2, "sha256", 32, 512, 8 + 2 * 4096 // 8),
    3: AvbAlgorithm("SHA256_RSA8192", 3, "sha256", 32, 1024, 8 + 2 * 8192 // 8),
    4: AvbAlgorithm("SHA512_RSA2048", 4, "sha512", 64, 256, 8 + 2 * 2048 // 8),
    5: AvbAlgorithm("SHA512_RSA4096", 5, "sha512", 64, 512, 8 + 2 * 4096 // 8),
    6: AvbAlgorithm("SHA512_RSA8192", 6, "sha512", 64, 1024, 8 + 2 * 8192 // 8),
}


@dataclass(frozen=True, slots=True)
class AvbHeader:
    algorithm: AvbAlgorithm
    required_libavb_version_major: int
    required_libavb_version_minor: int
    authentication_data_block_size: int
    auxiliary_data_block_size: int
    hash_offset: int
    hash_size: int
    signature_offset: int
    signature_size: int
    public_key_offset: int
    public_key_size: int
    public_key_metadata_offset: int
    public_key_metadata_size: int
    descriptors_offset: int
    descriptors_size: int
    rollback_index: int
    flags: int
    rollback_index_location: int
    release_string: str

    def to_dict(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm.name,
            "algorithm_type": self.algorithm.algorithm_type,
            "required_libavb_version": (
                f"{self.required_libavb_version_major}.{self.required_libavb_version_minor}"
            ),
            "authentication_data_block_size": self.authentication_data_block_size,
            "auxiliary_data_block_size": self.auxiliary_data_block_size,
            "rollback_index": self.rollback_index,
            "flags": self.flags,
            "rollback_index_location": self.rollback_index_location,
            "release_string": self.release_string,
            "hash_offset": self.hash_offset,
            "hash_size": self.hash_size,
            "signature_offset": self.signature_offset,
            "signature_size": self.signature_size,
            "public_key_offset": self.public_key_offset,
            "public_key_size": self.public_key_size,
            "public_key_metadata_offset": self.public_key_metadata_offset,
            "public_key_metadata_size": self.public_key_metadata_size,
            "descriptors_offset": self.descriptors_offset,
            "descriptors_size": self.descriptors_size,
        }


@dataclass(frozen=True, slots=True)
class AvbProperty:
    key: str
    value: bytes

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "property",
            "tag": 0,
            "key": self.key,
            "value_hex": self.value.hex(),
            "value_text": _decode_optional(self.value),
        }


@dataclass(frozen=True, slots=True)
class AvbHashDescriptor:
    image_size: int
    hash_algorithm: str
    partition_name: str
    salt: bytes
    digest: bytes
    flags: int

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "hash",
            "tag": 2,
            "image_size": self.image_size,
            "hash_algorithm": self.hash_algorithm,
            "partition_name": self.partition_name,
            "salt_hex": self.salt.hex(),
            "digest_hex": self.digest.hex(),
            "flags": self.flags,
        }


@dataclass(frozen=True, slots=True)
class AvbHashtreeDescriptor:
    dm_verity_version: int
    image_size: int
    tree_offset: int
    tree_size: int
    data_block_size: int
    hash_block_size: int
    fec_num_roots: int
    fec_offset: int
    fec_size: int
    hash_algorithm: str
    partition_name: str
    salt: bytes
    root_digest: bytes
    flags: int

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "hashtree",
            "tag": 1,
            "dm_verity_version": self.dm_verity_version,
            "image_size": self.image_size,
            "tree_offset": self.tree_offset,
            "tree_size": self.tree_size,
            "data_block_size": self.data_block_size,
            "hash_block_size": self.hash_block_size,
            "fec_num_roots": self.fec_num_roots,
            "fec_offset": self.fec_offset,
            "fec_size": self.fec_size,
            "hash_algorithm": self.hash_algorithm,
            "partition_name": self.partition_name,
            "salt_hex": self.salt.hex(),
            "root_digest_hex": self.root_digest.hex(),
            "flags": self.flags,
        }


@dataclass(frozen=True, slots=True)
class AvbKernelCmdline:
    flags: int
    cmdline: str

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "kernel_cmdline",
            "tag": 3,
            "flags": self.flags,
            "cmdline": self.cmdline,
        }


@dataclass(frozen=True, slots=True)
class AvbChainPartition:
    rollback_index_location: int
    partition_name: str
    public_key: bytes
    flags: int

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "chain_partition",
            "tag": 4,
            "rollback_index_location": self.rollback_index_location,
            "partition_name": self.partition_name,
            "public_key_size": len(self.public_key),
            "public_key_sha256": hashlib.sha256(self.public_key).hexdigest(),
            "flags": self.flags,
        }


@dataclass(frozen=True, slots=True)
class AvbUnknownDescriptor:
    tag: int
    payload: bytes

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "unknown",
            "tag": self.tag,
            "size": len(self.payload),
            "sha256": hashlib.sha256(self.payload).hexdigest(),
        }


type AvbDescriptor = (
    AvbProperty
    | AvbHashtreeDescriptor
    | AvbHashDescriptor
    | AvbKernelCmdline
    | AvbChainPartition
    | AvbUnknownDescriptor
)


@dataclass(frozen=True, slots=True)
class VbmetaImage:
    header: AvbHeader
    descriptors: tuple[AvbDescriptor, ...]
    blob: bytes
    trailing_bytes: int = 0
    source: Path | None = None

    @property
    def chain_partitions(self) -> tuple[AvbChainPartition, ...]:
        return tuple(
            descriptor
            for descriptor in self.descriptors
            if isinstance(descriptor, AvbChainPartition)
        )

    @property
    def hash_descriptors(self) -> tuple[AvbHashDescriptor, ...]:
        return tuple(
            descriptor
            for descriptor in self.descriptors
            if isinstance(descriptor, AvbHashDescriptor)
        )

    @property
    def hashtree_descriptors(self) -> tuple[AvbHashtreeDescriptor, ...]:
        return tuple(
            descriptor
            for descriptor in self.descriptors
            if isinstance(descriptor, AvbHashtreeDescriptor)
        )

    @property
    def properties(self) -> tuple[AvbProperty, ...]:
        return tuple(
            descriptor for descriptor in self.descriptors if isinstance(descriptor, AvbProperty)
        )

    @property
    def kernel_cmdlines(self) -> tuple[AvbKernelCmdline, ...]:
        return tuple(
            descriptor
            for descriptor in self.descriptors
            if isinstance(descriptor, AvbKernelCmdline)
        )

    @property
    def unknown_descriptors(self) -> tuple[AvbUnknownDescriptor, ...]:
        return tuple(
            descriptor
            for descriptor in self.descriptors
            if isinstance(descriptor, AvbUnknownDescriptor)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "source": None if self.source is None else str(self.source),
            "size": len(self.blob),
            "trailing_bytes": self.trailing_bytes,
            "header": self.header.to_dict(),
            "descriptors": [descriptor.to_dict() for descriptor in self.descriptors],
        }


def parse_vbmeta(data: bytes) -> VbmetaImage:
    """Parse a standalone or padded VBMeta image."""
    if len(data) < HEADER_SIZE:
        raise AvbError(f"vbmeta image is {len(data)} bytes, below the 256-byte header")
    values = _HEADER_STRUCT.unpack_from(data, 0)
    magic = values[0]
    if magic != AVB_MAGIC:
        raise AvbError(f"vbmeta magic is {magic!r}, expected {AVB_MAGIC!r}")

    version_major = values[1]
    version_minor = values[2]
    if version_major != 1:
        raise AvbError(f"unsupported AVB major version {version_major}")
    auth_size = values[3]
    aux_size = values[4]
    algorithm_type = values[5]
    algorithm = ALGORITHMS_BY_TYPE.get(algorithm_type)
    if algorithm is None:
        raise AvbError(f"unsupported AVB algorithm type {algorithm_type}")

    header = AvbHeader(
        algorithm=algorithm,
        required_libavb_version_major=version_major,
        required_libavb_version_minor=version_minor,
        authentication_data_block_size=auth_size,
        auxiliary_data_block_size=aux_size,
        hash_offset=values[6],
        hash_size=values[7],
        signature_offset=values[8],
        signature_size=values[9],
        public_key_offset=values[10],
        public_key_size=values[11],
        public_key_metadata_offset=values[12],
        public_key_metadata_size=values[13],
        descriptors_offset=values[14],
        descriptors_size=values[15],
        rollback_index=values[16],
        flags=values[17],
        rollback_index_location=values[18],
        release_string=_decode_release(values[19]),
    )
    _validate_header(header)

    total_size = HEADER_SIZE + auth_size + aux_size
    if total_size > len(data):
        raise AvbError(f"vbmeta declares {total_size} bytes but only {len(data)} are present")
    blob = data[:total_size]
    aux_start = HEADER_SIZE + auth_size
    descriptor_start = aux_start + header.descriptors_offset
    descriptor_end = descriptor_start + header.descriptors_size
    descriptor_bytes = data[descriptor_start:descriptor_end]
    descriptors = _parse_descriptors(descriptor_bytes)
    return VbmetaImage(
        header=header,
        descriptors=descriptors,
        blob=blob,
        trailing_bytes=len(data) - total_size,
    )


def load_vbmeta(path: Path, *, max_bytes: int = MAX_VBMETA_BYTES) -> VbmetaImage:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if not path.is_file():
        raise AvbError(f"vbmeta image not found at {path}")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AvbError(f"cannot stat vbmeta image {path}: {exc}") from exc
    if size > max_bytes:
        raise AvbError(f"vbmeta image is {size} bytes, above the {max_bytes}-byte limit")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise AvbError(f"cannot read vbmeta image {path}: {exc}") from exc
    image = parse_vbmeta(data)
    return VbmetaImage(
        header=image.header,
        descriptors=image.descriptors,
        blob=image.blob,
        trailing_bytes=image.trailing_bytes,
        source=path,
    )


def calculate_vbmeta_digest(
    image: VbmetaImage,
    *,
    hash_name: str = "sha256",
    chain: Mapping[str, VbmetaImage] | None = None,
) -> str:
    """Compute the AOSP VBMeta digest, including supplied chained images."""
    if hash_name not in _HASH_SIZES:
        raise AvbError(f"unsupported digest hash {hash_name!r}; use sha256 or sha512")
    hasher = hashlib.new(hash_name)
    hasher.update(image.blob)
    for descriptor in image.chain_partitions:
        if chain is None or descriptor.partition_name not in chain:
            raise AvbError(f"chained partition {descriptor.partition_name!r} was not supplied")
        hasher.update(chain[descriptor.partition_name].blob)
    return hasher.hexdigest()


def _validate_header(header: AvbHeader) -> None:
    algorithm = header.algorithm
    if algorithm.hash_size != header.hash_size:
        raise AvbError(
            f"{algorithm.name} requires a {algorithm.hash_size}-byte hash, got {header.hash_size}"
        )
    if algorithm.signature_size != header.signature_size:
        raise AvbError(
            f"{algorithm.name} requires a {algorithm.signature_size}-byte signature, "
            f"got {header.signature_size}"
        )
    if algorithm.public_key_size != header.public_key_size:
        raise AvbError(
            f"{algorithm.name} requires a {algorithm.public_key_size}-byte public key, "
            f"got {header.public_key_size}"
        )
    if header.flags & ~0x3:
        raise AvbError(f"vbmeta header has unknown flags 0x{header.flags:x}")

    _check_range(
        header.hash_offset,
        header.hash_size,
        header.authentication_data_block_size,
        "hash",
    )
    _check_range(
        header.signature_offset,
        header.signature_size,
        header.authentication_data_block_size,
        "signature",
    )
    _check_range(
        header.public_key_offset,
        header.public_key_size,
        header.auxiliary_data_block_size,
        "public key",
    )
    _check_range(
        header.public_key_metadata_offset,
        header.public_key_metadata_size,
        header.auxiliary_data_block_size,
        "public key metadata",
    )
    _check_range(
        header.descriptors_offset,
        header.descriptors_size,
        header.auxiliary_data_block_size,
        "descriptors",
    )
    _check_non_overlapping(
        (
            (header.hash_offset, header.hash_size, "hash"),
            (header.signature_offset, header.signature_size, "signature"),
        ),
        "authentication",
    )
    _check_non_overlapping(
        (
            (header.public_key_offset, header.public_key_size, "public key"),
            (
                header.public_key_metadata_offset,
                header.public_key_metadata_size,
                "public key metadata",
            ),
            (header.descriptors_offset, header.descriptors_size, "descriptors"),
        ),
        "auxiliary",
    )


def _parse_descriptors(data: bytes) -> tuple[AvbDescriptor, ...]:
    descriptors: list[AvbDescriptor] = []
    offset = 0
    while offset < len(data):
        if len(descriptors) >= MAX_DESCRIPTORS:
            raise AvbError(f"vbmeta has more than {MAX_DESCRIPTORS} descriptors")
        if len(data) - offset < DESCRIPTOR_HEADER_SIZE:
            raise AvbError(f"truncated descriptor header at offset {offset}")
        tag, following = _DESCRIPTOR_HEADER_STRUCT.unpack_from(data, offset)
        if following % 8 != 0:
            raise AvbError(f"descriptor at offset {offset} is not 8-byte aligned")
        end = offset + DESCRIPTOR_HEADER_SIZE + following
        if end > len(data):
            raise AvbError(f"descriptor at offset {offset} overruns the descriptor block")
        payload = data[offset:end]
        descriptors.append(_parse_descriptor(tag, payload))
        offset = end
    if offset != len(data):
        raise AvbError("descriptor block has trailing bytes")
    return tuple(descriptors)


def _parse_descriptor(tag: int, payload: bytes) -> AvbDescriptor:
    if tag == 0:
        return _parse_property(payload)
    if tag == 1:
        return _parse_hashtree(payload)
    if tag == 2:
        return _parse_hash(payload)
    if tag == 3:
        return _parse_kernel_cmdline(payload)
    if tag == 4:
        return _parse_chain_partition(payload)
    return AvbUnknownDescriptor(tag=tag, payload=payload)


def _parse_property(payload: bytes) -> AvbProperty:
    if len(payload) < _PROPERTY_STRUCT.size:
        raise AvbError("property descriptor is too short")
    _, following, key_size, value_size = _PROPERTY_STRUCT.unpack_from(payload, 0)
    expected = _round8(
        _PROPERTY_STRUCT.size - DESCRIPTOR_HEADER_SIZE + key_size + 1 + value_size + 1
    )
    if following != expected:
        raise AvbError("property descriptor size does not match its key and value")
    if key_size == 0:
        raise AvbError("property descriptor has an empty key")
    data_start = _PROPERTY_STRUCT.size
    data_end = data_start + key_size + 1 + value_size + 1
    if data_end > len(payload):
        raise AvbError("property descriptor data overruns the descriptor")
    key = _decode_utf8(payload[data_start : data_start + key_size], "property key")
    if payload[data_start + key_size] != 0:
        raise AvbError("property key is not NUL-terminated")
    value_start = data_start + key_size + 1
    value = payload[value_start : value_start + value_size]
    if payload[value_start + value_size] != 0:
        raise AvbError("property value is not NUL-terminated")
    return AvbProperty(key=key, value=value)


def _parse_hash(payload: bytes) -> AvbHashDescriptor:
    if len(payload) < _HASH_STRUCT.size:
        raise AvbError("hash descriptor is too short")
    (
        _tag,
        following,
        image_size,
        hash_algorithm_raw,
        partition_name_len,
        salt_len,
        digest_len,
        flags,
        _reserved,
    ) = _HASH_STRUCT.unpack_from(payload, 0)
    if flags & ~0x3:
        raise AvbError(f"hash descriptor has unknown flags 0x{flags:x}")
    hash_algorithm = _decode_hash_algorithm(hash_algorithm_raw)
    expected = _round8(
        _HASH_STRUCT.size - DESCRIPTOR_HEADER_SIZE + partition_name_len + salt_len + digest_len
    )
    if following != expected:
        raise AvbError("hash descriptor size does not match its variable data")
    data_start = _HASH_STRUCT.size
    data_end = data_start + partition_name_len + salt_len + digest_len
    if data_end > len(payload):
        raise AvbError("hash descriptor data overruns the descriptor")
    partition_name = _decode_utf8(
        payload[data_start : data_start + partition_name_len], "hash partition name"
    )
    if not partition_name:
        raise AvbError("hash descriptor has an empty partition name")
    offset = data_start + partition_name_len
    salt = payload[offset : offset + salt_len]
    offset += salt_len
    digest = payload[offset : offset + digest_len]
    _check_digest_length(hash_algorithm, digest_len, "hash descriptor")
    return AvbHashDescriptor(
        image_size=image_size,
        hash_algorithm=hash_algorithm,
        partition_name=partition_name,
        salt=salt,
        digest=digest,
        flags=flags,
    )


def _parse_hashtree(payload: bytes) -> AvbHashtreeDescriptor:
    if len(payload) < _HASHTREE_STRUCT.size:
        raise AvbError("hashtree descriptor is too short")
    (
        _tag,
        following,
        dm_verity_version,
        image_size,
        tree_offset,
        tree_size,
        data_block_size,
        hash_block_size,
        fec_num_roots,
        fec_offset,
        fec_size,
        hash_algorithm_raw,
        partition_name_len,
        salt_len,
        root_digest_len,
        flags,
        _reserved,
    ) = _HASHTREE_STRUCT.unpack_from(payload, 0)
    if flags & ~0x3:
        raise AvbError(f"hashtree descriptor has unknown flags 0x{flags:x}")
    hash_algorithm = _decode_hash_algorithm(hash_algorithm_raw)
    expected = _round8(
        _HASHTREE_STRUCT.size
        - DESCRIPTOR_HEADER_SIZE
        + partition_name_len
        + salt_len
        + root_digest_len
    )
    if following != expected:
        raise AvbError("hashtree descriptor size does not match its variable data")
    data_start = _HASHTREE_STRUCT.size
    data_end = data_start + partition_name_len + salt_len + root_digest_len
    if data_end > len(payload):
        raise AvbError("hashtree descriptor data overruns the descriptor")
    if data_block_size <= 0 or hash_block_size <= 0:
        raise AvbError("hashtree block sizes must be positive")
    if not _is_power_of_two(data_block_size) or not _is_power_of_two(hash_block_size):
        raise AvbError("hashtree block sizes must be powers of two")
    if tree_offset + tree_size > image_size:
        raise AvbError("hashtree tree overruns the image")
    partition_name = _decode_utf8(
        payload[data_start : data_start + partition_name_len],
        "hashtree partition name",
    )
    if not partition_name:
        raise AvbError("hashtree descriptor has an empty partition name")
    offset = data_start + partition_name_len
    salt = payload[offset : offset + salt_len]
    offset += salt_len
    root_digest = payload[offset : offset + root_digest_len]
    _check_digest_length(hash_algorithm, root_digest_len, "hashtree descriptor")
    return AvbHashtreeDescriptor(
        dm_verity_version=dm_verity_version,
        image_size=image_size,
        tree_offset=tree_offset,
        tree_size=tree_size,
        data_block_size=data_block_size,
        hash_block_size=hash_block_size,
        fec_num_roots=fec_num_roots,
        fec_offset=fec_offset,
        fec_size=fec_size,
        hash_algorithm=hash_algorithm,
        partition_name=partition_name,
        salt=salt,
        root_digest=root_digest,
        flags=flags,
    )


def _parse_kernel_cmdline(payload: bytes) -> AvbKernelCmdline:
    if len(payload) < _KERNEL_CMDLINE_STRUCT.size:
        raise AvbError("kernel cmdline descriptor is too short")
    _tag, following, flags, cmdline_len = _KERNEL_CMDLINE_STRUCT.unpack_from(payload, 0)
    if flags & ~0x3:
        raise AvbError(f"kernel cmdline descriptor has unknown flags 0x{flags:x}")
    expected = _round8(_KERNEL_CMDLINE_STRUCT.size - DESCRIPTOR_HEADER_SIZE + cmdline_len)
    if following != expected:
        raise AvbError("kernel cmdline descriptor size does not match its data")
    data_start = _KERNEL_CMDLINE_STRUCT.size
    data_end = data_start + cmdline_len
    if data_end > len(payload):
        raise AvbError("kernel cmdline data overruns the descriptor")
    cmdline = _decode_utf8(payload[data_start:data_end], "kernel cmdline")
    return AvbKernelCmdline(flags=flags, cmdline=cmdline)


def _parse_chain_partition(payload: bytes) -> AvbChainPartition:
    if len(payload) < _CHAIN_STRUCT.size:
        raise AvbError("chain partition descriptor is too short")
    (
        _tag,
        following,
        rollback_index_location,
        partition_name_len,
        public_key_len,
        flags,
        _reserved,
    ) = _CHAIN_STRUCT.unpack_from(payload, 0)
    if flags & ~0x1:
        raise AvbError(f"chain partition descriptor has unknown flags 0x{flags:x}")
    expected = _round8(
        _CHAIN_STRUCT.size - DESCRIPTOR_HEADER_SIZE + partition_name_len + public_key_len
    )
    if following != expected:
        raise AvbError("chain partition descriptor size does not match its data")
    data_start = _CHAIN_STRUCT.size
    data_end = data_start + partition_name_len + public_key_len
    if data_end > len(payload):
        raise AvbError("chain partition data overruns the descriptor")
    partition_name = _decode_utf8(
        payload[data_start : data_start + partition_name_len],
        "chain partition name",
    )
    if not partition_name:
        raise AvbError("chain partition descriptor has an empty partition name")
    if public_key_len == 0:
        raise AvbError("chain partition descriptor has an empty public key")
    public_key = payload[data_start + partition_name_len : data_end]
    return AvbChainPartition(
        rollback_index_location=rollback_index_location,
        partition_name=partition_name,
        public_key=public_key,
        flags=flags,
    )


def _decode_release(raw: bytes) -> str:
    return _decode_utf8(raw.rstrip(b"\0"), "release string")


def _decode_hash_algorithm(raw: bytes) -> str:
    try:
        algorithm = raw.rstrip(b"\0").decode("ascii")
    except UnicodeDecodeError as exc:
        raise AvbError("hash algorithm is not ASCII") from exc
    if algorithm not in _HASH_SIZES:
        raise AvbError(f"unsupported descriptor hash algorithm {algorithm!r}")
    return algorithm


def _decode_utf8(data: bytes, what: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AvbError(f"{what} is not valid UTF-8") from exc


def _decode_optional(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _check_digest_length(hash_algorithm: str, length: int, what: str) -> None:
    expected = _HASH_SIZES[hash_algorithm]
    if length not in (0, expected):
        raise AvbError(f"{what} digest is {length} bytes, expected {expected} for {hash_algorithm}")


def _check_range(offset: int, size: int, limit: int, what: str) -> None:
    if offset > limit or size > limit - offset:
        raise AvbError(f"{what} range {offset}+{size} exceeds its {limit}-byte block")


def _check_non_overlapping(
    ranges: tuple[tuple[int, int, str], ...],
    block: str,
) -> None:
    active = sorted((start, size, name) for start, size, name in ranges if size > 0)
    for (start, size, name), (next_start, _next_size, next_name) in itertools.pairwise(active):
        if start + size > next_start:
            raise AvbError(f"{block} {name} overlaps {next_name}")


def _round8(value: int) -> int:
    return (value + 7) // 8 * 8


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0
