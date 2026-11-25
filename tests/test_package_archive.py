from __future__ import annotations

import hashlib
import json
import os
import stat
import warnings
import zipfile
from pathlib import Path

import pytest

from cairn.package.archive import (
    EntryKind,
    OtaMetadata,
    PackageError,
    PackageKind,
    classify_entry,
    load_package,
    sha256_file,
)
from cairn.package.fastboot_info import FlashCommand

FIXTURES = Path(__file__).parent / "fixtures"
FASTBOOT_INFO = (FIXTURES / "fastboot" / "fastboot-info.txt").read_text(encoding="utf-8")


def _zip(path: Path, entries: list[tuple[str, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return path


def _factory_entries() -> list[tuple[str, bytes]]:
    return [
        ("flash-all.sh", b"#!/bin/sh\n"),
        ("flash-all.bat", b"@echo off\n"),
        ("bootloader-shiba.img", b"bootloader"),
        ("radio-shiba.img", b"radio"),
        ("image-shiba.zip", b"PK nested bytes"),
        ("fastboot-info.txt", FASTBOOT_INFO.encode()),
        ("README.txt", b"read me"),
    ]


def test_factory_package_manifest(tmp_path: Path) -> None:
    path = _zip(tmp_path / "factory.zip", _factory_entries())

    manifest = load_package(path)

    assert manifest.kind is PackageKind.FACTORY
    assert manifest.fastboot_info is not None
    assert manifest.fastboot_info.version == 1
    assert len(manifest.fastboot_info.commands) == 16
    first = manifest.fastboot_info.commands[0]
    assert isinstance(first, FlashCommand)
    assert first.partition == "bootloader"
    assert manifest.unknown_entries == ("README.txt",)
    assert any("nested archive contents" in warning for warning in manifest.warnings)
    assert any("CRCs are not fully verified" in warning for warning in manifest.warnings)
    assert manifest.archive_sha256 is None
    assert manifest.ota_metadata is None
    assert manifest.payload_properties is None

    kinds = {entry.name: entry.kind for entry in manifest.entries}
    assert kinds["bootloader-shiba.img"] is EntryKind.IMAGE
    assert kinds["image-shiba.zip"] is EntryKind.NESTED_ARCHIVE
    assert kinds["flash-all.sh"] is EntryKind.FLASH_SCRIPT
    assert kinds["fastboot-info.txt"] is EntryKind.FASTBOOT_INFO
    assert kinds["README.txt"] is EntryKind.UNKNOWN


def test_hash_files_and_archive(tmp_path: Path) -> None:
    path = _zip(
        tmp_path / "factory.zip",
        [("boot.img", b"hello"), ("README.txt", b"x")],
    )

    manifest = load_package(path, hash_files=True, hash_archive=True)

    assert manifest.archive_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert manifest.archive_sha256 == sha256_file(path)
    boot = next(entry for entry in manifest.entries if entry.name == "boot.img")
    assert boot.sha256 == hashlib.sha256(b"hello").hexdigest()
    assert not any("CRCs are not fully verified" in warning for warning in manifest.warnings)


def test_ota_package_manifest(tmp_path: Path) -> None:
    metadata = (
        "# synthetic metadata\n"
        "ota-type=AB\n"
        "pre-device=shiba\n"
        "pre-device=husky\n"
        "post-build=shiba-user 15 AP4A.250105.002\n"
        "\n"
    )
    properties = "FILE_HASH=abc=\nFILE_SIZE=123\nMETADATA_HASH=def\nMETADATA_SIZE=456\n"
    path = _zip(
        tmp_path / "ota.zip",
        [
            ("META-INF/com/android/metadata", metadata.encode()),
            ("META-INF/com/android/otacert", b"cert"),
            ("META-INF/MANIFEST.MF", b"manifest"),
            ("payload.bin", b"payload"),
            ("payload_properties.txt", properties.encode()),
            ("care_map.pb", b"care"),
            ("apex_info.pb", b"apex"),
        ],
    )

    manifest = load_package(path)

    assert manifest.kind is PackageKind.OTA
    assert manifest.ota_metadata is not None
    assert manifest.ota_metadata.first("pre-device") == "shiba"
    assert manifest.ota_metadata.values("pre-device") == ("shiba", "husky")
    assert manifest.ota_metadata.first("missing") is None
    assert manifest.payload_properties is not None
    assert manifest.payload_properties["FILE_HASH"] == "abc="
    assert manifest.unknown_entries == ()

    kinds = {entry.name: entry.kind for entry in manifest.entries}
    assert kinds["META-INF/com/android/otacert"] is EntryKind.SIGNATURE
    assert kinds["META-INF/MANIFEST.MF"] is EntryKind.METADATA
    assert kinds["payload.bin"] is EntryKind.PAYLOAD
    assert kinds["payload_properties.txt"] is EntryKind.PAYLOAD_PROPERTIES
    assert kinds["care_map.pb"] is EntryKind.METADATA

    payload = manifest.to_dict()
    ota_metadata = payload["ota_metadata"]
    assert isinstance(ota_metadata, dict)
    assert ota_metadata["pre-device"] == ["shiba", "husky"]


def test_mixed_markers_are_unknown(tmp_path: Path) -> None:
    path = _zip(
        tmp_path / "mixed.zip",
        [("fastboot-info.txt", b"version 1\n"), ("payload.bin", b"payload")],
    )

    manifest = load_package(path)

    assert manifest.kind is PackageKind.UNKNOWN
    assert any("both OTA and factory" in warning for warning in manifest.warnings)


def test_empty_package_is_unknown(tmp_path: Path) -> None:
    path = _zip(tmp_path / "empty.zip", [])

    manifest = load_package(path)

    assert manifest.kind is PackageKind.UNKNOWN
    assert any("no recognized" in warning for warning in manifest.warnings)
    assert manifest.entries == ()


def test_duplicate_payload_property_fails(tmp_path: Path) -> None:
    path = _zip(
        tmp_path / "ota.zip",
        [
            ("payload.bin", b"payload"),
            ("payload_properties.txt", b"FILE_HASH=a\nFILE_HASH=b\n"),
        ],
    )

    with pytest.raises(PackageError, match="repeats key"):
        load_package(path)


def test_nested_fastboot_info_is_warned_not_parsed(tmp_path: Path) -> None:
    path = _zip(
        tmp_path / "factory.zip",
        [
            ("boot.img", b"boot"),
            ("image/fastboot-info.txt", b"version 1\nflash boot\n"),
        ],
    )

    manifest = load_package(path)

    assert manifest.kind is PackageKind.FACTORY
    assert manifest.fastboot_info is None
    assert any("not at the archive root" in warning for warning in manifest.warnings)


@pytest.mark.parametrize(
    "name",
    [
        "../evil.img",
        "/absolute.img",
        "C:/evil.img",
        "a//b.img",
        "./x.img",
    ],
)
def test_unsafe_entry_names_fail(tmp_path: Path, name: str) -> None:
    path = _zip(tmp_path / "bad.zip", [(name, b"x")])

    with pytest.raises(PackageError):
        load_package(path)


@pytest.mark.skipif(
    os.name == "nt",
    reason="zipfile normalizes backslashes to slashes on Windows",
)
def test_backslash_entry_fails(tmp_path: Path) -> None:
    path = _zip(tmp_path / "bad.zip", [("dir/evil.img", b"x")])
    data = path.read_bytes().replace(b"dir/evil.img", b"dir\\evil.img")
    path.write_bytes(data)

    with pytest.raises(PackageError, match="backslash"):
        load_package(path)


def test_duplicate_entry_fails(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("boot.img", b"a")
            archive.writestr("boot.img", b"b")

    with pytest.raises(PackageError, match="duplicate"):
        load_package(path)


def test_encrypted_entry_fails(tmp_path: Path) -> None:
    path = _zip(tmp_path / "encrypted.zip", [("boot.img", b"boot")])
    data = bytearray(path.read_bytes())
    assert data[:4] == b"PK\x03\x04"
    data[6] |= 0x01
    central = data.rfind(b"PK\x01\x02")
    assert central > 0
    data[central + 8] |= 0x01
    path.write_bytes(data)

    with pytest.raises(PackageError, match="encrypted"):
        load_package(path)


def test_symlink_entry_fails(tmp_path: Path) -> None:
    path = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("link.img")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(info, b"target")

    with pytest.raises(PackageError, match="symlink"):
        load_package(path)


def test_entry_count_limit(tmp_path: Path) -> None:
    path = _zip(
        tmp_path / "many.zip",
        [("a.img", b"a"), ("b.img", b"b"), ("c.img", b"c")],
    )

    with pytest.raises(PackageError, match="above the limit"):
        load_package(path, max_entries=2)


def test_uncompressed_size_limit(tmp_path: Path) -> None:
    path = _zip(tmp_path / "large.zip", [("boot.img", b"0123456789" * 2)])

    with pytest.raises(PackageError, match="uncompressed-size limit"):
        load_package(path, max_total_uncompressed=10)


def test_malformed_fastboot_info_fails(tmp_path: Path) -> None:
    path = _zip(tmp_path / "bad.zip", [("fastboot-info.txt", b"version 2\n")])

    with pytest.raises(PackageError, match=r"fastboot-info\.txt is malformed"):
        load_package(path)


def test_non_utf8_fastboot_info_fails(tmp_path: Path) -> None:
    path = _zip(tmp_path / "bad.zip", [("fastboot-info.txt", b"\xff\xfe")])

    with pytest.raises(PackageError, match="not valid UTF-8"):
        load_package(path)


def test_oversized_text_fails(tmp_path: Path) -> None:
    path = _zip(tmp_path / "bad.zip", [("fastboot-info.txt", b"version 1\n")])

    with pytest.raises(PackageError, match="text limit"):
        load_package(path, max_text_bytes=4)


def test_malformed_ota_metadata_fails(tmp_path: Path) -> None:
    path = _zip(
        tmp_path / "bad.zip",
        [("META-INF/com/android/metadata", b"not-a-pair\n")],
    )

    with pytest.raises(PackageError, match="not key=value"):
        load_package(path)


def test_not_a_zip_fails(tmp_path: Path) -> None:
    path = tmp_path / "not.zip"
    path.write_bytes(b"not a zip")

    with pytest.raises(PackageError, match="cannot read package"):
        load_package(path)


def test_missing_package_fails(tmp_path: Path) -> None:
    with pytest.raises(PackageError, match="not found"):
        load_package(tmp_path / "missing.zip")


def test_zero_limits_are_rejected(tmp_path: Path) -> None:
    path = _zip(tmp_path / "empty.zip", [])

    with pytest.raises(ValueError, match="must be positive"):
        load_package(path, max_entries=0)


def test_directory_entries_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "dirs.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("images/", b"")
        archive.writestr("images/boot.img", b"boot")

    manifest = load_package(path)

    assert [entry.name for entry in manifest.entries] == ["images/boot.img"]
    assert manifest.kind is PackageKind.FACTORY


def test_to_dict_is_json_serializable(tmp_path: Path) -> None:
    path = _zip(tmp_path / "factory.zip", _factory_entries())

    payload = load_package(path).to_dict()

    encoded = json.dumps(payload)
    assert '"kind": "factory"' in encoded
    issues = payload["issues"]
    assert isinstance(issues, dict)
    assert issues["unknown_entries"] == ["README.txt"]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("fastboot-info.txt", EntryKind.FASTBOOT_INFO),
        ("flash-all.sh", EntryKind.FLASH_SCRIPT),
        ("flash-all.bat", EntryKind.FLASH_SCRIPT),
        ("system.img", EntryKind.IMAGE),
        ("SYSTEM.IMG", EntryKind.IMAGE),
        ("image.zip", EntryKind.NESTED_ARCHIVE),
        ("payload.bin", EntryKind.PAYLOAD),
        ("payload_properties.txt", EntryKind.PAYLOAD_PROPERTIES),
        ("META-INF/com/android/metadata", EntryKind.OTA_METADATA),
        ("META-INF/com/android/otacert", EntryKind.SIGNATURE),
        ("META-INF/CERT.RSA", EntryKind.SIGNATURE),
        ("care_map.pb", EntryKind.METADATA),
        ("META-INF/MANIFEST.MF", EntryKind.METADATA),
        ("README.md", EntryKind.UNKNOWN),
    ],
)
def test_classify_entry(name: str, expected: EntryKind) -> None:
    assert classify_entry(name) is expected


def test_ota_metadata_helpers() -> None:
    metadata = OtaMetadata(entries=(("pre-device", "a"), ("pre-device", "b")))

    assert metadata.first("pre-device") == "a"
    assert metadata.values("pre-device") == ("a", "b")
    assert metadata.first("missing") is None
    assert metadata.to_dict() == {"pre-device": ["a", "b"]}
