from __future__ import annotations

import json
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from cairn.core.tristate import Tri
from cairn.package.archive import PackageManifest, load_package
from cairn.provenance.hash_index import (
    HashIndexError,
    KnownPackage,
    load_hash_index,
    verify_manifest,
)


def _zip(path: Path, entries: list[tuple[str, bytes]] | None = None) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries or [
            ("boot.img", b"boot"),
            ("README.txt", b"readme"),
        ]:
            archive.writestr(name, data)
    return path


def _manifest(path: Path) -> PackageManifest:
    manifest = load_package(path, hash_files=True, hash_archive=True)
    assert manifest.archive_sha256 is not None
    assert all(entry.sha256 is not None for entry in manifest.entries)
    return manifest


def _entry_hashes(manifest: PackageManifest) -> dict[str, str]:
    result: dict[str, str] = {}
    for entry in manifest.entries:
        assert entry.sha256 is not None
        result[entry.name] = entry.sha256
    return result


def _index_payload(
    manifest: PackageManifest,
    *,
    archive_sha256: str | None = None,
    entries: dict[str, str] | None = None,
    package_id: str = "test-package",
    device: str = "shiba",
    build: str = "TEST.1",
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "packages": [
            {
                "id": package_id,
                "device": device,
                "build": build,
                "archive_sha256": archive_sha256 or manifest.archive_sha256,
                "entries": entries or _entry_hashes(manifest),
            }
        ],
    }


def _write_index(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_index_match_is_true(tmp_path: Path) -> None:
    package_path = _zip(tmp_path / "factory.zip")
    manifest = _manifest(package_path)
    index = load_hash_index(_write_index(tmp_path / "index.json", _index_payload(manifest)))

    result = verify_manifest(index, manifest)

    assert result.state is Tri.TRUE
    assert result.package_id == "test-package"
    assert result.device == "shiba"
    assert result.build == "TEST.1"
    assert result.reasons
    assert "match the local index" in result.reasons[0]
    assert result.to_dict()["state"] == "TRUE"


def test_unknown_archive_is_unknown(tmp_path: Path) -> None:
    indexed_path = _zip(tmp_path / "indexed.zip")
    index = load_hash_index(
        _write_index(tmp_path / "index.json", _index_payload(_manifest(indexed_path)))
    )
    other_path = _zip(tmp_path / "other.zip", [("boot.img", b"other")])

    result = verify_manifest(index, _manifest(other_path))

    assert result.state is Tri.UNKNOWN
    assert result.package_id is None
    assert any("not in the local index" in reason for reason in result.reasons)


def test_unhashed_manifest_is_unknown(tmp_path: Path) -> None:
    package_path = _zip(tmp_path / "factory.zip")
    index = load_hash_index(
        _write_index(tmp_path / "index.json", _index_payload(_manifest(package_path)))
    )

    result = verify_manifest(index, load_package(package_path))

    assert result.state is Tri.UNKNOWN
    assert result.reasons == ("archive sha256 was not computed",)


def test_missing_entry_hash_is_unknown(tmp_path: Path) -> None:
    package_path = _zip(tmp_path / "factory.zip")
    manifest = _manifest(package_path)
    index = load_hash_index(_write_index(tmp_path / "index.json", _index_payload(manifest)))
    first, *rest = manifest.entries
    unhashed = replace(manifest, entries=(replace(first, sha256=None), *rest))

    result = verify_manifest(index, unhashed)

    assert result.state is Tri.UNKNOWN
    assert any("entry hash not computed" in reason for reason in result.reasons)


def test_entry_hash_mismatch_is_false(tmp_path: Path) -> None:
    package_path = _zip(tmp_path / "factory.zip")
    manifest = _manifest(package_path)
    entries = _entry_hashes(manifest)
    entries["boot.img"] = "0" * 64
    index = load_hash_index(
        _write_index(
            tmp_path / "index.json",
            _index_payload(manifest, entries=entries),
        )
    )

    result = verify_manifest(index, manifest)

    assert result.state is Tri.FALSE
    assert result.package_id == "test-package"
    assert any("entry hash mismatch" in reason for reason in result.reasons)


def test_entry_set_mismatch_is_false(tmp_path: Path) -> None:
    package_path = _zip(tmp_path / "factory.zip")
    manifest = _manifest(package_path)
    entries = _entry_hashes(manifest)
    del entries["README.txt"]
    index = load_hash_index(
        _write_index(
            tmp_path / "index.json",
            _index_payload(manifest, entries=entries),
        )
    )

    result = verify_manifest(index, manifest)

    assert result.state is Tri.FALSE
    assert any("unexpected entries" in reason for reason in result.reasons)


def test_uppercase_hashes_are_normalized(tmp_path: Path) -> None:
    package_path = _zip(tmp_path / "factory.zip")
    manifest = _manifest(package_path)
    assert manifest.archive_sha256 is not None
    payload = _index_payload(
        manifest,
        archive_sha256=manifest.archive_sha256.upper(),
        entries={name: digest.upper() for name, digest in _entry_hashes(manifest).items()},
    )
    index = load_hash_index(_write_index(tmp_path / "index.json", payload))

    assert verify_manifest(index, manifest).state is Tri.TRUE


def test_empty_index_matches_nothing(tmp_path: Path) -> None:
    package_path = _zip(tmp_path / "factory.zip")
    index = load_hash_index(
        _write_index(
            tmp_path / "index.json",
            {"schema_version": 1, "packages": []},
        )
    )

    result = verify_manifest(index, _manifest(package_path))

    assert result.state is Tri.UNKNOWN


def test_load_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "index.json"
    path.write_text(
        '{"schema_version": 1, "schema_version": 1, "packages": []}',
        encoding="utf-8",
    )

    with pytest.raises(HashIndexError, match="repeats JSON key"):
        load_hash_index(path)


def test_load_rejects_wrong_schema_version(tmp_path: Path) -> None:
    path = _write_index(
        tmp_path / "index.json",
        {"schema_version": 2, "packages": []},
    )

    with pytest.raises(HashIndexError, match="schema_version"):
        load_hash_index(path)


def test_load_rejects_boolean_schema_version(tmp_path: Path) -> None:
    path = _write_index(
        tmp_path / "index.json",
        {"schema_version": True, "packages": []},
    )

    with pytest.raises(HashIndexError, match="schema_version"):
        load_hash_index(path)


def test_load_rejects_duplicate_archive_hashes(tmp_path: Path) -> None:
    package_path = _zip(tmp_path / "factory.zip")
    payload = _index_payload(_manifest(package_path))
    packages = payload["packages"]
    assert isinstance(packages, list)
    duplicate = dict(packages[0])
    duplicate["id"] = "other"
    packages.append(duplicate)

    with pytest.raises(HashIndexError, match="repeats archive_sha256"):
        load_hash_index(_write_index(tmp_path / "index.json", payload))


def test_load_rejects_duplicate_package_ids(tmp_path: Path) -> None:
    package_path = _zip(tmp_path / "factory.zip")
    payload = _index_payload(_manifest(package_path))
    packages = payload["packages"]
    assert isinstance(packages, list)
    duplicate = dict(packages[0])
    duplicate["archive_sha256"] = "0" * 64
    packages.append(duplicate)

    with pytest.raises(HashIndexError, match="repeats package id"):
        load_hash_index(_write_index(tmp_path / "index.json", payload))


def test_load_rejects_bad_hash(tmp_path: Path) -> None:
    path = _write_index(
        tmp_path / "index.json",
        {
            "schema_version": 1,
            "packages": [
                {
                    "id": "bad",
                    "archive_sha256": "abc",
                    "entries": {"boot.img": "0" * 64},
                }
            ],
        },
    )

    with pytest.raises(HashIndexError, match="64-character hex"):
        load_hash_index(path)


def test_load_rejects_unsafe_entry_name(tmp_path: Path) -> None:
    path = _write_index(
        tmp_path / "index.json",
        {
            "schema_version": 1,
            "packages": [
                {
                    "id": "bad",
                    "archive_sha256": "0" * 64,
                    "entries": {"../boot.img": "0" * 64},
                }
            ],
        },
    )

    with pytest.raises(HashIndexError, match="unsafe path segment"):
        load_hash_index(path)


def test_load_rejects_directory_entry(tmp_path: Path) -> None:
    path = _write_index(
        tmp_path / "index.json",
        {
            "schema_version": 1,
            "packages": [
                {
                    "id": "bad",
                    "archive_sha256": "0" * 64,
                    "entries": {"images/": "0" * 64},
                }
            ],
        },
    )

    with pytest.raises(HashIndexError, match="must list files"):
        load_hash_index(path)


def test_load_rejects_empty_entries(tmp_path: Path) -> None:
    path = _write_index(
        tmp_path / "index.json",
        {
            "schema_version": 1,
            "packages": [{"id": "bad", "archive_sha256": "0" * 64, "entries": {}}],
        },
    )

    with pytest.raises(HashIndexError, match="must not be empty"):
        load_hash_index(path)


def test_load_rejects_unknown_keys(tmp_path: Path) -> None:
    package_path = _zip(tmp_path / "factory.zip")
    payload = _index_payload(_manifest(package_path))
    packages = payload["packages"]
    assert isinstance(packages, list)
    packages[0]["extra"] = True

    with pytest.raises(HashIndexError, match="unknown keys"):
        load_hash_index(_write_index(tmp_path / "index.json", payload))


def test_load_rejects_non_utf8(tmp_path: Path) -> None:
    path = tmp_path / "index.json"
    path.write_bytes(b"\xff\xfe")

    with pytest.raises(HashIndexError, match="cannot read"):
        load_hash_index(path)


def test_load_rejects_oversized_index(tmp_path: Path) -> None:
    path = _write_index(
        tmp_path / "index.json",
        {"schema_version": 1, "packages": []},
    )

    with pytest.raises(HashIndexError, match="above the"):
        load_hash_index(path, max_bytes=10)


def test_load_rejects_missing_index(tmp_path: Path) -> None:
    with pytest.raises(HashIndexError, match="not found"):
        load_hash_index(tmp_path / "missing.json")


def test_load_rejects_zero_limit(tmp_path: Path) -> None:
    path = _write_index(
        tmp_path / "index.json",
        {"schema_version": 1, "packages": []},
    )

    with pytest.raises(ValueError, match="must be positive"):
        load_hash_index(path, max_bytes=0)


def test_known_package_to_dict() -> None:
    package = KnownPackage(
        package_id="pkg",
        archive_sha256="0" * 64,
        entries=(("boot.img", "1" * 64),),
        device="shiba",
        build="TEST.1",
    )

    assert package.entry_hashes() == {"boot.img": "1" * 64}
    assert package.to_dict()["id"] == "pkg"
    assert package.to_dict()["entries"] == {"boot.img": "1" * 64}
