"""Device-catalog parsing, anchoring, and CLI tests.

The catalog is caller-supplied anchoring input, not device evidence: these
tests pin the strict schema (uncited entries and raw identity are refused),
the key/sha256 cross-check, and the catalog-anchored `avb key-check` path.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from cairn.catalog import (
    CATALOG_SCHEMA_VERSION,
    CatalogError,
    DeviceCatalog,
    load_catalog,
    parse_catalog,
)
from cairn.cli import EXIT_FAILED, EXIT_OK, EXIT_USAGE, main

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "avb"
SIGNED_KEY = FIXTURE_DIR / "signed_vbmeta.avbpubkey"

_FINGERPRINT = hashlib.sha256(b"device-fingerprint-a").hexdigest()
_KEY_B64 = base64.b64encode(SIGNED_KEY.read_bytes()).decode("ascii")
_KEY_SHA = hashlib.sha256(SIGNED_KEY.read_bytes()).hexdigest()


def _catalog_document() -> dict[str, object]:
    return {
        "kind": "cairn.catalog",
        "schema_version": CATALOG_SCHEMA_VERSION,
        "devices": [
            {
                "product": "shiba",
                "fingerprint_sha256": _FINGERPRINT,
                "serial_sha256": None,
                "trusted_key_sha256": _KEY_SHA,
                "trusted_key_b64": _KEY_B64,
                "expected_lock_state": "locked",
                "source": "HF-0001",
                "notes": "test device",
            }
        ],
        "packages": [
            {
                "archive_sha256": hashlib.sha256(b"package").hexdigest(),
                "label": "pixel8-factory",
                "source": "https://developers.google.com/android/images",
                "notes": None,
            }
        ],
    }


def _catalog_file(tmp_path: Path, document: dict[str, object] | None = None) -> Path:
    path = tmp_path / "catalog.json"
    path.write_text(
        json.dumps(document if document is not None else _catalog_document()), encoding="utf-8"
    )
    return path


def test_catalog_roundtrip_and_matching(tmp_path: Path) -> None:
    catalog = load_catalog(_catalog_file(tmp_path))
    assert isinstance(catalog, DeviceCatalog)
    entry = catalog.device_by_fingerprint(_FINGERPRINT)
    assert entry is not None
    assert entry.product == "shiba"
    assert entry.trusted_key == SIGNED_KEY.read_bytes()
    assert entry.source == "HF-0001"
    assert catalog.device_by_fingerprint("f" * 64) is None
    assert catalog.device_by_product("shiba") is not None
    assert catalog.device_by_product("nope") is None
    assert catalog.package_by_archive(hashlib.sha256(b"package").hexdigest()) is not None


def test_catalog_refuses_an_uncited_entry(tmp_path: Path) -> None:
    document = _catalog_document()
    document["devices"][0]["source"] = "  "  # type: ignore[index]
    with pytest.raises(CatalogError, match="uncited"):
        parse_catalog(document)


def test_catalog_refuses_a_key_that_does_not_hash_to_its_sha256(tmp_path: Path) -> None:
    document = _catalog_document()
    document["devices"][0]["trusted_key_sha256"] = "a" * 64  # type: ignore[index]
    with pytest.raises(CatalogError, match="does not hash"):
        parse_catalog(document)


def test_catalog_refuses_a_wrong_schema_version_and_unknown_keys() -> None:
    bad_version = _catalog_document()
    bad_version["schema_version"] = 99
    with pytest.raises(CatalogError, match="schema_version"):
        parse_catalog(bad_version)
    extra = _catalog_document()
    extra["serial"] = "raw-serial-string"
    with pytest.raises(CatalogError, match="unknown keys"):
        parse_catalog(extra)


def test_catalog_refuses_a_non_hex64_fingerprint() -> None:
    document = _catalog_document()
    document["devices"][0]["fingerprint_sha256"] = "not-a-fingerprint"  # type: ignore[index]
    with pytest.raises(CatalogError, match="64 lowercase hex"):
        parse_catalog(document)


def test_catalog_check_cli_reports_entries(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _catalog_file(tmp_path)
    exit_code = main(["catalog", "check", str(path)])
    assert exit_code == EXIT_OK
    text = capsys.readouterr().out
    assert "shiba" in text
    assert "source: HF-0001" in text


def test_catalog_check_cli_refuses_a_broken_catalog(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    exit_code = main(["catalog", "check", str(path)])
    assert exit_code == EXIT_FAILED
    assert "not valid JSON" in capsys.readouterr().err
    assert main(["catalog", "check", str(_catalog_file(tmp_path))]) == EXIT_OK


def test_avb_key_check_with_a_catalog_anchored_key_is_true(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    catalog_path = _catalog_file(tmp_path)
    exit_code = main(
        [
            "avb",
            "key-check",
            str(FIXTURE_DIR / "signed_vbmeta.img"),
            "--catalog",
            str(catalog_path),
            "--device-fingerprint",
            _FINGERPRINT,
            "--lock-state",
            "locked",
        ]
    )
    assert exit_code == EXIT_OK
    text = capsys.readouterr().out
    assert "key trust: TRUE" in text
    assert "trusted key source: HF-0001" in text


def test_avb_key_check_with_a_catalog_anchored_key_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    catalog_path = _catalog_file(tmp_path)
    exit_code = main(
        [
            "avb",
            "key-check",
            str(FIXTURE_DIR / "signed_vbmeta.img"),
            "--catalog",
            str(catalog_path),
            "--product",
            "shiba",
            "--lock-state",
            "locked",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_OK
    assert payload["trusted_key_source"] == "HF-0001"
    assert payload["key_matches"] is True


def test_avb_key_check_refuses_a_mismatched_catalog_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    document = _catalog_document()
    wrong_key = SIGNED_KEY.read_bytes()[:-1] + b"\x00"
    document["devices"][0]["trusted_key_b64"] = base64.b64encode(wrong_key).decode("ascii")  # type: ignore[index]
    document["devices"][0]["trusted_key_sha256"] = hashlib.sha256(wrong_key).hexdigest()  # type: ignore[index]
    catalog_path = _catalog_file(tmp_path, document)
    exit_code = main(
        [
            "avb",
            "key-check",
            str(FIXTURE_DIR / "signed_vbmeta.img"),
            "--catalog",
            str(catalog_path),
            "--product",
            "shiba",
            "--lock-state",
            "locked",
        ]
    )
    assert exit_code == EXIT_FAILED
    assert "key trust: FALSE" in capsys.readouterr().out


def test_avb_key_check_refuses_an_unmatched_device(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        [
            "avb",
            "key-check",
            str(FIXTURE_DIR / "signed_vbmeta.img"),
            "--catalog",
            str(_catalog_file(tmp_path)),
            "--product",
            "unknown-device",
            "--lock-state",
            "locked",
        ]
    )
    assert exit_code == EXIT_USAGE
    assert "no catalog device matches" in capsys.readouterr().err
