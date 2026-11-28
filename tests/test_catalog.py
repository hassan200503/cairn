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
    load_catalog_verified,
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
                "rollback_bounds": None,
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


def test_catalog_parses_rollback_bounds(tmp_path: Path) -> None:
    document = _catalog_document()
    document["devices"][0]["rollback_bounds"] = {
        "1": {"minimum": 2, "maximum": 7},
        "0": {"maximum": 3},
    }  # type: ignore[index]
    catalog = load_catalog(_catalog_file(tmp_path, document))
    entry = catalog.device_by_fingerprint(_FINGERPRINT)
    assert entry is not None
    assert entry.rollback_bounds[1].minimum == 2
    assert entry.rollback_bounds[1].maximum == 7
    assert entry.rollback_bounds[0].minimum is None
    assert entry.rollback_bounds[0].maximum == 3


def test_catalog_refuses_unusable_rollback_bounds() -> None:
    for bad, message in (
        ({"1": {}}, "at least one end"),
        ({"1": {"minimum": 5, "maximum": 2}}, "minimum exceeds"),
        ({"-1": {"maximum": 2}}, "non-negative integer"),
        ({"1": {"maximum": -3}}, "outside 0"),
        ({"x": {"maximum": 2}}, "non-negative integer"),
        ({"1": {"maximum": "2"}}, "must be an integer"),
        ({"1": {"middle": 2}}, "only 'minimum' and 'maximum'"),
        ([{"maximum": 2}], "must be an object"),
    ):
        document = _catalog_document()
        document["devices"][0]["rollback_bounds"] = bad  # type: ignore[index]
        with pytest.raises(CatalogError, match=message):
            parse_catalog(document)


def test_catalog_refuses_an_old_schema_version() -> None:
    document = _catalog_document()
    document["schema_version"] = CATALOG_SCHEMA_VERSION - 1
    with pytest.raises(CatalogError, match="schema_version"):
        parse_catalog(document)


def test_rollback_check_with_a_catalog_bound_proves_safety(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from cairn.provenance.avb import load_vbmeta

    package_index = load_vbmeta(FIXTURE_DIR / "signed_vbmeta.img").header.rollback_index
    document = _catalog_document()
    document["devices"][0]["rollback_bounds"] = {  # type: ignore[index]
        "0": {"maximum": package_index}
    }
    catalog_path = _catalog_file(tmp_path, document)
    exit_code = main(
        [
            "rollback",
            "check",
            str(FIXTURE_DIR / "signed_vbmeta.img"),
            "--catalog",
            str(catalog_path),
            "--product",
            "shiba",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_OK
    assert payload["state"] == "TRUE"
    assert payload["rollback_bounds_source"] == "HF-0001"


def test_rollback_check_with_a_catalog_bound_proves_a_downgrade(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from cairn.provenance.avb import load_vbmeta

    package_index = load_vbmeta(FIXTURE_DIR / "signed_vbmeta.img").header.rollback_index
    document = _catalog_document()
    document["devices"][0]["rollback_bounds"] = {  # type: ignore[index]
        "0": {"minimum": package_index + 1}
    }
    catalog_path = _catalog_file(tmp_path, document)
    exit_code = main(
        [
            "rollback",
            "check",
            str(FIXTURE_DIR / "signed_vbmeta.img"),
            "--catalog",
            str(catalog_path),
            "--device-fingerprint",
            _FINGERPRINT,
        ]
    )
    assert exit_code == EXIT_FAILED
    out = capsys.readouterr().out
    assert "FALSE" in out
    assert "rollback bounds source: HF-0001" in out


def test_rollback_check_with_a_catalog_entry_without_bounds_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    catalog_path = _catalog_file(tmp_path)
    exit_code = main(
        [
            "rollback",
            "check",
            str(FIXTURE_DIR / "signed_vbmeta.img"),
            "--catalog",
            str(catalog_path),
            "--product",
            "shiba",
        ]
    )
    assert exit_code == EXIT_FAILED
    assert "carries no rollback_bounds" in capsys.readouterr().err


def test_rollback_check_requires_a_catalog_entry_selector(tmp_path: Path) -> None:
    exit_code = main(
        [
            "rollback",
            "check",
            str(FIXTURE_DIR / "signed_vbmeta.img"),
            "--catalog",
            str(_catalog_file(tmp_path)),
        ]
    )
    assert exit_code == EXIT_USAGE


def _key_file(tmp_path: Path) -> Path:
    key_path = tmp_path / "catalog.key"
    key_path.write_bytes(b"k" * 32)
    return key_path


def test_catalog_sign_and_verify_roundtrip(tmp_path: Path) -> None:
    catalog_path = _catalog_file(tmp_path)
    key = _key_file(tmp_path)
    assert main(["catalog", "sign", str(catalog_path), "--key", str(key)]) == EXIT_OK
    assert main(["catalog", "verify", str(catalog_path), "--key", str(key)]) == EXIT_OK


def test_catalog_verify_refuses_a_tampered_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    catalog_path = _catalog_file(tmp_path)
    key = _key_file(tmp_path)
    assert main(["catalog", "sign", str(catalog_path), "--key", str(key)]) == EXIT_OK
    document = json.loads(catalog_path.read_text(encoding="utf-8"))
    document["devices"][0]["notes"] = "tampered"
    catalog_path.write_text(json.dumps(document), encoding="utf-8")
    assert main(["catalog", "verify", str(catalog_path), "--key", str(key)]) == EXIT_FAILED
    assert "does not match" in capsys.readouterr().err


def test_rollback_check_refuses_a_bad_catalog_signature(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    catalog_path = _catalog_file(tmp_path)
    key = _key_file(tmp_path)
    assert main(["catalog", "sign", str(catalog_path), "--key", str(key)]) == EXIT_OK
    sig_path = tmp_path / "wrong.sig"
    sig_path.write_text("0" * 64, encoding="ascii")
    exit_code = main(
        [
            "rollback",
            "check",
            str(FIXTURE_DIR / "signed_vbmeta.img"),
            "--catalog",
            str(catalog_path),
            "--catalog-key",
            str(key),
            "--catalog-signature",
            str(sig_path),
            "--product",
            "shiba",
        ]
    )
    assert exit_code == EXIT_USAGE
    assert "does not match" in capsys.readouterr().err


def test_avb_key_check_verifies_the_catalog_signature(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    catalog_path = _catalog_file(tmp_path)
    key = _key_file(tmp_path)
    assert main(["catalog", "sign", str(catalog_path), "--key", str(key)]) == EXIT_OK
    exit_code = main(
        [
            "avb",
            "key-check",
            str(FIXTURE_DIR / "signed_vbmeta.img"),
            "--catalog",
            str(catalog_path),
            "--catalog-key",
            str(key),
            "--catalog-signature",
            str(tmp_path / "catalog.json.sig"),
            "--product",
            "shiba",
            "--lock-state",
            "locked",
        ]
    )
    assert exit_code == EXIT_OK
    assert "key trust: TRUE" in capsys.readouterr().out


def test_rollback_check_refuses_key_without_signature(tmp_path: Path) -> None:
    exit_code = main(
        [
            "rollback",
            "check",
            str(FIXTURE_DIR / "signed_vbmeta.img"),
            "--catalog",
            str(_catalog_file(tmp_path)),
            "--catalog-key",
            str(_key_file(tmp_path)),
            "--product",
            "shiba",
        ]
    )
    assert exit_code == EXIT_USAGE


def test_catalog_key_rotation_invalidates_the_old_signature(tmp_path: Path) -> None:
    """Key rotation (KU-018): re-signing under a new key is the whole procedure.

    The old signature must fail against the new key and the re-signed file must
    verify only with the new key, on the direct loader and on the anchoring
    path an operator actually uses.
    """
    catalog_path = _catalog_file(tmp_path)
    old_key = _key_file(tmp_path)  # b"k" * 32
    new_key = tmp_path / "catalog-rotated.key"
    new_key.write_bytes(b"r" * 32)
    old_sig = tmp_path / "catalog.json.sig"

    assert main(["catalog", "sign", str(catalog_path), "--key", str(old_key)]) == EXIT_OK
    old_sig_text = old_sig.read_text(encoding="ascii")

    # Rotation: the catalog is re-signed under the new key; the .sig is replaced.
    assert main(["catalog", "sign", str(catalog_path), "--key", str(new_key)]) == EXIT_OK
    assert main(["catalog", "verify", str(catalog_path), "--key", str(new_key)]) == EXIT_OK

    # The old signature no longer verifies under the new key, anywhere.
    old_sig.write_text(old_sig_text, encoding="ascii")
    assert main(["catalog", "verify", str(catalog_path), "--key", str(new_key)]) == EXIT_FAILED
    with pytest.raises(CatalogError):
        load_catalog_verified(
            catalog_path, hmac_key=new_key.read_bytes(), signature=old_sig_text.strip()
        )
    # Note what rotation does NOT guarantee: the file bytes did not change, so
    # the old key still verifies its own (old) signature. Rotation's promise is
    # that an operator trusting only the new key rejects the old signature —
    # pinned above — never that old-key verification stops working.


def test_catalog_rotation_through_the_anchoring_path(tmp_path: Path, capsys) -> None:
    """After rotation the wizard/rollback anchoring path trusts the new key only."""
    document = _catalog_document()
    # A cited maximum bound makes the anchored evaluation deterministic (the
    # package counter is not lower, so SR-004 is TRUE); the point of this test
    # is that the post-rotation signature verifies on the anchoring path.
    document["devices"][0]["rollback_bounds"] = {"0": {"minimum": 0, "maximum": 0}}  # type: ignore[index]
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(json.dumps(document), encoding="utf-8")
    new_key = tmp_path / "catalog-rotated.key"
    new_key.write_bytes(b"r" * 32)

    assert main(["catalog", "sign", str(catalog_path), "--key", str(new_key)]) == EXIT_OK
    exit_code = main(
        [
            "rollback",
            "check",
            str(FIXTURE_DIR / "signed_vbmeta.img"),
            "--catalog",
            str(catalog_path),
            "--catalog-key",
            str(new_key),
            "--catalog-signature",
            str(tmp_path / "catalog.json.sig"),
            "--product",
            "shiba",
        ]
    )
    assert exit_code == EXIT_OK
    assert "rollback bounds source: HF-0001" in capsys.readouterr().out
