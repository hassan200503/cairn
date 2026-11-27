from __future__ import annotations

from pathlib import Path

import pytest

from cairn.core.tristate import Tri
from cairn.provenance.avb import (
    AvbError,
    AvbSignature,
    load_vbmeta,
    parse_vbmeta,
    verify_vbmeta_signature,
)
from cairn.provenance.trust import (
    MAX_TRUSTED_KEY_BYTES,
    LockState,
    evaluate_lock_key,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "avb"
UNSIGNED = FIXTURE_DIR / "unsigned_vbmeta.img"
SIGNED = FIXTURE_DIR / "signed_vbmeta.img"
SIGNED_KEY = FIXTURE_DIR / "signed_vbmeta.avbpubkey"


def _signature(path: Path = SIGNED) -> AvbSignature:
    return verify_vbmeta_signature(load_vbmeta(path))


def test_locked_device_with_matching_key_is_true() -> None:
    result = evaluate_lock_key(
        _signature(),
        lock_state=LockState.LOCKED,
        trusted_key=SIGNED_KEY.read_bytes(),
    )

    assert result.state is Tri.TRUE
    assert result.lock_state is LockState.LOCKED
    assert result.key_matches is True
    assert result.signature_valid is True
    assert result.image_key_sha256 == result.trusted_key_sha256
    assert result.warnings == ()


def test_locked_device_with_mismatched_key_is_false() -> None:
    wrong_key = SIGNED_KEY.read_bytes()[:-1] + b"\x00"

    result = evaluate_lock_key(
        _signature(),
        lock_state=LockState.LOCKED,
        trusted_key=wrong_key,
    )

    assert result.state is Tri.FALSE
    assert result.key_matches is False
    assert "does not match" in result.reason


def test_unlocked_device_with_matching_key_is_true_with_warning() -> None:
    result = evaluate_lock_key(
        _signature(),
        lock_state=LockState.UNLOCKED,
        trusted_key=SIGNED_KEY.read_bytes(),
    )

    assert result.state is Tri.TRUE
    assert result.key_matches is True
    assert any("not enforced" in warning for warning in result.warnings)


def test_unlocked_device_with_mismatched_key_is_unknown_with_warning() -> None:
    wrong_key = SIGNED_KEY.read_bytes()[:-1] + b"\x00"

    result = evaluate_lock_key(
        _signature(),
        lock_state=LockState.UNLOCKED,
        trusted_key=wrong_key,
    )

    assert result.state is Tri.UNKNOWN
    assert result.key_matches is False
    assert any("not a trust result" in warning for warning in result.warnings)


def test_unknown_lock_state_is_unknown_even_with_matching_key() -> None:
    result = evaluate_lock_key(
        _signature(),
        lock_state=LockState.UNKNOWN,
        trusted_key=SIGNED_KEY.read_bytes(),
    )

    assert result.state is Tri.UNKNOWN
    assert result.key_matches is True
    assert "lock state is unknown" in result.reason


def test_missing_trusted_key_is_unknown() -> None:
    result = evaluate_lock_key(
        _signature(),
        lock_state=LockState.LOCKED,
        trusted_key=None,
    )

    assert result.state is Tri.UNKNOWN
    assert result.key_matches is None
    assert result.trusted_key_sha256 is None
    assert "no trusted key" in result.reason


def test_unsigned_image_is_unknown() -> None:
    result = evaluate_lock_key(
        _signature(UNSIGNED),
        lock_state=LockState.LOCKED,
        trusted_key=SIGNED_KEY.read_bytes(),
    )

    assert result.state is Tri.UNKNOWN
    assert result.signature_valid is None
    assert result.image_key_sha256 is None
    assert "unsigned" in result.reason


def test_invalid_signature_is_false_even_with_matching_key() -> None:
    data = bytearray(SIGNED.read_bytes())
    data[data.index(b"test-value")] ^= 1
    signature = verify_vbmeta_signature(parse_vbmeta(bytes(data)))

    result = evaluate_lock_key(
        signature,
        lock_state=LockState.LOCKED,
        trusted_key=SIGNED_KEY.read_bytes(),
    )

    assert signature.valid is False
    assert result.state is Tri.FALSE
    assert result.key_matches is True
    assert "signature is invalid" in result.reason


def test_invalid_signature_is_false_even_with_unknown_lock_state() -> None:
    data = bytearray(SIGNED.read_bytes())
    data[data.index(b"test-value")] ^= 1
    signature = verify_vbmeta_signature(parse_vbmeta(bytes(data)))

    result = evaluate_lock_key(
        signature,
        lock_state=LockState.UNKNOWN,
        trusted_key=SIGNED_KEY.read_bytes(),
    )

    assert result.state is Tri.FALSE
    assert result.key_matches is True


def test_empty_trusted_key_is_rejected() -> None:
    with pytest.raises(AvbError, match="must not be empty"):
        evaluate_lock_key(
            _signature(),
            lock_state=LockState.LOCKED,
            trusted_key=b"",
        )


def test_oversized_trusted_key_is_rejected() -> None:
    with pytest.raises(AvbError, match="above the"):
        evaluate_lock_key(
            _signature(),
            lock_state=LockState.LOCKED,
            trusted_key=b"x" * (MAX_TRUSTED_KEY_BYTES + 1),
        )


def test_lock_key_check_to_dict_is_machine_readable() -> None:
    result = evaluate_lock_key(
        _signature(),
        lock_state=LockState.LOCKED,
        trusted_key=SIGNED_KEY.read_bytes(),
    )

    payload = result.to_dict()
    assert payload["state"] == "TRUE"
    assert payload["lock_state"] == "locked"
    assert payload["key_matches"] is True
    assert payload["signature_valid"] is True
    assert payload["image_key_sha256"] == payload["trusted_key_sha256"]
    assert payload["warnings"] == []
