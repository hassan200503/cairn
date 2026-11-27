"""Vault, asset verification, SR-008/SR-009 rules, and the M6 recovery drill tests.

Everything runs in the simulator or in memory; no real device is touched.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cairn.core.tristate import Tri
from cairn.executor.executor import WriteTransport
from cairn.recovery import (
    AssetVerdict,
    DrillInputs,
    VaultDevice,
    VaultDeviceMismatch,
    VaultError,
    VaultTamperedError,
    create_vault,
    decrypt_entry,
    load_vault,
    readiness_check,
    restore_check,
    run_drill,
    save_vault,
    verify_assets,
)
from cairn.safety.engine import CheckState, SafetyContext, SafetyEngine
from cairn.tools.runner import ToolResult

NOW = datetime(2026, 11, 27, 12, 0, 0, tzinfo=UTC)
_PASSPHRASE = "correct horse battery staple"
_PARTITION_BYTES = b"persist-partition-content-0123456789"


def _device(serial: str = "serial-a") -> VaultDevice:
    import hashlib

    return VaultDevice(
        product="pixel-test",
        serial_sha256=hashlib.sha256(serial.encode()).hexdigest(),
        fingerprint_sha256=hashlib.sha256(("hw-" + serial).encode()).hexdigest(),
    )


def _asset(tmp_path: Path, data: bytes = _PARTITION_BYTES) -> Path:
    path = tmp_path / "persist.img"
    path.write_bytes(data)
    return path


def _sha(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------


def test_vault_roundtrip_preserves_bytes(tmp_path: Path) -> None:
    vault = create_vault(
        device=_device(), entries={"persist": _PARTITION_BYTES}, passphrase=_PASSPHRASE, now=NOW
    )
    path = tmp_path / "vault.json"
    save_vault(path, vault, passphrase=_PASSPHRASE)

    loaded = load_vault(path, passphrase=_PASSPHRASE)
    assert loaded.device.matches(_device())
    assert decrypt_entry(loaded, "persist", passphrase=_PASSPHRASE) == _PARTITION_BYTES


def test_vault_refuses_wrong_passphrase_and_tampering(tmp_path: Path) -> None:
    vault = create_vault(
        device=_device(), entries={"persist": _PARTITION_BYTES}, passphrase=_PASSPHRASE, now=NOW
    )
    path = tmp_path / "vault.json"
    save_vault(path, vault, passphrase=_PASSPHRASE)

    with pytest.raises(VaultTamperedError):
        load_vault(path, passphrase="wrong passphrase entirely")

    document = json.loads(path.read_text(encoding="utf-8"))
    document["device"]["product"] = "pixel-other"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(VaultTamperedError):
        load_vault(path, passphrase=_PASSPHRASE)

    # A flipped bit inside a ciphertext is caught by the MAC too.
    document = json.loads(path.read_text(encoding="utf-8"))
    blob = bytearray(__import__("base64").b64decode(document["entries"][0]["ciphertext_b64"]))
    blob[0] ^= 0x01
    document["entries"][0]["ciphertext_b64"] = __import__("base64").b64encode(bytes(blob)).decode()
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(VaultTamperedError):
        load_vault(path, passphrase=_PASSPHRASE)


def test_vault_restore_is_same_device_only(tmp_path: Path) -> None:
    vault = create_vault(
        device=_device("serial-a"),
        entries={"persist": _PARTITION_BYTES},
        passphrase=_PASSPHRASE,
        now=NOW,
    )
    assert restore_check(vault, _device("serial-a")) is True
    with pytest.raises(VaultDeviceMismatch, match="never overridable"):
        restore_check(vault, _device("serial-b"))


def test_vault_rejects_unsafe_names_and_duplicates(tmp_path: Path) -> None:
    with pytest.raises(VaultError, match="unsafe vault partition"):
        create_vault(
            device=_device(),
            entries={"../boot": _PARTITION_BYTES},
            passphrase=_PASSPHRASE,
            now=NOW,
        )
    vault = create_vault(
        device=_device(),
        entries={"persist": _PARTITION_BYTES},
        passphrase=_PASSPHRASE,
        now=NOW,
    )
    object.__setattr__(vault, "entries", vault.entries + vault.entries)
    with pytest.raises(VaultError, match="repeats a partition entry"):
        vault.__post_init__()


# ---------------------------------------------------------------------------
# Asset verification and SR-008/SR-009 rules
# ---------------------------------------------------------------------------


def test_asset_verification_is_tri_state(tmp_path: Path) -> None:
    asset = _asset(tmp_path)
    good = verify_assets({"persist": (asset, _sha(_PARTITION_BYTES))})
    assert good[0].state is Tri.TRUE

    bad = verify_assets({"persist": (asset, _sha(b"other"))})
    assert bad[0].state is Tri.FALSE

    missing = verify_assets({"persist": (tmp_path / "nope.img", _sha(_PARTITION_BYTES))})
    assert missing[0].state is Tri.UNKNOWN

    malformed = verify_assets({"persist": (asset, "nothex")})
    assert malformed[0].state is Tri.UNKNOWN


def test_readiness_check_blocks_unknown_and_false() -> None:
    true_all = readiness_check(
        (AssetVerdict("persist", "p", Tri.TRUE, "ok"),),
        last_resort_stated=True,
        observed_at=NOW,
    )
    assert true_all.state is Tri.TRUE
    unknown = readiness_check((), last_resort_stated=True, observed_at=NOW)
    assert unknown.state is Tri.UNKNOWN
    no_path = readiness_check(
        (AssetVerdict("persist", "p", Tri.TRUE, "ok"),),
        last_resort_stated=False,
        observed_at=NOW,
    )
    assert no_path.state is Tri.UNKNOWN
    false = readiness_check(
        (AssetVerdict("persist", "p", Tri.FALSE, "mismatch"),),
        last_resort_stated=True,
        observed_at=NOW,
    )
    assert false.state is Tri.FALSE


def test_engine_rules_sr008_sr009_block_without_input() -> None:
    report = SafetyEngine.pre_approval().evaluate(SafetyContext())
    sr008 = report.rule("SR-008")
    sr009 = report.rule("SR-009")
    assert sr008 is not None
    assert sr008.state is Tri.UNKNOWN
    assert sr009 is not None
    assert sr009.state is Tri.UNKNOWN
    assert "SR-008" in report.blocking
    assert "SR-009" in report.blocking
    assert not report.can_proceed


def test_engine_rules_sr008_sr009_pass_and_refuse() -> None:
    passing = SafetyEngine.pre_approval().evaluate(
        SafetyContext(
            recovery_readiness=CheckState(state=Tri.TRUE, detail="assets verified"),
            vault_backup=CheckState(state=Tri.TRUE, detail="vault bound to device"),
        )
    )
    assert passing.rule("SR-008").state is Tri.TRUE  # type: ignore[union-attr]
    assert passing.rule("SR-009").state is Tri.TRUE  # type: ignore[union-attr]

    refusing = SafetyEngine.pre_approval().evaluate(
        SafetyContext(
            recovery_readiness=CheckState(state=Tri.FALSE, detail="asset hash mismatch"),
            vault_backup=CheckState(state=Tri.FALSE, detail="device identity mismatch"),
        )
    )
    assert refusing.verdict is Tri.FALSE
    assert "SR-008" in refusing.blocking
    assert "SR-009" in refusing.blocking


# ---------------------------------------------------------------------------
# M6 drill
# ---------------------------------------------------------------------------


class DrillTransport(WriteTransport):
    def __init__(self) -> None:
        self.written: dict[str, bytes | None] = {}
        self.fail = False

    def run_write(self, step: object, *, image_path: Path | None, timeout_s: float) -> ToolResult:
        from cairn.plan.planner import PlanStep

        assert isinstance(step, PlanStep)
        self.written[step.partition or ""] = None if image_path is None else image_path.read_bytes()
        if self.fail:
            return ToolResult(
                argv=("flash", step.partition or ""),
                exit_code=1,
                stdout="",
                stderr="FAILED (remote: 'simulated failure')",
                duration_s=0.0,
            )
        return ToolResult(
            argv=("flash", step.partition or ""),
            exit_code=0,
            stdout="OKAY",
            stderr="",
            duration_s=0.0,
        )


def _drill_inputs(tmp_path: Path) -> DrillInputs:
    return DrillInputs(
        partition="persist",
        asset_path=_asset(tmp_path),
        asset_sha256=_sha(_PARTITION_BYTES),
        device=_device("serial-a"),
        other_device=_device("serial-b"),
        vault_path=tmp_path / "vault.json",
        staging_dir=tmp_path / "staging",
        passphrase=_PASSPHRASE,
        journal_path=tmp_path / "drill.journal",
        last_resort_path="EDL 9008 entry via test point, service only",
    )


def test_drill_passes_same_device_and_refuses_cross_device(tmp_path: Path) -> None:
    transport = DrillTransport()
    report = run_drill(_drill_inputs(tmp_path), transport, now=NOW)

    assert report.verdict is Tri.TRUE
    assert report.simulated
    assert report.same_device_restored
    assert report.cross_device_refused
    assert transport.written["persist"] == _PARTITION_BYTES
    names = [step.name for step in report.steps]
    assert names == [
        "asset-verification",
        "last-resort-path",
        "vault-backup",
        "vault-integrity",
        "cross-device-refusal",
        "same-device-restore",
    ]


def test_drill_fails_without_a_stated_last_resort_path(tmp_path: Path) -> None:
    inputs = _drill_inputs(tmp_path)
    stripped = DrillInputs(
        partition=inputs.partition,
        asset_path=inputs.asset_path,
        asset_sha256=inputs.asset_sha256,
        device=inputs.device,
        other_device=inputs.other_device,
        vault_path=inputs.vault_path,
        staging_dir=inputs.staging_dir,
        passphrase=inputs.passphrase,
        journal_path=inputs.journal_path,
        last_resort_path="  ",
    )
    report = run_drill(stripped, DrillTransport(), now=NOW)
    assert report.verdict is Tri.FALSE
    assert not report.same_device_restored
    assert not (tmp_path / "vault.json").exists()


def test_drill_fails_on_an_asset_hash_mismatch(tmp_path: Path) -> None:
    inputs = _drill_inputs(tmp_path)
    wrong_hash = DrillInputs(
        partition=inputs.partition,
        asset_path=inputs.asset_path,
        asset_sha256=_sha(b"different"),
        device=inputs.device,
        other_device=inputs.other_device,
        vault_path=inputs.vault_path,
        staging_dir=inputs.staging_dir,
        passphrase=inputs.passphrase,
        journal_path=inputs.journal_path,
        last_resort_path=inputs.last_resort_path,
    )
    report = run_drill(wrong_hash, DrillTransport(), now=NOW)
    assert report.verdict is Tri.FALSE
    assert report.steps[0].state is Tri.FALSE


def test_drill_reports_a_failed_restore_write(tmp_path: Path) -> None:
    transport = DrillTransport()
    transport.fail = True
    report = run_drill(_drill_inputs(tmp_path), transport, now=NOW)
    assert report.verdict is Tri.FALSE
    assert not report.same_device_restored
    assert report.cross_device_refused
