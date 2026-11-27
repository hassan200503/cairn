"""The M6 recovery drill.

The drill proves the recovery story end to end *in the simulator*:

1. recovery assets are hash-verified on the host (SR-008);
2. a critical partition image is backed up into an encrypted vault bound to the
   device identity (SR-009);
3. the vault is restored **to the same device** through a journaled, simulator-only
   write;
4. a restore attempted against a **different device identity is refused** before
   any write, and the refusal is recorded.

The drill result is `SIMULATED`, never device evidence, and it never touches real
hardware: the only write-capable transport is the transcript simulator. Passing the
drill is one input to the M6 gate; the real-device write transport still requires
the external safety review and hardware drills described in T15.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cairn.core.errors import ToolError
from cairn.core.tristate import Tri
from cairn.executor import Journal, JournalKind
from cairn.executor.executor import WriteTransport
from cairn.plan.planner import PlanAction, PlanStep
from cairn.recovery.assets import AssetVerdict, verify_assets
from cairn.recovery.vault import (
    Vault,
    VaultDevice,
    VaultDeviceMismatch,
    VaultError,
    VaultTamperedError,
    create_vault,
    decrypt_entry,
    load_vault,
    restore_check,
    save_vault,
)


class DrillError(ToolError):
    code = "DRILL_ERROR"


@dataclass(frozen=True, slots=True)
class DrillStep:
    name: str
    state: Tri
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "state": self.state.name, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class DrillReport:
    verdict: Tri
    simulated: bool
    steps: tuple[DrillStep, ...]
    vault_path: str
    same_device_restored: bool
    cross_device_refused: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict.name,
            "simulated": self.simulated,
            "steps": [step.to_dict() for step in self.steps],
            "vault_path": self.vault_path,
            "same_device_restored": self.same_device_restored,
            "cross_device_refused": self.cross_device_refused,
        }


@dataclass(frozen=True, slots=True)
class DrillInputs:
    partition: str
    asset_path: Path
    asset_sha256: str
    device: VaultDevice
    other_device: VaultDevice
    vault_path: Path
    staging_dir: Path
    passphrase: str
    journal_path: Path
    last_resort_path: str


def run_drill(inputs: DrillInputs, transport: WriteTransport, *, now: datetime) -> DrillReport:
    if now.tzinfo is None:
        raise DrillError("drill time must be timezone-aware")
    steps: list[DrillStep] = []

    # 1. SR-008: hash-verify the recovery assets.
    verdicts = verify_assets({inputs.partition: (inputs.asset_path, inputs.asset_sha256)})
    asset_state = verdicts[0].state
    steps.append(DrillStep("asset-verification", asset_state, verdicts[0].detail))
    if not inputs.last_resort_path.strip():
        steps.append(
            DrillStep(
                "last-resort-path",
                Tri.UNKNOWN,
                "no last-resort recovery path was stated; the drill cannot pass",
            )
        )
        return _report(steps, inputs, restored=False, refused=False)
    steps.append(
        DrillStep(
            "last-resort-path",
            Tri.TRUE,
            f"last-resort path stated: {inputs.last_resort_path}",
        )
    )

    # 2. SR-009: back the partition image up into an encrypted, device-bound vault.
    try:
        plaintext = inputs.asset_path.read_bytes()
    except OSError as exc:
        steps.append(DrillStep("vault-backup", Tri.UNKNOWN, f"cannot read asset: {exc}"))
        return _report(steps, inputs, restored=False, refused=False)
    vault = create_vault(
        device=inputs.device,
        entries={inputs.partition: plaintext},
        passphrase=inputs.passphrase,
        now=now,
    )
    save_vault(inputs.vault_path, vault, passphrase=inputs.passphrase)
    steps.append(
        DrillStep(
            "vault-backup",
            Tri.TRUE,
            f"partition {inputs.partition!r} encrypted and bound to device "
            f"{inputs.device.product} (serial hash {inputs.device.serial_sha256[:12]}…)",
        )
    )

    # 3. Integrity: reload and decrypt.
    try:
        reloaded = load_vault(inputs.vault_path, passphrase=inputs.passphrase)
        restored_bytes = decrypt_entry(reloaded, inputs.partition, passphrase=inputs.passphrase)
    except (VaultError, VaultTamperedError) as exc:
        steps.append(DrillStep("vault-integrity", Tri.FALSE, str(exc)))
        return _report(steps, inputs, restored=False, refused=False)
    if hashlib.sha256(restored_bytes).hexdigest() != hashlib.sha256(plaintext).hexdigest():
        steps.append(
            DrillStep("vault-integrity", Tri.FALSE, "decrypted bytes differ from the asset")
        )
        return _report(steps, inputs, restored=False, refused=False)
    steps.append(
        DrillStep("vault-integrity", Tri.TRUE, "vault reloaded, MAC verified, plaintext matches")
    )

    # 4. Cross-device restore must be refused before any write.
    try:
        other_vault = load_vault(inputs.vault_path, passphrase=inputs.passphrase)
        restore_check(other_vault, inputs.other_device)
    except VaultDeviceMismatch as exc:
        steps.append(DrillStep("cross-device-refusal", Tri.TRUE, str(exc)))
        refused = True
    except VaultError as exc:
        steps.append(DrillStep("cross-device-refusal", Tri.UNKNOWN, str(exc)))
        return _report(steps, inputs, restored=False, refused=False)
    else:
        steps.append(
            DrillStep(
                "cross-device-refusal",
                Tri.FALSE,
                "a vault restore against a different device was NOT refused",
            )
        )
        return _report(steps, inputs, restored=False, refused=False)

    # 5. Same-device restore through the journaled, simulator-only write.
    try:
        restore_check(reloaded, inputs.device)
    except VaultDeviceMismatch as exc:
        steps.append(DrillStep("same-device-restore", Tri.FALSE, str(exc)))
        return _report(steps, inputs, restored=False, refused=refused)

    journal = _open_journal(inputs.journal_path, inputs)
    step = PlanStep(
        number=1,
        action=PlanAction.FLASH,
        source_line=0,
        partition=inputs.partition,
        image=inputs.partition,
    )
    journal.append(JournalKind.STEP_STARTED, {"number": 1, "partition": inputs.partition})
    try:
        inputs.staging_dir.mkdir(parents=True, exist_ok=True)
        staged = inputs.staging_dir / f"drill-{inputs.partition}.img"
        staged.write_bytes(restored_bytes)
        result = transport.run_write(step, image_path=staged, timeout_s=60.0)
    except (ToolError, OSError) as exc:
        journal.append(JournalKind.STEP_FAILED, {"number": 1, "detail": str(exc)})
        steps.append(DrillStep("same-device-restore", Tri.FALSE, f"restore write failed: {exc}"))
        return _report(steps, inputs, restored=False, refused=refused)
    if getattr(result, "ok", False):
        journal.append(JournalKind.STEP_DONE, {"number": 1})
        journal.append(JournalKind.COMPLETED, {"steps_done": 1, "steps_total": 1})
        steps.append(
            DrillStep(
                "same-device-restore",
                Tri.TRUE,
                f"partition {inputs.partition!r} restored to the same device in the "
                "simulator, journaled",
            )
        )
        restored = True
    else:
        journal.append(
            JournalKind.STEP_FAILED,
            {"number": 1, "exit_code": getattr(result, "exit_code", -1)},
        )
        steps.append(
            DrillStep(
                "same-device-restore",
                Tri.FALSE,
                "restore write reported failure; stop-and-reprobe",
            )
        )
        restored = False

    return _report(steps, inputs, restored=restored, refused=refused)


def _open_journal(path: Path, inputs: DrillInputs) -> Journal:
    payload: dict[str, object] = {
        "journal_kind": "cairn.recovery-drill",
        "schema_version": 1,
        "partition": inputs.partition,
        "simulated": True,
    }
    if path.exists():
        return Journal.resume(path)
    return Journal.create(path, payload)


def _report(
    steps: list[DrillStep],
    inputs: DrillInputs,
    *,
    restored: bool,
    refused: bool,
) -> DrillReport:
    states = [step.state for step in steps]
    if Tri.FALSE in states or not restored or not refused:
        verdict = Tri.FALSE
    elif Tri.UNKNOWN in states:
        verdict = Tri.UNKNOWN
    else:
        verdict = Tri.TRUE
    return DrillReport(
        verdict=verdict,
        simulated=True,
        steps=tuple(steps),
        vault_path=str(inputs.vault_path),
        same_device_restored=restored,
        cross_device_refused=refused,
    )


__all__ = [
    "AssetVerdict",
    "DrillError",
    "DrillInputs",
    "DrillReport",
    "DrillStep",
    "Vault",
    "VaultDevice",
    "run_drill",
    "verify_assets",
]
