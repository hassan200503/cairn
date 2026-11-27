"""Modeled Virtual A/B snapshot flows: explicit operator-approved cancel/merge.

SAFETY_RULES SR-010 permits a merge/cancel flow only when the operator
explicitly approves it and recovery readiness is verified, because cancel
can leave the device unbootable until the dynamic partitions are reflashed
([AOSP-FASTBOOTD]). Cairn never auto-cancels: both flows demand an exact,
typed acknowledgment sentence, verified recovery assets, a stated
last-resort path, and a transcript-replay transport (ADR-027).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from cairn.adapters.fastboot import FastbootClient
from cairn.adapters.prepare import prepare_fastboot
from cairn.core.tristate import Tri
from cairn.executor.executor import SimulatedFastbootTransport
from cairn.plan.planner import PlanAction, PlanStep
from cairn.recovery.assets import verify_assets
from cairn.vab.merge_state import read_merge_state

FLOW_CANCEL: Final = "cancel"
FLOW_MERGE: Final = "merge"
_ACTIONS: Final[frozenset[str]] = frozenset({FLOW_CANCEL, FLOW_MERGE})

_CANCEL_ACKNOWLEDGMENT: Final = (
    "I understand that cancelling a Virtual A/B update can leave the device "
    "unbootable until the dynamic partitions are reflashed"
)
_MERGE_ACKNOWLEDGMENT: Final = (
    "I understand that merging a Virtual A/B update finishes the transition "
    "and that a failed merge requires the stated recovery plan"
)


def expected_acknowledgment(action: str) -> str:
    """The exact sentence the operator must type for this flow."""
    if action == FLOW_CANCEL:
        return _CANCEL_ACKNOWLEDGMENT
    if action == FLOW_MERGE:
        return _MERGE_ACKNOWLEDGMENT
    raise ValueError(f"unknown snapshot flow {action!r}")


class FlowRefused(Exception):
    code = "SNAPSHOT_FLOW_REFUSED"


@dataclass(frozen=True, slots=True)
class SnapshotFlowInputs:
    action: str
    transcript: Path
    acknowledgment: str
    recovery_asset: Path
    recovery_sha256: str
    last_resort: str

    def __post_init__(self) -> None:
        if self.action not in _ACTIONS:
            raise FlowRefused(f"unknown snapshot flow {self.action!r}")
        if not str(self.last_resort).strip():
            raise FlowRefused("a last-resort recovery path must be stated")


@dataclass(frozen=True, slots=True)
class FlowReport:
    action: str
    merge_state_seen: str | None
    simulated: bool
    acknowledgments: tuple[str, ...] = field(default=())
    exit_code: int | None = None
    ok: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "merge_state_seen": self.merge_state_seen,
            "simulated": self.simulated,
            "acknowledgments": list(self.acknowledgments),
            "exit_code": self.exit_code,
            "ok": self.ok,
        }


def run_snapshot_flow(
    client_factory: Callable[[], FastbootClient],
    inputs: SnapshotFlowInputs,
    *,
    serial: str | None = None,
) -> FlowReport:
    """Gate and run one snapshot flow against the transcript replay.

    ``client_factory`` builds a FastbootClient bound to the same transcript;
    it is called once for the merge-state read and the same transcript feeds
    the write transport.
    """
    client = client_factory()
    read = read_merge_state(client, serial=serial, simulated=True)

    # Precondition: cancel needs a snapshot or merge in progress; merge
    # needs an in-progress merge. A "none" device has nothing to act on.
    if read.value is None or read.value == "none":
        raise FlowRefused(
            f"snapshot-update-status is {read.value!r}; there is nothing to {inputs.action}"
        )
    if inputs.action == FLOW_MERGE and read.value != "merging":
        raise FlowRefused(f"merge requires snapshot-update-status 'merging', saw {read.value!r}")

    expected = expected_acknowledgment(inputs.action)
    if inputs.acknowledgment.strip() != expected:
        raise FlowRefused(
            "the acknowledgment must be typed exactly; pass it verbatim to "
            "confirm the risk has been read"
        )

    verdicts = verify_assets({"recovery": (inputs.recovery_asset, inputs.recovery_sha256)})
    bad = [v for v in verdicts if v.state is not Tri.TRUE]
    if bad:
        raise FlowRefused(
            "recovery assets are not verified; recovery readiness is required "
            f"before a snapshot flow ({bad[0].detail})"
        )

    prepared = prepare_fastboot(fastboot=None, simulate=inputs.transcript)
    transport = SimulatedFastbootTransport.from_prepared(prepared)
    step = PlanStep(
        number=1,
        action=PlanAction.SNAPSHOT_UPDATE,
        source_line=0,
        target=inputs.action,
    )
    result = transport.run_write(step, image_path=None, timeout_s=600.0)
    return FlowReport(
        action=inputs.action,
        merge_state_seen=read.value,
        simulated=True,
        acknowledgments=(expected,),
        exit_code=result.exit_code,
        ok=result.ok,
    )
