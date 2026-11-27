"""Virtual A/B merge-state reading and classification (SR-010)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from cairn.adapters.fastboot import FastbootClient
from cairn.core.errors import CairnError
from cairn.core.tristate import Tri

# Observed AOSP fastbootd values ([AOSP-FASTBOOTD], scrubbed fixture
# tests/fixtures/fastboot/pixel8_getvar_all.json). KU-004 keeps vendor
# variants open; anything unrecognized is UNKNOWN, never a guess.
_NONE_STATES: Final[frozenset[str]] = frozenset({"none"})
# merge_pending is not in the observed set but SAFETY_RULES SR-010 names it
# FALSE explicitly; a device reporting it is mid-merge and must block.
_BLOCKING_STATES: Final[frozenset[str]] = frozenset({"snapshotted", "merging", "merge_pending"})

_GETVAR_NAME: Final = "snapshot-update-status"


class MergeStateError(CairnError):
    code = "MERGE_STATE_ERROR"


@dataclass(frozen=True, slots=True)
class MergeStateRead:
    """A tri-state read of one device's ``snapshot-update-status``."""

    value: str | None
    state: Tri
    detail: str
    simulated: bool = False
    warnings: tuple[str, ...] = field(default=())

    def to_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "state": self.state.name,
            "detail": self.detail,
            "simulated": self.simulated,
            "warnings": list(self.warnings),
        }


def classify_snapshot_status(value: str | None, *, simulated: bool = False) -> MergeStateRead:
    """Classify one reported ``snapshot-update-status`` value.

    ``none`` is the only safe state for a normal flash job. The mid-merge
    states are FALSE and block with no override. Anything else — an
    unrecognized vendor string, a FAIL line, or no value at all — is UNKNOWN
    and blocks the same way (SAFETY_RULES SR-010, [AOSP-FASTBOOTD]).
    """
    if value is None:
        return MergeStateRead(
            value=None,
            state=Tri.UNKNOWN,
            detail="snapshot-update-status was not reported; the merge state is unknown",
            simulated=simulated,
            warnings=("the device did not report snapshot-update-status",),
        )
    normalized = value.strip().lower()
    if normalized in _NONE_STATES:
        return MergeStateRead(
            value=normalized,
            state=Tri.TRUE,
            detail="snapshot-update-status is none; no merge is pending",
            simulated=simulated,
        )
    if normalized in _BLOCKING_STATES:
        return MergeStateRead(
            value=normalized,
            state=Tri.FALSE,
            detail=(
                f"snapshot-update-status is {normalized!r}; a flash during an "
                "unfinished merge can leave the device unbootable and is never "
                "overridable"
            ),
            simulated=simulated,
            warnings=("cairn never auto-cancels a merge; cancel can require a reflash",),
        )
    return MergeStateRead(
        value=value,
        state=Tri.UNKNOWN,
        detail=(
            f"unrecognized snapshot-update-status {value!r}; vendor-specific merge state (KU-004)"
        ),
        simulated=simulated,
        warnings=("treat the value as UNKNOWN until a source describes it",),
    )


def read_merge_state(
    client: FastbootClient,
    *,
    serial: str | None = None,
    simulated: bool = False,
) -> MergeStateRead:
    """Run one read-only ``getvar snapshot-update-status`` and classify it."""
    result = client.getvar(_GETVAR_NAME, serial=serial)
    if not result.ok:
        return MergeStateRead(
            value=None,
            state=Tri.UNKNOWN,
            detail=(f"getvar {_GETVAR_NAME} failed: {result.stderr.strip() or 'no stderr'}"),
            simulated=simulated,
            warnings=("a FAIL on this variable is UNKNOWN, per SAFETY_RULES SR-010",),
        )
    value = _value_from_output(result.combined_output)
    return classify_snapshot_status(value, simulated=simulated)


def _value_from_output(output: str) -> str | None:
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("(bootloader) "):
            line = line[len("(bootloader) ") :]
        name, sep, value = line.partition(":")
        if not sep:
            continue
        if name.strip() == _GETVAR_NAME:
            value = value.strip()
            return value or None
    return None
