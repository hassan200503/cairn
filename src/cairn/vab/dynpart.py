"""Dynamic-partition mode gate (SR-011).

AOSP splits dynamic-partition work between fastbootd (userspace) and the
bootloader. Flashing logical partitions or updating super metadata from the
wrong mode fails or corrupts super ([AOSP-DYNPART], [AOSP-FASTBOOTD]). The
planner already refuses retrofit force mode as unmodeled, so this gate only
has to prove the observed mode matches the job's requirement.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Final

from cairn.adapters.fastboot import FastbootClient
from cairn.core.errors import CairnError
from cairn.core.tristate import Tri
from cairn.tools.runner import ToolResult

# Mode required for a job. FASTBOOTD covers update-super and logical
# partition flashes; BOOTLOADER covers ordinary (non-dynamic) partition
# flashes on either kind of device.
MODE_FASTBOOTD: Final = "fastbootd"
MODE_BOOTLOADER: Final = "bootloader"
_JOB_MODES: Final[frozenset[str]] = frozenset({MODE_FASTBOOTD, MODE_BOOTLOADER})


class DynPartError(CairnError):
    code = "DYNPART_ERROR"


@dataclass(frozen=True, slots=True)
class DynPartRead:
    """A tri-state mode check against the device's dynamic-partition facts."""

    is_userspace: bool | None
    dynamic_partition: bool | None
    super_partition_name: str | None
    state: Tri
    detail: str
    simulated: bool = False
    warnings: tuple[str, ...] = field(default=())

    def to_dict(self) -> dict[str, object]:
        return {
            "is_userspace": self.is_userspace,
            "dynamic_partition": self.dynamic_partition,
            "super_partition_name": self.super_partition_name,
            "state": self.state.name,
            "detail": self.detail,
            "simulated": self.simulated,
            "warnings": list(self.warnings),
        }


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized == "yes":
        return True
    if normalized == "no":
        return False
    return None


def classify_dynpart_mode(
    *,
    job_mode: str,
    is_userspace: bool | None,
    dynamic_partition: bool | None,
    simulated: bool = False,
) -> DynPartRead:
    """Evaluate whether the observed boot mode satisfies the job's mode.

    A fastbootd job (update-super, logical partition flash) on a dynamic
    device must run in userspace fastbootd; running it from the bootloader
    is FALSE. A bootloader flash is TRUE on either kind of device. Any
    unreadable fact leaves the gate UNKNOWN and blocking, never permissive
    (SAFETY_RULES SR-011).
    """
    if job_mode not in _JOB_MODES:
        raise DynPartError(f"unknown job mode {job_mode!r}; use fastbootd or bootloader")

    def _read(
        state: Tri,
        detail: str,
        *,
        userspace: bool | None,
        dynamic: bool | None,
        warnings: tuple[str, ...] = (),
    ) -> DynPartRead:
        return DynPartRead(
            is_userspace=userspace,
            dynamic_partition=dynamic,
            super_partition_name=None,
            state=state,
            detail=detail,
            simulated=simulated,
            warnings=warnings,
        )

    if dynamic_partition is None or is_userspace is None:
        return _read(
            Tri.UNKNOWN,
            "dynamic-partition state could not be read; the correct flash mode is unknown",
            userspace=is_userspace,
            dynamic=dynamic_partition,
        )
    if dynamic_partition is False:
        return _read(
            Tri.TRUE,
            "device is not dynamic-partitioned; the bootloader mode is valid "
            "for ordinary partition flashes",
            userspace=is_userspace,
            dynamic=dynamic_partition,
        )
    if job_mode == MODE_FASTBOOTD:
        if is_userspace:
            return _read(
                Tri.TRUE,
                "running in fastbootd (is-userspace yes); dynamic partitions are flashable",
                userspace=is_userspace,
                dynamic=dynamic_partition,
            )
        return _read(
            Tri.FALSE,
            "bootloader mode cannot flash dynamic partitions; reboot to "
            "fastbootd first ([AOSP-DYNPART])",
            userspace=is_userspace,
            dynamic=dynamic_partition,
        )
    # A bootloader-mode job on a dynamic device is suspicious: logical
    # partition images belong in fastbootd, and retrofit force is unmodeled.
    return _read(
        Tri.UNKNOWN,
        "bootloader-mode job on a dynamic-partition device; retrofit force "
        "and logical-partition targeting are not modeled here",
        userspace=is_userspace,
        dynamic=dynamic_partition,
        warnings=(
            "the planner already marks retrofit force mode not executable",
            "confirm the job targets only physical partitions before proceeding",
        ),
    )


def read_dynpart(
    client: FastbootClient,
    *,
    job_mode: str,
    serial: str | None = None,
    simulated: bool = False,
) -> DynPartRead:
    """Run three read-only getvars and evaluate the SR-011 mode gate."""
    userspace_result = client.getvar("is-userspace", serial=serial)
    dynamic_result = client.getvar("dynamic-partition", serial=serial)
    super_result = client.getvar("super-partition-name", serial=serial)

    is_userspace = _parse_bool(_value(userspace_result, "is-userspace"))
    dynamic = _parse_bool(_value(dynamic_result, "dynamic-partition"))
    super_name = _value(super_result, "super-partition-name")

    read = classify_dynpart_mode(
        job_mode=job_mode,
        is_userspace=is_userspace,
        dynamic_partition=dynamic,
        simulated=simulated,
    )
    return replace(read, super_partition_name=super_name)


def _value(result: ToolResult, name: str) -> str | None:
    if not result.ok:
        return None
    for raw_line in result.combined_output.splitlines():
        line = raw_line.strip()
        if line.startswith("(bootloader) "):
            line = line[len("(bootloader) ") :]
        reported, sep, value = line.partition(":")
        if sep and reported.strip() == name:
            value = value.strip()
            if value:
                return value
    return None
