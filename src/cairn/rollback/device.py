"""Read vendor-reported stored rollback indexes from ``fastboot getvar all``.

AOSP ``external/avb`` says the device keeps ``stored_rollback_index[n]`` in
tamper-evident storage and that the value can differ between A/B slots. AOSP
fastboot does not define a standard getvar for that value, so this reader only
accepts the vendor-specific forms that have been observed in the field:

* ``stored_rollback_index:<location> = <value>``
* ``avb_stored_rollback_indexes:<location>:<value>``

The parser is deliberately narrow. It never maps an OEM anti-rollback signal
(for example ``ap-ar-s``) to an AVB location, because that mapping is unknown
(KU-005, KU-030). Missing, malformed, conflicting, or truncated values are
unresolved, not a pass. A successful read is a device claim, not AVB verification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Final

from cairn.adapters.fastboot import FastbootClient
from cairn.core.tristate import Tri
from cairn.rollback.oracle import MAX_ROLLBACK_INDEX
from cairn.tools.runner import ToolResult

_GETVAR_PREFIX: Final = "(bootloader) "
_STORED_PREFIX: Final = "stored_rollback_index"
_AVB_PREFIX: Final = "avb_stored_rollback_indexes"
_MAX_LOCATION: Final = (1 << 32) - 1

_STORED_RE: Final = re.compile(
    rf"^{_STORED_PREFIX}\s*:\s*(?P<location>[^:=\s]+)\s*(?:=|:)\s*(?P<value>.*)$",
    re.IGNORECASE,
)
_AVB_RE: Final = re.compile(
    rf"^{_AVB_PREFIX}\s*:\s*(?P<location>[^:=\s]+)\s*(?:=|:)\s*(?P<value>.*)$",
    re.IGNORECASE,
)
_DECIMAL_RE: Final = re.compile(r"[0-9]+")
_HEX_PREFIX_RE: Final = re.compile(r"0[xX][0-9a-fA-F]+")
_BARE_HEX_RE: Final = re.compile(r"[0-9a-fA-F]+")
_HEX_LETTERS: Final = frozenset("abcdefABCDEF")

_OEM_NAMES: Final[frozenset[str]] = frozenset(
    {
        "ap-ar-s",
        "anti-rollback",
        "anti_rollback",
        "antirollback",
        "arb",
        "swrev",
        "binary-version",
        "binary_version",
        "oem-anti-rollback",
    }
)


@dataclass(frozen=True, slots=True)
class StoredRollbackIndex:
    """One stored rollback index reported by a device."""

    location: int
    value: int
    variable: str
    raw_value: str
    source: str = "fastboot getvar all"
    slot: str | None = None

    def __post_init__(self) -> None:
        if self.location < 0 or self.location > _MAX_LOCATION:
            raise ValueError("stored rollback location is outside the 32-bit range")
        if self.value < 0 or self.value > MAX_ROLLBACK_INDEX:
            raise ValueError("stored rollback value is outside the 64-bit range")
        if not self.variable.strip():
            raise ValueError("stored rollback variable must not be empty")
        if not self.raw_value.strip():
            raise ValueError("stored rollback raw value must not be empty")
        if not self.source.strip():
            raise ValueError("stored rollback source must not be empty")
        if self.slot is not None and not self.slot.strip():
            raise ValueError("stored rollback slot must not be empty")

    def to_dict(self) -> dict[str, object]:
        return {
            "location": self.location,
            "value": self.value,
            "variable": self.variable,
            "raw_value": self.raw_value,
            "source": self.source,
            "slot": self.slot,
        }


@dataclass(frozen=True, slots=True)
class OemAntiRollbackSignal:
    """An OEM counter that must not be treated as an AVB stored index."""

    name: str
    value: str
    source: str = "fastboot getvar all"
    detail: str = "OEM anti-rollback signal; its AVB rollback location mapping is unknown"

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("OEM anti-rollback signal name must not be empty")
        if not self.source.strip():
            raise ValueError("OEM anti-rollback signal source must not be empty")
        if not self.detail.strip():
            raise ValueError("OEM anti-rollback signal detail must not be empty")

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "value": self.value,
            "source": self.source,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class DeviceRollbackRead:
    """The parsed stored indexes plus everything that could not be read."""

    indexes: tuple[StoredRollbackIndex, ...] = ()
    unresolved: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    oem_signals: tuple[OemAntiRollbackSignal, ...] = ()
    serial: str | None = None
    slot: str | None = None
    tool_ok: bool = True
    detail: str = ""

    @property
    def state(self) -> Tri:
        """Whether the read is complete enough to use, not a safety verdict."""
        if self.tool_ok and self.indexes and not self.unresolved:
            return Tri.TRUE
        return Tri.UNKNOWN

    @property
    def stored(self) -> dict[int, int]:
        """The location-to-value mapping the Rollback Oracle consumes."""
        return {index.location: index.value for index in self.indexes}

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.name,
            "tool_ok": self.tool_ok,
            "detail": self.detail,
            "serial": self.serial,
            "slot": self.slot,
            "indexes": [index.to_dict() for index in self.indexes],
            "unresolved": list(self.unresolved),
            "warnings": list(self.warnings),
            "oem_signals": [signal.to_dict() for signal in self.oem_signals],
        }


def parse_stored_rollback_indexes(
    text: str,
    *,
    slot: str | None = None,
) -> DeviceRollbackRead:
    """Parse stored rollback indexes from raw ``getvar all`` output.

    Duplicate identical values for one location are accepted once. Conflicting
    values make that location unresolved. Any malformed or empty rollback line is
    unresolved, and no rollback line at all is unresolved because AOSP fastboot
    has no standard variable for this value.
    """
    candidates: dict[int, list[StoredRollbackIndex]] = {}
    unresolved: list[str] = []
    warnings: list[str] = []
    oem_signals: list[OemAntiRollbackSignal] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line.startswith(_GETVAR_PREFIX):
            continue
        payload = line[len(_GETVAR_PREFIX) :].strip()
        if not payload:
            continue
        lowered = payload.lower()

        if lowered.startswith(_AVB_PREFIX):
            match = _AVB_RE.fullmatch(payload)
            if match is None:
                unresolved.append(
                    _unresolved_line(
                        line_number,
                        payload,
                        "malformed avb_stored_rollback_indexes line",
                    )
                )
                continue
            _record_candidate(
                candidates,
                unresolved,
                line_number=line_number,
                payload=payload,
                match=match,
                variable=_AVB_PREFIX,
                slot=slot,
            )
            continue

        if lowered.startswith(_STORED_PREFIX):
            match = _STORED_RE.fullmatch(payload)
            if match is None:
                unresolved.append(
                    _unresolved_line(
                        line_number,
                        payload,
                        "malformed stored_rollback_index line",
                    )
                )
                continue
            _record_candidate(
                candidates,
                unresolved,
                line_number=line_number,
                payload=payload,
                match=match,
                variable=_STORED_PREFIX,
                slot=slot,
            )
            continue

        signal = _parse_oem_signal(payload)
        if signal is not None:
            oem_signals.append(signal)
            warnings.append(
                f"OEM anti-rollback signal {signal.name}={signal.value!r} is not an "
                "AVB stored rollback index; its AVB location mapping is unknown"
            )

    indexes: list[StoredRollbackIndex] = []
    for location in sorted(candidates):
        values = {candidate.value for candidate in candidates[location]}
        if len(values) > 1:
            rendered = ", ".join(str(value) for value in sorted(values))
            unresolved.append(
                f"conflicting stored rollback indexes for location {location}: {rendered}"
            )
            continue
        indexes.append(candidates[location][0])

    if not indexes and not unresolved:
        if oem_signals:
            unresolved.append(
                "no AVB stored rollback index variable was reported; OEM anti-rollback "
                "signals cannot be mapped to AVB locations"
            )
        else:
            unresolved.append(
                "no stored rollback index variable was reported; AOSP fastboot does not define one"
            )

    return DeviceRollbackRead(
        indexes=tuple(indexes),
        unresolved=tuple(unresolved),
        warnings=tuple(warnings),
        oem_signals=tuple(oem_signals),
        slot=slot,
    )


def read_stored_rollback_indexes(
    client: FastbootClient,
    *,
    serial: str | None = None,
    slot: str | None = None,
) -> DeviceRollbackRead:
    """Run one read-only ``getvar all`` and parse the stored indexes.

    A failed or truncated command produces no trusted indexes. A successful
    command with no vendor variable still produces no indexes, because AOSP
    fastboot does not guarantee a portable way to read this value.
    """
    result = client.getvar_all(serial=serial)
    detail = _describe_result(result)
    if not result.ok:
        return DeviceRollbackRead(
            serial=serial,
            slot=slot,
            tool_ok=False,
            detail=detail,
            unresolved=(f"{detail}; stored rollback indexes were not read",),
        )
    if result.stdout_truncated or result.stderr_truncated:
        return DeviceRollbackRead(
            serial=serial,
            slot=slot,
            tool_ok=True,
            detail=detail,
            unresolved=(f"{detail}; stored rollback indexes are incomplete",),
        )

    parsed = parse_stored_rollback_indexes(result.combined_output, slot=slot)
    return replace(parsed, serial=serial, detail=detail)


def _record_candidate(
    candidates: dict[int, list[StoredRollbackIndex]],
    unresolved: list[str],
    *,
    line_number: int,
    payload: str,
    match: re.Match[str],
    variable: str,
    slot: str | None,
) -> None:
    location_text = match.group("location").strip()
    value_text = match.group("value").strip()
    location = _parse_location(location_text)
    if location is None:
        unresolved.append(
            _unresolved_line(line_number, payload, f"invalid rollback location {location_text!r}")
        )
        return
    if not value_text:
        unresolved.append(
            _unresolved_line(line_number, payload, f"rollback location {location} has no value")
        )
        return
    value = _parse_value(value_text)
    if value is None:
        unresolved.append(
            _unresolved_line(
                line_number,
                payload,
                f"invalid rollback value {value_text!r} for location {location}",
            )
        )
        return

    candidate = StoredRollbackIndex(
        location=location,
        value=value,
        variable=variable,
        raw_value=value_text,
        slot=slot,
    )
    candidates.setdefault(location, []).append(candidate)


def _parse_location(text: str) -> int | None:
    value = _parse_unsigned(text, allow_bare_hex=False)
    if value is None or value > _MAX_LOCATION:
        return None
    return value


def _parse_value(text: str) -> int | None:
    value = _parse_unsigned(text, allow_bare_hex=True)
    if value is None or value > MAX_ROLLBACK_INDEX:
        return None
    return value


def _parse_unsigned(text: str, *, allow_bare_hex: bool) -> int | None:
    if _DECIMAL_RE.fullmatch(text):
        return int(text, 10)
    if _HEX_PREFIX_RE.fullmatch(text):
        return int(text, 16)
    if (
        allow_bare_hex
        and _BARE_HEX_RE.fullmatch(text)
        and any(character in _HEX_LETTERS for character in text)
    ):
        return int(text, 16)
    return None


def _parse_oem_signal(payload: str) -> OemAntiRollbackSignal | None:
    name, separator, value = payload.partition(":")
    if not separator:
        name, separator, value = payload.partition("=")
    if not separator:
        return None
    normalized = name.strip().lower()
    if normalized not in _OEM_NAMES:
        return None
    return OemAntiRollbackSignal(name=normalized, value=value.strip())


def _unresolved_line(line_number: int, payload: str, reason: str) -> str:
    return f"line {line_number}: {reason}: {_short(payload)!r}"


def _short(text: str, limit: int = 120) -> str:
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


def _describe_result(result: ToolResult) -> str:
    if result.cancelled:
        return "fastboot was cancelled"
    if result.timed_out:
        return "fastboot timed out"
    if result.exit_code != 0:
        lines = result.stderr.strip().splitlines()
        tail = lines[-1] if lines else ""
        return f"fastboot exited {result.exit_code}" + (f": {tail}" if tail else "")
    if result.stdout_truncated or result.stderr_truncated:
        return "fastboot output was truncated; stored index read is incomplete"
    return "getvar all completed"
