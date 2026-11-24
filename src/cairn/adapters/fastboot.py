"""Read-only fastboot probing and parsing.

The adapter never writes. It runs pinned host tools through ``ToolRunner`` and
turns raw ``getvar all`` output into evidence. Missing variables, tool failures,
and unknown values become UNKNOWN, never a silent pass.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from cairn.core.errors import ConfigurationError
from cairn.core.evidence import Evidence, EvidenceSource
from cairn.core.tristate import Tri
from cairn.tools.runner import ToolResult, ToolRunner

GETVAR_TIMEOUT_S: Final = 30.0
PROBE_MAX_AGE: Final = timedelta(minutes=10)
_GETVAR_PREFIX: Final = "(bootloader) "
_PARAMETERIZED_VARS: Final[frozenset[str]] = frozenset(
    {
        "partition-size",
        "partition-type",
        "has-slot",
        "is-logical",
        "slot-successful",
        "slot-unbootable",
        "slot-retry-count",
    }
)
_SLOT_SIGNAL_RE: Final = re.compile(
    r"^(slot-successful|slot-unbootable|slot-retry-count|has-slot|partition-size"
    r"|partition-type|is-logical):(?P<arg>[^:]+)$"
)

IDENTITY_VARS: Final[tuple[str, ...]] = (
    "product",
    "variant",
    "serialno",
    "hw-revision",
    "version-bootloader",
    "version-baseband",
    "system-fingerprint",
    "vendor-fingerprint",
    "security-patch-level",
    "first-api-level",
)
STATE_VARS: Final[tuple[str, ...]] = (
    "version",
    "unlocked",
    "secure",
    "current-slot",
    "slot-count",
    "is-userspace",
    "max-download-size",
    "max-fetch-size",
    "super-partition-name",
    "snapshot-update-status",
    "dynamic-partition",
    "treble-enabled",
    "battery-voltage",
    "battery-soc",
    "battery-soc-ok",
)
PROBE_VARS: Final[tuple[str, ...]] = IDENTITY_VARS + STATE_VARS

_YES_NO: Final[Mapping[str, Tri]] = {"yes": Tri.TRUE, "no": Tri.FALSE}
_BOOLEAN: Final[Mapping[str, Tri]] = {
    "yes": Tri.TRUE,
    "no": Tri.FALSE,
    "true": Tri.TRUE,
    "false": Tri.FALSE,
}
_KNOWN_SNAPSHOT_STATES: Final[frozenset[str]] = frozenset({"none", "snapshotted", "merging"})


@dataclass(frozen=True, slots=True)
class ProbedFact:
    name: str
    evidence: Evidence[str]


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Read-only probe outcome: facts plus tool status, never a safety verdict."""

    serial: str | None
    facts: tuple[ProbedFact, ...]
    tool_ok: bool
    exit_code: int
    stderr: str
    timed_out: bool
    cancelled: bool
    detail: str

    def fact(self, name: str) -> ProbedFact | None:
        for item in self.facts:
            if item.name == name:
                return item
        return None


class FastbootClient:
    """Minimal fastboot CLI adapter limited to read-only verbs."""

    def __init__(
        self,
        argv_prefix: Sequence[str],
        *,
        runner: ToolRunner | None = None,
        timeout_s: float = GETVAR_TIMEOUT_S,
        extra_env: Mapping[str, str] | None = None,
    ) -> None:
        if not argv_prefix:
            raise ConfigurationError("fastboot argv prefix must not be empty")
        self._prefix = tuple(argv_prefix)
        self._runner = runner if runner is not None else ToolRunner()
        self._timeout_s = timeout_s
        self._extra_env = dict(extra_env) if extra_env is not None else None

    @property
    def argv_prefix(self) -> tuple[str, ...]:
        return self._prefix

    def _argv(self, args: Sequence[str], *, serial: str | None) -> tuple[str, ...]:
        argv = list(self._prefix)
        if serial is not None:
            argv.extend(("-s", serial))
        argv.extend(args)
        return tuple(argv)

    def getvar_all(self, *, serial: str | None = None) -> ToolResult:
        return self._runner.run(
            self._argv(("getvar", "all"), serial=serial),
            timeout_s=self._timeout_s,
            extra_env=self._extra_env,
        )

    def getvar(self, name: str, *, serial: str | None = None) -> ToolResult:
        if not name or name == "all":
            raise ConfigurationError(f"invalid getvar name {name!r}")
        return self._runner.run(
            self._argv(("getvar", name), serial=serial),
            timeout_s=self._timeout_s,
            extra_env=self._extra_env,
        )

    def probe(
        self,
        *,
        serial: str | None = None,
        expected_serial: str | None = None,
        source: EvidenceSource = EvidenceSource.PROBED,
        now: datetime | None = None,
        max_age: timedelta | None = PROBE_MAX_AGE,
    ) -> ProbeResult:
        observed_at = now if now is not None else datetime.now(UTC)
        result = self.getvar_all(serial=serial)
        facts = parse_getvar_output(f"{result.stdout}\n{result.stderr}")
        tool_ok = result.ok
        detail = _result_detail(result)

        probed: list[ProbedFact] = []
        for name in PROBE_VARS:
            value = facts.get(name)
            probed.append(
                _classify(
                    name,
                    value,
                    tool_ok=tool_ok,
                    observed_at=observed_at,
                    source=source,
                    max_age=max_age,
                    failure=detail,
                )
            )

        if expected_serial is not None:
            probed.append(
                _serial_fact(
                    facts.get("serialno"),
                    expected_serial,
                    tool_ok=tool_ok,
                    observed_at=observed_at,
                    source=source,
                    max_age=max_age,
                    failure=detail,
                )
            )

        for name, value in facts.items():
            if _SLOT_SIGNAL_RE.match(name) is not None:
                probed.append(
                    ProbedFact(
                        name=name,
                        evidence=_evidence(
                            Tri.UNKNOWN,
                            value=value,
                            observed_at=observed_at,
                            source=source,
                            max_age=max_age,
                            detail=(
                                "raw value recorded; AOSP fastbootd slot signals are "
                                "inverted or implementation-specific and unconfirmed"
                            ),
                        ),
                    )
                )

        probed.sort(key=lambda item: item.name)
        return ProbeResult(
            serial=serial,
            facts=tuple(probed),
            tool_ok=tool_ok,
            exit_code=result.exit_code,
            stderr=result.stderr,
            timed_out=result.timed_out,
            cancelled=result.cancelled,
            detail=detail,
        )


def parse_getvar_output(text: str) -> dict[str, str]:
    """Parse ``(bootloader) name:value`` lines from stdout or stderr.

    Parameterized variables such as ``partition-size:boot_a:0x1000`` keep the full
    variable name. The first occurrence wins: the host emits each variable once per
    ``getvar all``, and a duplicate is more likely corruption than intent.
    """
    facts: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip("\r")
        if not line.startswith(_GETVAR_PREFIX):
            continue
        payload = line[len(_GETVAR_PREFIX) :]
        parsed = _split_payload(payload)
        if parsed is None:
            continue
        name, value = parsed
        if not name:
            continue
        facts.setdefault(name, value)
    return facts


def _split_payload(payload: str) -> tuple[str, str] | None:
    head, separator, rest = payload.partition(":")
    if not separator:
        return None
    head = head.strip()
    if head in _PARAMETERIZED_VARS:
        argument, second, value = rest.partition(":")
        if not second:
            return None
        return f"{head}:{argument.strip()}", value.strip()
    return head, rest.strip()


def _result_detail(result: ToolResult) -> str:
    if result.cancelled:
        return "fastboot was cancelled"
    if result.timed_out:
        return "fastboot timed out"
    if result.exit_code != 0:
        stderr_tail = result.stderr.strip().splitlines()
        tail = stderr_tail[-1] if stderr_tail else ""
        return f"fastboot exited {result.exit_code}" + (f": {tail}" if tail else "")
    if result.stdout_truncated or result.stderr_truncated:
        return "fastboot output was truncated; probe is incomplete"
    return "getvar all completed"


def _evidence(
    state: Tri,
    *,
    value: str | None = None,
    observed_at: datetime,
    source: EvidenceSource,
    max_age: timedelta | None,
    detail: str,
) -> Evidence[str]:
    return Evidence(
        state=state,
        source=source,
        observed_at=observed_at,
        value=value,
        max_age=max_age,
        detail=detail,
    )


def _classify(
    name: str,
    value: str | None,
    *,
    tool_ok: bool,
    observed_at: datetime,
    source: EvidenceSource,
    max_age: timedelta | None,
    failure: str,
) -> ProbedFact:
    if not tool_ok:
        return ProbedFact(
            name,
            _evidence(
                Tri.UNKNOWN,
                value=value,
                observed_at=observed_at,
                source=source,
                max_age=max_age,
                detail=f"{failure}; value not trusted",
            ),
        )

    if value is None:
        return ProbedFact(
            name,
            _evidence(
                Tri.UNKNOWN,
                observed_at=observed_at,
                source=source,
                max_age=max_age,
                detail=(
                    "not reported; AOSP getvar omits unsupported variables and reports "
                    "unknown ones as FAIL lines"
                ),
            ),
        )

    state = Tri.TRUE
    detail = "reported by getvar all"

    if name in ("unlocked", "secure", "is-userspace", "dynamic-partition", "treble-enabled"):
        state = _BOOLEAN.get(value.lower(), Tri.UNKNOWN)
        if state is Tri.UNKNOWN:
            detail = f"unrecognized boolean value {value!r}"
    elif name == "battery-soc-ok":
        state = _YES_NO.get(value.lower(), Tri.UNKNOWN)
        if state is Tri.UNKNOWN:
            detail = f"unrecognized yes/no value {value!r}"
        else:
            detail = "voltage compared with the HAL flashing threshold, not state of charge"
    elif name == "snapshot-update-status":
        if value not in _KNOWN_SNAPSHOT_STATES:
            state = Tri.UNKNOWN
            detail = f"unrecognized snapshot status {value!r}; vendor-specific state"
    elif name == "max-download-size":
        parsed_size = _parse_size(value)
        if parsed_size is None:
            state = Tri.UNKNOWN
            detail = f"unparseable size {value!r}"
        elif parsed_size == 0:
            state = Tri.FALSE
            detail = "zero maximum download size"
        else:
            detail = f"device accepts downloads up to {parsed_size} bytes"
    elif name == "max-fetch-size":
        parsed_fetch = _parse_size(value)
        if value.lower() in ("fetch not supported", "not supported"):
            state = Tri.FALSE
            detail = "device does not support fetch"
        elif parsed_fetch is None:
            state = Tri.UNKNOWN
            detail = f"unparseable size {value!r}"
        elif parsed_fetch == 0:
            state = Tri.FALSE
            detail = "fetch is disabled"
        else:
            detail = f"device fetches up to {parsed_fetch} bytes"
    elif name == "slot-count":
        if not _is_positive_int(value):
            state = Tri.UNKNOWN
            detail = f"unparseable slot count {value!r}"
    elif name in ("battery-voltage", "battery-soc"):
        if not _is_non_negative_int(value):
            state = Tri.UNKNOWN
            detail = f"unparseable numeric value {value!r}"
    elif name == "current-slot" and value == "":
        state = Tri.UNKNOWN
        detail = "empty current slot"

    return ProbedFact(
        name,
        _evidence(
            state,
            value=value,
            observed_at=observed_at,
            source=source,
            max_age=max_age,
            detail=detail,
        ),
    )


def _serial_fact(
    observed: str | None,
    expected: str,
    *,
    tool_ok: bool,
    observed_at: datetime,
    source: EvidenceSource,
    max_age: timedelta | None,
    failure: str,
) -> ProbedFact:
    if not tool_ok:
        state = Tri.UNKNOWN
        detail = f"{failure}; serial not trusted"
    elif observed is None:
        state = Tri.UNKNOWN
        detail = "device did not report serialno"
    elif observed != expected:
        state = Tri.FALSE
        detail = f"serial mismatch: expected {expected!r}, device reported {observed!r}"
    else:
        state = Tri.TRUE
        detail = "serial matched the requested device"
    return ProbedFact(
        "serial-match",
        _evidence(
            state,
            value=observed,
            observed_at=observed_at,
            source=source,
            max_age=max_age,
            detail=detail,
        ),
    )


def _parse_size(text: str) -> int | None:
    value = text.strip()
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value, 10)
    except ValueError:
        return None


def _is_positive_int(text: str) -> bool:
    try:
        return int(text, 10) > 0
    except ValueError:
        return False


def _is_non_negative_int(text: str) -> bool:
    try:
        return int(text, 10) >= 0
    except ValueError:
        return False
