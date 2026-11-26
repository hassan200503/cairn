from __future__ import annotations

from cairn.core.tristate import Tri
from cairn.rollback.device import (
    parse_stored_rollback_indexes,
    read_stored_rollback_indexes,
)
from cairn.tools.runner import ToolResult


class _FakeFastboot:
    def __init__(self, result: ToolResult) -> None:
        self._result = result
        self.serial: str | None = None

    def getvar_all(self, *, serial: str | None = None) -> ToolResult:
        self.serial = serial
        return self._result


def _result(
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    stdout_truncated: bool = False,
    stderr_truncated: bool = False,
) -> ToolResult:
    return ToolResult(
        argv=("fastboot", "getvar", "all"),
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_s=0.01,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
    )


def test_parse_stored_rollback_index_with_spaces_and_decimal() -> None:
    read = parse_stored_rollback_indexes("(bootloader) stored_rollback_index:5 = 0\n")

    assert read.state is Tri.TRUE
    assert read.stored == {5: 0}
    assert read.indexes[0].variable == "stored_rollback_index"
    assert read.indexes[0].raw_value == "0"
    assert read.unresolved == ()


def test_parse_stored_rollback_index_accepts_hex() -> None:
    read = parse_stored_rollback_indexes(
        "(bootloader) stored_rollback_index:3 = 66D8F480\n"
        "(bootloader) stored_rollback_index:4 = 0x10\n"
    )

    assert read.stored == {3: int("66D8F480", 16), 4: 16}
    assert read.state is Tri.TRUE


def test_parse_avb_stored_rollback_indexes() -> None:
    read = parse_stored_rollback_indexes("(bootloader) avb_stored_rollback_indexes:0:1577836800\n")

    assert read.stored == {0: 1577836800}
    assert read.indexes[0].variable == "avb_stored_rollback_indexes"
    assert read.state is Tri.TRUE


def test_empty_avb_stored_rollback_indexes_is_unresolved() -> None:
    read = parse_stored_rollback_indexes("(bootloader) avb_stored_rollback_indexes:\n")

    assert read.indexes == ()
    assert read.state is Tri.UNKNOWN
    assert any("malformed avb_stored_rollback_indexes" in item for item in read.unresolved)


def test_malformed_stored_line_is_unresolved() -> None:
    read = parse_stored_rollback_indexes("(bootloader) stored_rollback_index:oops = 1\n")

    assert read.indexes == ()
    assert read.state is Tri.UNKNOWN
    assert any("invalid rollback location" in item for item in read.unresolved)


def test_out_of_range_value_is_unresolved() -> None:
    read = parse_stored_rollback_indexes(
        "(bootloader) stored_rollback_index:0 = 0x10000000000000000\n"
    )

    assert read.indexes == ()
    assert read.state is Tri.UNKNOWN
    assert any("invalid rollback value" in item for item in read.unresolved)


def test_negative_value_is_unresolved() -> None:
    read = parse_stored_rollback_indexes("(bootloader) stored_rollback_index:0 = -1\n")

    assert read.indexes == ()
    assert read.state is Tri.UNKNOWN


def test_conflicting_duplicate_locations_are_unresolved() -> None:
    read = parse_stored_rollback_indexes(
        "(bootloader) stored_rollback_index:0 = 1\n(bootloader) stored_rollback_index:0 = 2\n"
    )

    assert read.indexes == ()
    assert read.state is Tri.UNKNOWN
    assert any(
        "conflicting stored rollback indexes for location 0" in item for item in read.unresolved
    )


def test_identical_duplicate_locations_are_accepted_once() -> None:
    read = parse_stored_rollback_indexes(
        "(bootloader) stored_rollback_index:0 = 1\n(bootloader) stored_rollback_index:0 = 1\n"
    )

    assert read.stored == {0: 1}
    assert read.state is Tri.TRUE
    assert read.unresolved == ()


def test_oem_signal_is_not_an_avb_index() -> None:
    read = parse_stored_rollback_indexes("(bootloader) ap-ar-s:2\n")

    assert read.indexes == ()
    assert read.state is Tri.UNKNOWN
    assert len(read.oem_signals) == 1
    assert read.oem_signals[0].name == "ap-ar-s"
    assert read.oem_signals[0].value == "2"
    assert any("not an AVB stored rollback index" in warning for warning in read.warnings)
    assert any("cannot be mapped to AVB locations" in item for item in read.unresolved)


def test_no_variable_is_unresolved() -> None:
    read = parse_stored_rollback_indexes("(bootloader) product:shiba\n")

    assert read.indexes == ()
    assert read.state is Tri.UNKNOWN
    assert read.unresolved == (
        "no stored rollback index variable was reported; AOSP fastboot does not define one",
    )


def test_read_stored_rollback_indexes_uses_getvar_all() -> None:
    client = _FakeFastboot(_result(stderr="(bootloader) stored_rollback_index:5 = 0\n"))

    read = read_stored_rollback_indexes(client, serial="SIMIDX", slot="b")

    assert client.serial == "SIMIDX"
    assert read.serial == "SIMIDX"
    assert read.slot == "b"
    assert read.stored == {5: 0}
    assert read.detail == "getvar all completed"
    assert read.state is Tri.TRUE


def test_read_stored_rollback_indexes_fails_closed_on_tool_failure() -> None:
    client = _FakeFastboot(
        _result(exit_code=255, stderr="fastboot: error: no devices/emulators found\n")
    )

    read = read_stored_rollback_indexes(client)

    assert read.tool_ok is False
    assert read.indexes == ()
    assert read.state is Tri.UNKNOWN
    assert any("were not read" in item for item in read.unresolved)


def test_read_stored_rollback_indexes_fails_closed_on_truncated_output() -> None:
    client = _FakeFastboot(
        _result(
            stderr="(bootloader) stored_rollback_index:5 = 0\n",
            stderr_truncated=True,
        )
    )

    read = read_stored_rollback_indexes(client)

    assert read.tool_ok is True
    assert read.indexes == ()
    assert read.state is Tri.UNKNOWN
    assert any("incomplete" in item for item in read.unresolved)
