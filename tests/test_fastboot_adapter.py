from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cairn.adapters.fastboot import (
    FastbootClient,
    ProbeResult,
    parse_getvar_output,
)
from cairn.core.errors import ConfigurationError
from cairn.core.evidence import EvidenceSource
from cairn.core.tristate import Tri
from cairn.sim.transcript import TRANSCRIPT_ENV

FIXTURE = Path(__file__).parent / "fixtures" / "fastboot" / "pixel8_getvar_all.json"
NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


def make_client(timeout_s: float = 5.0) -> FastbootClient:
    return FastbootClient(
        (sys.executable, "-m", "cairn.sim.fastboot_sim"),
        extra_env={TRANSCRIPT_ENV: str(FIXTURE)},
        timeout_s=timeout_s,
    )


def state_of(result: ProbeResult, name: str) -> Tri:
    fact = result.fact(name)
    assert fact is not None, f"missing fact {name}"
    return fact.evidence.state


def value_of(result: ProbeResult, name: str) -> str | None:
    fact = result.fact(name)
    assert fact is not None, f"missing fact {name}"
    return fact.evidence.value


def test_parse_getvar_output_handles_simple_and_parameterized_vars() -> None:
    text = (
        "(bootloader) product:shiba\n"
        "(bootloader) partition-size:boot_a:0x10000000\n"
        "(bootloader) has-slot:boot:yes\n"
        "(bootloader) partition-size:boot_a: 0x20000000\n"
        "(bootloader) serialno:SIM123\r\n"
        "INFO not a getvar line\n"
        "(bootloader) malformed-line\n"
    )
    facts = parse_getvar_output(text)
    assert facts["product"] == "shiba"
    assert facts["partition-size:boot_a"] == "0x10000000"
    assert facts["has-slot:boot"] == "yes"
    assert facts["serialno"] == "SIM123"
    assert "malformed-line" not in facts


def test_probe_parses_synthetic_device() -> None:
    result = make_client().probe(serial="SIM123", expected_serial="SIM123", now=NOW)

    assert result.tool_ok
    assert result.exit_code == 0
    assert state_of(result, "product") is Tri.TRUE
    assert value_of(result, "product") == "shiba"
    assert value_of(result, "version") == "0.4"
    assert state_of(result, "unlocked") is Tri.TRUE
    assert state_of(result, "battery-soc-ok") is Tri.TRUE
    assert value_of(result, "battery-voltage") == "4301"
    assert state_of(result, "snapshot-update-status") is Tri.TRUE
    assert value_of(result, "snapshot-update-status") == "none"
    assert state_of(result, "serial-match") is Tri.TRUE

    assert state_of(result, "max-fetch-size") is Tri.UNKNOWN

    slot = result.fact("slot-successful:a")
    assert slot is not None
    assert slot.evidence.state is Tri.UNKNOWN
    assert slot.evidence.value == "yes"

    for fact in result.facts:
        assert fact.evidence.source is EvidenceSource.PROBED
        assert fact.evidence.observed_at == NOW


def test_serial_mismatch_is_false() -> None:
    result = make_client().probe(
        serial="SIM123",
        expected_serial="OTHER-DEVICE",
        now=NOW,
    )
    assert result.tool_ok
    assert state_of(result, "serial-match") is Tri.FALSE


def test_disconnect_marks_everything_unknown() -> None:
    result = make_client().probe(serial="BAD", expected_serial="BAD", now=NOW)
    assert not result.tool_ok
    assert "255" in result.detail
    assert state_of(result, "unlocked") is Tri.UNKNOWN
    assert state_of(result, "product") is Tri.UNKNOWN
    assert state_of(result, "serial-match") is Tri.UNKNOWN


def test_timeout_is_classified() -> None:
    result = make_client(timeout_s=0.3).probe(serial="SLOW", now=NOW)
    assert not result.tool_ok
    assert result.timed_out
    assert state_of(result, "unlocked") is Tri.UNKNOWN


def test_truncated_output_cannot_supply_missing_facts() -> None:
    result = make_client().probe(serial="TRUNC", now=NOW)
    assert result.tool_ok
    assert state_of(result, "unlocked") is Tri.UNKNOWN
    assert state_of(result, "battery-soc-ok") is Tri.UNKNOWN


def test_garbage_output_marks_everything_unknown() -> None:
    result = make_client().probe(serial="GARBAGE", now=NOW)
    assert result.tool_ok
    assert state_of(result, "unlocked") is Tri.UNKNOWN
    assert state_of(result, "product") is Tri.UNKNOWN


def test_simulated_evidence_is_inferred() -> None:
    result = make_client().probe(
        serial="SIM123",
        now=NOW,
        source=EvidenceSource.INFERRED,
    )
    fact = result.fact("unlocked")
    assert fact is not None
    assert fact.evidence.source is EvidenceSource.INFERRED


def test_single_getvar_is_read_only_and_parsed() -> None:
    result = make_client().getvar("unlocked", serial="SIM123")
    assert result.ok
    assert "(bootloader) unlocked:yes" in result.stderr


def test_single_getvar_failure_is_not_ok() -> None:
    result = make_client().getvar("nosuchvar", serial="SIM123")
    assert not result.ok
    assert result.exit_code == 1


def test_getvar_all_is_rejected_as_single_var() -> None:
    with pytest.raises(ConfigurationError):
        make_client().getvar("all", serial="SIM123")
