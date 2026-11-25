from __future__ import annotations

import json
from pathlib import Path

from cairn import __version__
from cairn.cli import EXIT_FAILED, EXIT_OK, EXIT_UNKNOWN, EXIT_USAGE, main

TRANSCRIPT = Path(__file__).parent / "fixtures" / "fastboot" / "pixel8_getvar_all.json"


def test_version_command(capsys) -> None:
    assert main(["version"]) == EXIT_OK
    assert __version__ in capsys.readouterr().out


def test_no_command_prints_help(capsys) -> None:
    assert main([]) == EXIT_OK
    assert "usage: cairn" in capsys.readouterr().out


def test_levels_command(capsys) -> None:
    assert main(["levels"]) == EXIT_OK
    output = capsys.readouterr().out
    for level in ("V0", "V1", "V2", "V3"):
        assert level in output


def test_doctor_simulated_runs_a_link_soak(capsys) -> None:
    exit_code = main(
        [
            "doctor",
            "--simulate",
            str(TRANSCRIPT),
            "--serial",
            "SIM123",
            "--soak",
            "2",
        ]
    )
    output = capsys.readouterr().out
    assert "cairn doctor" in output
    assert "link-soak: TRUE" in output
    assert "2 probes passed" in output
    assert "read-only" in output
    assert exit_code in (EXIT_OK, EXIT_FAILED, EXIT_UNKNOWN)


def test_doctor_json_is_machine_readable(capsys) -> None:
    exit_code = main(
        [
            "doctor",
            "--simulate",
            str(TRANSCRIPT),
            "--serial",
            "SIM123",
            "--soak",
            "2",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["simulated"] is True
    assert payload["soak"]["attempts"] == 2
    assert payload["soak"]["state"] == "TRUE"
    assert payload["tool"]["fastboot"]["simulated"] is True
    assert payload["verdict"] in ("TRUE", "FALSE", "UNKNOWN")
    assert exit_code in (EXIT_OK, EXIT_FAILED, EXIT_UNKNOWN)


def test_doctor_missing_fastboot_is_reported(tmp_path, capsys) -> None:
    exit_code = main(
        [
            "doctor",
            "--fastboot",
            str(tmp_path / "no-fastboot.exe"),
            "--soak",
            "0",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    checks = {check["name"]: check for check in payload["checks"]}
    assert checks["fastboot-tool"]["state"] == "UNKNOWN"
    assert checks["link-soak"]["state"] == "UNKNOWN"
    assert payload["verdict"] != "TRUE"
    assert exit_code in (EXIT_FAILED, EXIT_UNKNOWN)


def test_probe_simulated_reports_read_only(capsys) -> None:
    exit_code = main(["probe", "--simulate", str(TRANSCRIPT), "--serial", "SIM123"])
    assert exit_code == EXIT_OK
    output = capsys.readouterr().out
    assert "SIMULATED" in output
    assert "unlocked: TRUE yes" in output
    assert "no device writes" in output


def test_probe_simulated_json_is_machine_readable(capsys) -> None:
    exit_code = main(["probe", "--simulate", str(TRANSCRIPT), "--serial", "SIM123", "--json"])
    assert exit_code == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"]["simulated"] is True
    assert payload["tool_ok"] is True
    facts = {fact["name"]: fact for fact in payload["facts"]}
    assert facts["unlocked"]["state"] == "TRUE"
    assert facts["unlocked"]["source"] == "INFERRED"
    assert facts["max-fetch-size"]["state"] == "UNKNOWN"
    assert facts["slot-successful:a"]["state"] == "UNKNOWN"


def test_probe_missing_fastboot_is_a_usage_error(tmp_path, capsys) -> None:
    missing = tmp_path / "no-fastboot.exe"
    exit_code = main(["probe", "--fastboot", str(missing)])
    assert exit_code == EXIT_USAGE
    assert "not found" in capsys.readouterr().err
