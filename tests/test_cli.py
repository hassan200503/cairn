from __future__ import annotations

import json
from pathlib import Path

from cairn import __version__
from cairn.cli import EXIT_NOT_IMPLEMENTED, EXIT_OK, EXIT_USAGE, main

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


def test_doctor_reports_not_run(capsys) -> None:
    assert main(["doctor"]) == EXIT_NOT_IMPLEMENTED
    assert "NOT RUN" in capsys.readouterr().out


def test_doctor_json_is_machine_readable(capsys) -> None:
    assert main(["doctor", "--json"]) == EXIT_NOT_IMPLEMENTED
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "not_implemented"
    assert payload["checks_run"] == 0


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
