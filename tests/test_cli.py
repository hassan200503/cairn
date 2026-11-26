from __future__ import annotations

import json
import zipfile
from pathlib import Path

from cairn import __version__
from cairn.cli import EXIT_FAILED, EXIT_OK, EXIT_UNKNOWN, EXIT_USAGE, main
from cairn.package.archive import load_package

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


def _write_factory_zip(path: Path) -> Path:
    info = (TRANSCRIPT.parent / "fastboot-info.txt").read_text(encoding="utf-8")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("boot.img", b"boot")
        archive.writestr("README.txt", b"readme")
        archive.writestr("fastboot-info.txt", info)
    return path


def test_inspect_factory_package(tmp_path, capsys) -> None:
    path = _write_factory_zip(tmp_path / "factory.zip")

    exit_code = main(["inspect", str(path)])

    output = capsys.readouterr().out
    assert exit_code == EXIT_OK
    assert "kind: factory" in output
    assert "fastboot-info: 16 commands" in output
    assert "unknown entries:" in output
    assert "README.txt" in output
    assert "read-only" in output


def test_inspect_json_with_hashes(tmp_path, capsys) -> None:
    path = _write_factory_zip(tmp_path / "factory.zip")

    exit_code = main(["inspect", str(path), "--json", "--hash"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_OK
    assert payload["kind"] == "factory"
    assert payload["archive_sha256"] is not None
    boot = next(entry for entry in payload["entries"] if entry["name"] == "boot.img")
    assert boot["sha256"] is not None
    assert payload["issues"]["unknown_entries"] == ["README.txt"]


def test_inspect_missing_package_fails(tmp_path, capsys) -> None:
    exit_code = main(["inspect", str(tmp_path / "missing.zip")])

    assert exit_code == EXIT_FAILED
    assert "not found" in capsys.readouterr().err


def test_inspect_malformed_package_fails(tmp_path, capsys) -> None:
    path = tmp_path / "broken.zip"
    path.write_bytes(b"not a zip")

    exit_code = main(["inspect", str(path)])

    assert exit_code == EXIT_FAILED
    assert "cannot read package" in capsys.readouterr().err


def _write_index_for(package: Path, index: Path) -> Path:
    manifest = load_package(package, hash_files=True, hash_archive=True)
    assert manifest.archive_sha256 is not None
    entries = {entry.name: entry.sha256 for entry in manifest.entries}
    index.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "packages": [
                    {
                        "id": "cli-test",
                        "device": "shiba",
                        "build": "TEST.1",
                        "archive_sha256": manifest.archive_sha256,
                        "entries": entries,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return index


def test_provenance_matches_local_index(tmp_path, capsys) -> None:
    package = _write_factory_zip(tmp_path / "factory.zip")
    index = _write_index_for(package, tmp_path / "index.json")

    exit_code = main(["provenance", str(package), "--index", str(index)])

    output = capsys.readouterr().out
    assert exit_code == EXIT_OK
    assert "verdict: TRUE" in output
    assert "package id: cli-test" in output
    assert "not a signature" in output


def test_provenance_json_is_machine_readable(tmp_path, capsys) -> None:
    package = _write_factory_zip(tmp_path / "factory.zip")
    index = _write_index_for(package, tmp_path / "index.json")

    exit_code = main(["provenance", str(package), "--index", str(index), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_OK
    assert payload["state"] == "TRUE"
    assert payload["package_id"] == "cli-test"
    assert payload["device"] == "shiba"
    assert payload["archive_sha256"] is not None


def test_provenance_unknown_package_is_unknown(tmp_path, capsys) -> None:
    package = _write_factory_zip(tmp_path / "factory.zip")
    index = _write_index_for(package, tmp_path / "index.json")
    other = tmp_path / "other.zip"
    with zipfile.ZipFile(other, "w") as archive:
        archive.writestr("boot.img", b"different")

    exit_code = main(["provenance", str(other), "--index", str(index)])

    output = capsys.readouterr().out
    assert exit_code == EXIT_UNKNOWN
    assert "verdict: UNKNOWN" in output
    assert "not in the local index" in output


def test_provenance_entry_mismatch_is_false(tmp_path, capsys) -> None:
    package = _write_factory_zip(tmp_path / "factory.zip")
    index = _write_index_for(package, tmp_path / "index.json")
    payload = json.loads(index.read_text(encoding="utf-8"))
    payload["packages"][0]["entries"]["boot.img"] = "0" * 64
    index.write_text(json.dumps(payload), encoding="utf-8")

    exit_code = main(["provenance", str(package), "--index", str(index)])

    output = capsys.readouterr().out
    assert exit_code == EXIT_FAILED
    assert "verdict: FALSE" in output
    assert "entry hash mismatch" in output


def test_provenance_malformed_index_fails(tmp_path, capsys) -> None:
    package = _write_factory_zip(tmp_path / "factory.zip")
    index = tmp_path / "index.json"
    index.write_bytes(b"not json")

    exit_code = main(["provenance", str(package), "--index", str(index)])

    assert exit_code == EXIT_FAILED
    assert "not valid JSON" in capsys.readouterr().err


def test_provenance_missing_index_fails(tmp_path, capsys) -> None:
    package = _write_factory_zip(tmp_path / "factory.zip")

    exit_code = main(["provenance", str(package), "--index", str(tmp_path / "missing.json")])

    assert exit_code == EXIT_FAILED
    assert "not found" in capsys.readouterr().err


def _write_plan_package(path: Path) -> Path:
    info = (
        "version 1\n"
        "flash bootloader bootloader.img\n"
        "flash boot boot.img\n"
        "if-wipe erase metadata\n"
        "reboot fastboot\n"
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bootloader.img", b"bootloader")
        archive.writestr("boot.img", b"boot")
        archive.writestr("fastboot-info.txt", info)
    return path


def test_plan_dry_run(tmp_path, capsys) -> None:
    package = _write_plan_package(tmp_path / "factory.zip")
    index = _write_index_for(package, tmp_path / "index.json")

    exit_code = main(["plan", str(package), "--index", str(index)])

    output = capsys.readouterr().out
    assert exit_code == EXIT_OK
    assert "plan:" in output
    assert "executable: TRUE" in output
    assert "steps: 3" in output
    assert "read-only dry run" in output


def test_plan_wipe_includes_erase(tmp_path, capsys) -> None:
    package = _write_plan_package(tmp_path / "factory.zip")
    index = _write_index_for(package, tmp_path / "index.json")

    exit_code = main(["plan", str(package), "--index", str(index), "--wipe"])

    output = capsys.readouterr().out
    assert exit_code == EXIT_OK
    assert "steps: 4" in output
    assert "erase metadata" in output


def test_plan_json_is_machine_readable(tmp_path, capsys) -> None:
    package = _write_plan_package(tmp_path / "factory.zip")
    index = _write_index_for(package, tmp_path / "index.json")

    exit_code = main(["plan", str(package), "--index", str(index), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_OK
    assert payload["executable"] is True
    assert len(payload["plan_sha256"]) == 64
    assert len(payload["steps"]) == 3


def test_plan_hash_is_stable_across_runs(tmp_path, capsys) -> None:
    package = _write_plan_package(tmp_path / "factory.zip")
    index = _write_index_for(package, tmp_path / "index.json")

    assert main(["plan", str(package), "--index", str(index), "--json"]) == EXIT_OK
    first = json.loads(capsys.readouterr().out)["plan_sha256"]
    assert main(["plan", str(package), "--index", str(index), "--json"]) == EXIT_OK
    second = json.loads(capsys.readouterr().out)["plan_sha256"]

    assert first == second


def test_plan_unknown_package_is_not_executable(tmp_path, capsys) -> None:
    package = _write_plan_package(tmp_path / "factory.zip")
    index = _write_index_for(package, tmp_path / "index.json")
    other = tmp_path / "other.zip"
    with zipfile.ZipFile(other, "w") as archive:
        archive.writestr("boot.img", b"different")
        archive.writestr("fastboot-info.txt", "version 1\nflash boot boot.img\n")

    exit_code = main(["plan", str(other), "--index", str(index)])

    output = capsys.readouterr().out
    assert exit_code == EXIT_UNKNOWN
    assert "executable: FALSE" in output
    assert "not in the local index" in output


def test_plan_missing_fastboot_info_fails(tmp_path, capsys) -> None:
    package = tmp_path / "factory.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("boot.img", b"boot")
    index = _write_index_for(package, tmp_path / "index.json")

    exit_code = main(["plan", str(package), "--index", str(index)])

    assert exit_code == EXIT_FAILED
    assert "no fastboot-info" in capsys.readouterr().err


def test_plan_slot_other_is_not_executable(tmp_path, capsys) -> None:
    package = _write_plan_package(tmp_path / "factory.zip")
    index = _write_index_for(package, tmp_path / "index.json")

    exit_code = main(["plan", str(package), "--index", str(index), "--slot", "other"])

    output = capsys.readouterr().out
    assert exit_code == EXIT_UNKNOWN
    assert "executable: FALSE" in output
    assert "requires verified slot facts" in output


def test_plan_retrofit_force_is_not_executable(tmp_path, capsys) -> None:
    package = _write_plan_package(tmp_path / "factory.zip")
    index = _write_index_for(package, tmp_path / "index.json")

    exit_code = main(["plan", str(package), "--index", str(index), "--retrofit-force"])

    output = capsys.readouterr().out
    assert exit_code == EXIT_UNKNOWN
    assert "executable: FALSE" in output
    assert "retrofit force" in output


AVB_FIXTURE = Path(__file__).parent / "fixtures" / "avb" / "unsigned_vbmeta.img"
SIGNED_AVB_FIXTURE = Path(__file__).parent / "fixtures" / "avb" / "signed_vbmeta.img"
SIGNED_AVB_KEY = Path(__file__).parent / "fixtures" / "avb" / "signed_vbmeta.avbpubkey"


def test_avb_info_fixture(capsys) -> None:
    exit_code = main(["avb", "info", str(AVB_FIXTURE)])

    output = capsys.readouterr().out
    assert exit_code == EXIT_OK
    assert "algorithm: NONE" in output
    assert "property test.key" in output
    assert "kernel_cmdline" in output
    assert "not verified" in output
    assert "read-only" in output


def test_avb_info_json_is_machine_readable(capsys) -> None:
    exit_code = main(["avb", "info", str(AVB_FIXTURE), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_OK
    assert payload["header"]["algorithm"] == "NONE"
    assert len(payload["descriptors"]) == 2
    assert payload["descriptors"][0]["kind"] == "property"
    assert payload["descriptors"][0]["key"] == "test.key"


def test_avb_digest_matches_fixture_sha256(capsys) -> None:
    exit_code = main(["avb", "digest", str(AVB_FIXTURE)])

    output = capsys.readouterr().out.strip()
    assert exit_code == EXIT_OK
    assert output == "df3d0b84fce2abbf0ebdcebbec571cbc2d4b089dca88cf3ab8214c610059b405"


def test_avb_digest_sha512(capsys) -> None:
    exit_code = main(["avb", "digest", str(AVB_FIXTURE), "--hash", "sha512"])

    output = capsys.readouterr().out.strip()
    assert exit_code == EXIT_OK
    assert len(output) == 128


def test_avb_digest_missing_chain_fails(tmp_path, capsys) -> None:
    exit_code = main(
        ["avb", "digest", str(AVB_FIXTURE), "--chain", f"boot={tmp_path / 'missing.img'}"]
    )

    assert exit_code == EXIT_FAILED
    assert "not found" in capsys.readouterr().err


def test_avb_digest_malformed_chain_is_usage_error(capsys) -> None:
    exit_code = main(["avb", "digest", str(AVB_FIXTURE), "--chain", "boot"])

    assert exit_code == EXIT_USAGE
    assert "NAME=PATH" in capsys.readouterr().err


def test_avb_without_subcommand_is_usage_error(capsys) -> None:
    assert main(["avb"]) == EXIT_USAGE
    assert "choose 'info', 'digest', or 'verify'" in capsys.readouterr().err


def test_avb_malformed_image_fails(tmp_path, capsys) -> None:
    image = tmp_path / "bad.img"
    image.write_bytes(b"x" * 256)

    assert main(["avb", "info", str(image)]) == EXIT_FAILED
    assert "magic" in capsys.readouterr().err


def test_avb_verify_signed_fixture(capsys) -> None:
    exit_code = main(["avb", "verify", str(SIGNED_AVB_FIXTURE)])

    output = capsys.readouterr().out
    assert exit_code == EXIT_OK
    assert "signature: valid" in output
    assert "not a trust anchor" in output
    assert "chain-of-trust and rollback are not checked" in output


def test_avb_verify_signed_json(capsys) -> None:
    exit_code = main(["avb", "verify", str(SIGNED_AVB_FIXTURE), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_OK
    assert payload["signed"] is True
    assert payload["valid"] is True
    assert payload["algorithm"] == "SHA256_RSA2048"
    assert len(payload["key_sha256"]) == 64


def test_avb_verify_expected_key(capsys) -> None:
    exit_code = main(["avb", "verify", str(SIGNED_AVB_FIXTURE), "--key", str(SIGNED_AVB_KEY)])

    assert exit_code == EXIT_OK
    assert "expected key" in capsys.readouterr().out


def test_avb_verify_wrong_expected_key_fails(tmp_path, capsys) -> None:
    wrong_key = tmp_path / "wrong.avbpubkey"
    wrong_key.write_bytes(SIGNED_AVB_KEY.read_bytes()[:-1] + b"\x00")

    exit_code = main(["avb", "verify", str(SIGNED_AVB_FIXTURE), "--key", str(wrong_key)])

    assert exit_code == EXIT_FAILED
    assert "INVALID" in capsys.readouterr().out


def test_avb_verify_tampered_image_fails(tmp_path, capsys) -> None:
    data = bytearray(SIGNED_AVB_FIXTURE.read_bytes())
    data[data.index(b"test-value")] ^= 1
    tampered = tmp_path / "tampered.img"
    tampered.write_bytes(data)

    assert main(["avb", "verify", str(tampered)]) == EXIT_FAILED
    assert "stored VBMeta digest" in capsys.readouterr().out


def test_avb_verify_unsigned_is_unknown(capsys) -> None:
    exit_code = main(["avb", "verify", str(AVB_FIXTURE)])

    assert exit_code == EXIT_UNKNOWN
    assert "unsigned" in capsys.readouterr().out


def test_avb_verify_missing_key_fails(tmp_path, capsys) -> None:
    exit_code = main(
        [
            "avb",
            "verify",
            str(SIGNED_AVB_FIXTURE),
            "--key",
            str(tmp_path / "missing.avbpubkey"),
        ]
    )

    assert exit_code == EXIT_FAILED
    assert "not found" in capsys.readouterr().err


SIGNED_BOOT_FIXTURE = Path(__file__).parent / "fixtures" / "avb" / "signed_boot.img"


def test_avb_info_footer_image(capsys) -> None:
    exit_code = main(["avb", "info", str(SIGNED_BOOT_FIXTURE)])

    output = capsys.readouterr().out
    assert exit_code == EXIT_OK
    assert "footer:" in output
    assert "image size: 131072 bytes" in output
    assert "hash boot" in output


def test_avb_digest_footer_image(capsys) -> None:
    exit_code = main(["avb", "digest", str(SIGNED_BOOT_FIXTURE)])

    output = capsys.readouterr().out.strip()
    assert exit_code == EXIT_OK
    assert output == "5ce1e97790e8afd1d7120da6fc785161049c2c1705fe7dd53addee590b1e22b7"


def test_avb_verify_footer_image(capsys) -> None:
    exit_code = main(["avb", "verify", str(SIGNED_BOOT_FIXTURE)])

    output = capsys.readouterr().out
    assert exit_code == EXIT_OK
    assert "signature: valid" in output
    assert "not a trust anchor" in output


CHAIN_TOP = Path(__file__).parent / "fixtures" / "avb" / "chain" / "vbmeta.img"
CHAIN_BOOT = Path(__file__).parent / "fixtures" / "avb" / "chain" / "boot.img"
CHAIN_TOP_KEY = Path(__file__).parent / "fixtures" / "avb" / "chain" / "top.avbpubkey"


def test_avb_verify_chain(capsys) -> None:
    exit_code = main(["avb", "verify", str(CHAIN_TOP), "--chain", f"boot={CHAIN_BOOT}"])

    output = capsys.readouterr().out
    assert exit_code == EXIT_OK
    assert "chains: 1" in output
    assert "boot: valid" in output
    assert "overall: valid" in output
    assert "chain-of-trust checked" in output


def test_avb_verify_chain_json(capsys) -> None:
    exit_code = main(
        [
            "avb",
            "verify",
            str(CHAIN_TOP),
            "--chain",
            f"boot={CHAIN_BOOT}",
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_OK
    assert payload["valid"] is True
    assert payload["chains"][0]["partition_name"] == "boot"


def test_avb_verify_chain_with_expected_top_key(capsys) -> None:
    exit_code = main(
        [
            "avb",
            "verify",
            str(CHAIN_TOP),
            "--chain",
            f"boot={CHAIN_BOOT}",
            "--key",
            str(CHAIN_TOP_KEY),
        ]
    )

    assert exit_code == EXIT_OK
    assert "matches the expected key" in capsys.readouterr().out


def test_avb_verify_missing_chain_is_unknown(capsys) -> None:
    exit_code = main(["avb", "verify", str(CHAIN_TOP), "--chain", f"other={CHAIN_BOOT}"])

    output = capsys.readouterr().out
    assert exit_code == EXIT_UNKNOWN
    assert "chained image was not supplied" in output


def test_avb_verify_wrong_chain_is_invalid(capsys) -> None:
    exit_code = main(["avb", "verify", str(CHAIN_TOP), "--chain", f"boot={AVB_FIXTURE}"])

    output = capsys.readouterr().out
    assert exit_code == EXIT_FAILED
    assert "boot: INVALID" in output
    assert "overall: INVALID" in output


def test_avb_digest_chain_matches_aosp(capsys) -> None:
    exit_code = main(["avb", "digest", str(CHAIN_TOP), "--chain", f"boot={CHAIN_BOOT}"])

    assert exit_code == EXIT_OK
    assert (
        capsys.readouterr().out.strip()
        == "4718daa501cd42cf97865a46b45cf52b205cd6f0a45a09f46c2a95363df9fb83"
    )


def test_rollback_check_known_safe(capsys) -> None:
    exit_code = main(
        [
            "rollback",
            "check",
            str(CHAIN_TOP),
            "--chain",
            f"boot={CHAIN_BOOT}",
            "--stored",
            "0=1",
            "--stored",
            "3=3",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == EXIT_OK
    assert "avb:main: TRUE" in output
    assert "avb:boot: TRUE" in output
    assert "verdict: TRUE" in output
    assert "read-only" in output


def test_rollback_check_unknown_stored_index_is_unknown(capsys) -> None:
    exit_code = main(
        [
            "rollback",
            "check",
            str(CHAIN_TOP),
            "--chain",
            f"boot={CHAIN_BOOT}",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == EXIT_UNKNOWN
    assert "the stored index is unknown" in output
    assert "verdict: UNKNOWN" in output
    assert "hard stop for SR-004" in output


def test_rollback_check_definite_lowering_is_failed(capsys) -> None:
    exit_code = main(
        [
            "rollback",
            "check",
            str(CHAIN_TOP),
            "--chain",
            f"boot={CHAIN_BOOT}",
            "--stored",
            "0=1",
            "--stored",
            "3=9",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == EXIT_FAILED
    assert "avb:boot: FALSE" in output
    assert "not overridable" in output


def test_rollback_check_missing_chain_is_unknown(capsys) -> None:
    exit_code = main(
        [
            "rollback",
            "check",
            str(CHAIN_TOP),
            "--chain",
            f"other={CHAIN_BOOT}",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == EXIT_UNKNOWN
    assert "could not be read" in output


def test_rollback_check_json_is_machine_readable(capsys) -> None:
    exit_code = main(
        [
            "rollback",
            "check",
            str(CHAIN_TOP),
            "--chain",
            f"boot={CHAIN_BOOT}",
            "--stored",
            "0=1",
            "--stored",
            "3=3",
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_OK
    assert payload["state"] == "TRUE"
    assert payload["blocks"] is False
    assert [finding["counter"] for finding in payload["findings"]] == ["avb:main", "avb:boot"]


def test_rollback_check_malformed_stored_is_usage_error(capsys) -> None:
    exit_code = main(["rollback", "check", str(CHAIN_TOP), "--stored", "zero"])

    assert exit_code == EXIT_USAGE
    assert "LOCATION=VALUE" in capsys.readouterr().err


def test_rollback_check_duplicate_location_is_usage_error(capsys) -> None:
    exit_code = main(
        [
            "rollback",
            "check",
            str(CHAIN_TOP),
            "--stored",
            "0=1",
            "--stored",
            "0=2",
        ]
    )

    assert exit_code == EXIT_USAGE
    assert "duplicate stored location" in capsys.readouterr().err


def test_rollback_without_subcommand_is_usage_error(capsys) -> None:
    assert main(["rollback"]) == EXIT_USAGE
    assert "choose 'check'" in capsys.readouterr().err


def test_rollback_check_rejects_oversized_stored_value(capsys) -> None:
    exit_code = main(
        [
            "rollback",
            "check",
            str(CHAIN_TOP),
            "--stored",
            f"0={2**64}",
        ]
    )

    assert exit_code == EXIT_USAGE
    assert "64-bit rollback index limit" in capsys.readouterr().err


def test_rollback_check_malformed_image_is_unknown(tmp_path, capsys) -> None:
    image = tmp_path / "bad.img"
    image.write_bytes(b"not an AVB image")

    exit_code = main(["rollback", "check", str(image)])

    assert exit_code == EXIT_UNKNOWN
    assert "cairn rollback check" in capsys.readouterr().err


def test_rollback_check_warns_that_chain_signatures_are_not_checked(capsys) -> None:
    exit_code = main(
        [
            "rollback",
            "check",
            str(CHAIN_TOP),
            "--chain",
            f"boot={CHAIN_BOOT}",
            "--stored",
            "0=1",
            "--stored",
            "3=3",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == EXIT_OK
    assert "chain images are parsed, not signature-checked" in output
