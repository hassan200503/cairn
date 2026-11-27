"""CLI tests for `cairn recovery`: vault backup/verify/restore and the drill."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cairn.cli import EXIT_FAILED, EXIT_OK, main
from cairn.sim.transcript import Transcript, TranscriptStep, dump_transcript

_PARTITion_BYTES = b"persist-partition-content-0123456789"
_PASSPHRASE = "correct horse battery staple"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_SERIAL_A = _sha(b"serial-a")
_FP_A = _sha(b"hw-serial-a")
_SERIAL_B = _sha(b"serial-b")
_FP_B = _sha(b"hw-serial-b")


def _asset(tmp_path: Path) -> Path:
    path = tmp_path / "persist.img"
    path.write_bytes(_PARTITion_BYTES)
    return path


def _passphrase_file(tmp_path: Path) -> Path:
    path = tmp_path / "passphrase.txt"
    path.write_text(_PASSPHRASE, encoding="utf-8")
    return path


def _device_args() -> list[str]:
    return [
        "--product",
        "pixel-test",
        "--serial-sha256",
        _SERIAL_A,
        "--device-fingerprint",
        _FP_A,
    ]


def _restore_transcript(tmp_path: Path, staged: Path) -> Path:
    transcript = Transcript(
        schema_version=1,
        device={"product": "pixel-test"},
        steps=(
            TranscriptStep(
                argv=("flash", "persist", str(staged)),
                stdout="OKAY",
            ),
        ),
    )
    path = tmp_path / "restore.json"
    dump_transcript(transcript, path)
    return path


def test_backup_verify_restore_roundtrip_in_the_simulator(tmp_path: Path, capsys) -> None:
    vault = tmp_path / "vault.json"
    passphrase = _passphrase_file(tmp_path)
    base = ["recovery"]

    assert (
        main(
            [
                *base,
                "backup",
                "--partition",
                "persist",
                "--asset",
                str(_asset(tmp_path)),
                "--out",
                str(vault),
                *_device_args(),
                "--passphrase-file",
                str(passphrase),
            ]
        )
        == EXIT_OK
    )

    assert main([*base, "verify", str(vault), "--passphrase-file", str(passphrase)]) == EXIT_OK
    assert "persist" in capsys.readouterr().out

    staging = tmp_path / "staging"
    staged = staging / "restore-persist.img"
    transcript = _restore_transcript(tmp_path, staged)
    exit_code = main(
        [
            *base,
            "restore",
            str(vault),
            "--partition",
            "persist",
            "--simulate",
            str(transcript),
            "--staging-dir",
            str(staging),
            *_device_args(),
            "--passphrase-file",
            str(passphrase),
        ]
    )
    assert exit_code == EXIT_OK
    assert "SIMULATED" in capsys.readouterr().out
    assert staged.read_bytes() == _PARTITion_BYTES


def test_restore_refuses_a_different_device(tmp_path: Path, capsys) -> None:
    vault = tmp_path / "vault.json"
    passphrase = _passphrase_file(tmp_path)
    main(
        [
            "recovery",
            "backup",
            "--partition",
            "persist",
            "--asset",
            str(_asset(tmp_path)),
            "--out",
            str(vault),
            *_device_args(),
            "--passphrase-file",
            str(passphrase),
        ]
    )

    other_device = [
        "--product",
        "pixel-test",
        "--serial-sha256",
        _SERIAL_B,
        "--device-fingerprint",
        _FP_B,
    ]
    staging = tmp_path / "staging"
    transcript = _restore_transcript(tmp_path, staging / "restore-persist.img")
    exit_code = main(
        [
            "recovery",
            "restore",
            str(vault),
            "--partition",
            "persist",
            "--simulate",
            str(transcript),
            "--staging-dir",
            str(staging),
            *other_device,
            "--passphrase-file",
            str(passphrase),
        ]
    )
    assert exit_code == EXIT_FAILED
    assert "REFUSED" in capsys.readouterr().err
    assert not (staging / "restore-persist.img").exists()


def test_drill_passes_and_refuses_cross_device(tmp_path: Path, capsys) -> None:
    vault = tmp_path / "vault.json"
    passphrase = _passphrase_file(tmp_path)
    staging = tmp_path / "drill-staging"
    staged = staging / "drill-persist.img"
    transcript = _restore_transcript(tmp_path, staged)

    exit_code = main(
        [
            "recovery",
            "drill",
            "--partition",
            "persist",
            "--asset",
            str(_asset(tmp_path)),
            "--expected-sha256",
            _sha(_PARTITion_BYTES),
            "--vault",
            str(vault),
            "--last-resort",
            "EDL 9008 entry via test point, service only",
            "--simulate",
            str(transcript),
            "--other-serial-sha256",
            _SERIAL_B,
            "--other-fingerprint",
            _FP_B,
            *_device_args(),
            "--passphrase-file",
            str(passphrase),
            "--json",
        ]
    )

    assert exit_code == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "TRUE"
    assert payload["same_device_restored"] is True
    assert payload["cross_device_refused"] is True
    assert staged.read_bytes() == _PARTITion_BYTES


def test_drill_requires_a_stated_last_resort_path(tmp_path: Path, capsys) -> None:
    vault = tmp_path / "vault.json"
    passphrase = _passphrase_file(tmp_path)
    transcript = _restore_transcript(tmp_path, tmp_path / "drill-staging" / "drill-persist.img")

    exit_code = main(
        [
            "recovery",
            "drill",
            "--partition",
            "persist",
            "--asset",
            str(_asset(tmp_path)),
            "--expected-sha256",
            _sha(_PARTITion_BYTES),
            "--vault",
            str(vault),
            "--last-resort",
            "",
            "--simulate",
            str(transcript),
            "--other-serial-sha256",
            _SERIAL_B,
            "--other-fingerprint",
            _FP_B,
            *_device_args(),
            "--passphrase-file",
            str(passphrase),
        ]
    )
    assert exit_code == EXIT_FAILED
    payload_like = capsys.readouterr().out
    assert "UNKNOWN" in payload_like
    assert not vault.exists()


def test_backup_refuses_an_unbound_device_identity(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "recovery",
            "backup",
            "--partition",
            "persist",
            "--asset",
            str(_asset(tmp_path)),
            "--out",
            str(tmp_path / "vault.json"),
            "--product",
            "pixel-test",
            "--serial-sha256",
            "nothex",
            "--device-fingerprint",
            _FP_A,
            "--passphrase-file",
            str(_passphrase_file(tmp_path)),
        ]
    )
    assert exit_code == EXIT_FAILED
    assert "must be 64 lowercase hex" in capsys.readouterr().err
