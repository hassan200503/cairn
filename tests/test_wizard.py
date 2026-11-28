from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cairn.approval import encode_approval_key, generate_approval_key
from cairn.cli import EXIT_FAILED, EXIT_UNKNOWN, EXIT_USAGE, main
from cairn.core.tristate import Tri
from cairn.package.archive import load_package, sha256_file
from cairn.plan.planner import PlanFacts, PlanOptions, build_plan
from cairn.provenance.hash_index import load_hash_index, verify_manifest
from cairn.wizard.session import (
    STAGE_TITLES,
    ApprovalBundle,
    DeviceRecord,
    SessionOutcome,
    StageOutcome,
    StageRecord,
    WizardError,
    load_session,
    new_session,
    save_session,
)

TRANSCRIPT = Path(__file__).parent / "fixtures" / "fastboot" / "pixel8_getvar_all.json"
INFO = Path(__file__).parent / "fixtures" / "fastboot" / "fastboot-info.txt"


def _hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _package(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("boot.img", b"boot")
        archive.writestr("fastboot-info.txt", INFO.read_text(encoding="utf-8"))
    return path


def _index(path: Path, package: Path) -> Path:
    manifest = load_package(package, hash_files=True, hash_archive=True)
    payload = {
        "schema_version": 1,
        "packages": [
            {
                "id": "test-build",
                "archive_sha256": manifest.archive_sha256,
                "entries": {entry.name: entry.sha256 for entry in manifest.entries},
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _ready_session(path: Path, package: Path, index_path: Path) -> Path:
    manifest = load_package(package, hash_files=True, hash_archive=True)
    provenance = verify_manifest(load_hash_index(index_path), manifest)
    assert provenance.state is Tri.TRUE
    plan = build_plan(
        manifest,
        provenance,
        options=PlanOptions(),
        facts=PlanFacts(),
    )
    assert manifest.archive_sha256 is not None
    snapshot = _hex("snapshot")
    now = datetime.now(UTC)
    device = DeviceRecord(
        source="probed",
        simulated=False,
        nonce="a" * 32,
        fingerprint_sha256=_hex("device"),
        probed_at=now,
        max_age_s=600,
    )
    bundle = ApprovalBundle(
        plan_sha256=plan.plan_sha256,
        evidence_snapshot_sha256=snapshot,
        archive_sha256=manifest.archive_sha256,
        package_hashes=tuple(sorted((entry.name, entry.sha256) for entry in manifest.entries)),
        tools=(),
        pre_safety={"can_proceed": True, "evidence_snapshot_sha256": snapshot},
        plan_options=plan.options.to_dict(),
        plan_facts=plan.facts.to_dict(),
    )
    stages = (
        *(
            StageRecord(
                stage=name,
                title=STAGE_TITLES[name],
                outcome=StageOutcome.PASS,
                detail="test pass",
                at=now,
                duration_ms=0,
            )
            for name in (
                "doctor",
                "inspect",
                "provenance",
                "probe",
                "avb",
                "rollback",
                "plan",
            )
        ),
        StageRecord(
            stage="approval",
            title=STAGE_TITLES["approval"],
            outcome=StageOutcome.SKIPPED,
            detail="awaiting approval token",
            at=now,
            duration_ms=0,
        ),
    )
    session = new_session(
        package_path=package,
        index_path=index_path,
        cairn_version="test",
        now=now,
        session_id="b" * 32,
    ).replace(
        stages=stages,
        device=device,
        bundle=bundle,
        archive_sha256=manifest.archive_sha256,
        index_sha256=sha256_file(index_path),
        plan=plan.to_dict(),
        pre_safety={"can_proceed": True, "evidence_snapshot_sha256": snapshot},
        outcome=SessionOutcome.READY,
    )
    save_session(path, session)
    return path


def test_wizard_simulation_persists_a_non_device_evidence_session(tmp_path, capsys) -> None:
    package = _package(tmp_path / "factory.zip")
    index = _index(tmp_path / "index.json", package)
    state = tmp_path / "wizard.json"

    exit_code = main(
        [
            "wizard",
            str(package),
            "--index",
            str(index),
            "--state",
            str(state),
            "--simulate",
            str(TRANSCRIPT),
            "--serial",
            "SIM123",
            "--soak",
            "0",
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_UNKNOWN
    assert payload["outcome"] == "simulated"
    assert payload["device"]["simulated"] is True
    assert state.is_file()
    assert load_session(state).state_sha256 == payload["state_sha256"]


def test_session_load_rejects_tampering_and_duplicate_keys(tmp_path) -> None:
    package = _package(tmp_path / "factory.zip")
    index = _index(tmp_path / "index.json", package)
    state = _ready_session(tmp_path / "wizard.json", package, index)

    text = state.read_text(encoding="utf-8")
    state.write_text(text.replace('"outcome": "ready"', '"outcome": "blocked"'), encoding="utf-8")
    with pytest.raises(WizardError, match="state hash"):
        load_session(state)

    state.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(WizardError, match="repeats JSON key"):
        load_session(state)


def test_approval_session_issue_and_verify_reloads_current_inputs(tmp_path, capsys) -> None:
    package = _package(tmp_path / "factory.zip")
    index = _index(tmp_path / "index.json", package)
    state = _ready_session(tmp_path / "wizard.json", package, index)
    key = tmp_path / "approval.key"
    key.write_text(encode_approval_key(generate_approval_key()) + "\n", encoding="ascii")
    token = tmp_path / "approval.json"

    assert (
        main(
            [
                "approval",
                "issue",
                "--session",
                str(state),
                "--key",
                str(key),
                "--operator",
                "test operator",
                "--reason",
                "session test approval",
                "--out",
                str(token),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            [
                "approval",
                "verify",
                str(token),
                "--session",
                str(state),
                "--key",
                str(key),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["state"] == "TRUE"

    package.write_bytes(package.read_bytes() + b"session-drift")
    assert (
        main(
            [
                "approval",
                "verify",
                str(token),
                "--session",
                str(state),
                "--key",
                str(key),
            ]
        )
        == EXIT_FAILED
    )
    assert "archive hash changed" in capsys.readouterr().err


def test_session_approval_refuses_non_ready_or_conflicting_inputs(tmp_path, capsys) -> None:
    package = _package(tmp_path / "factory.zip")
    index = _index(tmp_path / "index.json", package)
    state = _ready_session(tmp_path / "wizard.json", package, index)
    key = tmp_path / "approval.key"
    key.write_text(encode_approval_key(generate_approval_key()) + "\n", encoding="ascii")
    blocked = load_session(state).replace(outcome=SessionOutcome.BLOCKED)
    save_session(state, blocked)

    assert (
        main(
            [
                "approval",
                "issue",
                "--session",
                str(state),
                "--key",
                str(key),
                "--operator",
                "test operator",
                "--reason",
                "session test approval",
            ]
        )
        == EXIT_FAILED
    )
    assert "requires a READY" in capsys.readouterr().err

    assert (
        main(
            [
                "approval",
                "issue",
                str(package),
                "--session",
                str(state),
                "--key",
                str(key),
                "--operator",
                "test operator",
                "--reason",
                "session test approval",
            ]
        )
        == EXIT_USAGE
    )
    assert "cannot be combined" in capsys.readouterr().err


def test_hash_index_helper_is_equivalent_to_manifest_verification(tmp_path) -> None:
    package = _package(tmp_path / "factory.zip")
    index_path = _index(tmp_path / "index.json", package)
    manifest = load_package(package, hash_files=True, hash_archive=True)
    index = load_hash_index(index_path)

    from cairn.provenance.hash_index import verify_manifest, verify_package_hashes

    assert verify_package_hashes(
        index,
        manifest.archive_sha256,
        {entry.name: entry.sha256 for entry in manifest.entries},
    ) == verify_manifest(index, manifest)


def _catalog_file(tmp_path, fingerprint: str, *, with_key: bool = True) -> Path:
    import base64

    from cairn.catalog import CATALOG_SCHEMA_VERSION

    key = (Path(__file__).parent / "fixtures" / "avb" / "signed_vbmeta.avbpubkey").read_bytes()
    document = {
        "kind": "cairn.catalog",
        "schema_version": CATALOG_SCHEMA_VERSION,
        "devices": [
            {
                "product": "pixel8",
                "fingerprint_sha256": fingerprint,
                "serial_sha256": None,
                "trusted_key_sha256": hashlib.sha256(key).hexdigest(),
                "trusted_key_b64": base64.b64encode(key).decode("ascii") if with_key else None,
                "expected_lock_state": "locked",
                "source": "HF-0001",
                "notes": None,
            }
        ],
        "packages": [],
    }
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _avb_run(tmp_path: Path, *, catalog: Path | None, fingerprint: str | None):
    from cairn.wizard.stages import WizardOptions, WizardRun, stage_avb

    options = WizardOptions(
        package=tmp_path / "factory.zip",
        index=tmp_path / "index.json",
        state=tmp_path / "wizard.json",
        device_fingerprint=fingerprint,
        vbmeta=Path(__file__).parent / "fixtures" / "avb" / "signed_vbmeta.img",
        catalog=catalog,
    )
    run = WizardRun(options=options)
    return run, stage_avb(run, now=datetime.now(UTC))


def test_wizard_avb_stage_anchors_the_key_from_a_catalog(tmp_path) -> None:
    fingerprint = _hex("device")
    catalog = _catalog_file(tmp_path, fingerprint)
    _run, result = _avb_run(tmp_path, catalog=catalog, fingerprint=fingerprint)

    assert result.outcome is StageOutcome.PASS
    assert result.payload["trusted_key_source"] == "HF-0001"
    assert result.payload["catalog_sha256"] == hashlib.sha256(catalog.read_bytes()).hexdigest()
    assert any("catalog entry" in w for w in result.warnings)


def test_wizard_avb_stage_anchors_by_the_probed_device_fingerprint(tmp_path) -> None:
    from cairn.wizard.stages import WizardOptions, WizardRun, stage_avb

    fingerprint = _hex("probed-device")
    options = WizardOptions(
        package=tmp_path / "factory.zip",
        index=tmp_path / "index.json",
        state=tmp_path / "wizard.json",
        vbmeta=Path(__file__).parent / "fixtures" / "avb" / "signed_vbmeta.img",
        catalog=_catalog_file(tmp_path, fingerprint),
    )
    run = WizardRun(options=options)
    run.device = DeviceRecord(
        source="probed",
        simulated=False,
        nonce="a" * 32,
        fingerprint_sha256=fingerprint,
        probed_at=datetime.now(UTC),
        max_age_s=600,
    )
    result = stage_avb(run, now=datetime.now(UTC))
    assert result.outcome is StageOutcome.PASS
    assert result.payload["trusted_key_source"] == "HF-0001"


def test_wizard_avb_stage_warns_when_the_catalog_entry_has_no_key(tmp_path) -> None:
    fingerprint = _hex("device")
    catalog = _catalog_file(tmp_path, fingerprint, with_key=False)
    _run, result = _avb_run(tmp_path, catalog=catalog, fingerprint=fingerprint)

    assert result.outcome is StageOutcome.BLOCKED
    assert any("no key was anchored" in w for w in result.warnings)


def test_wizard_avb_stage_warns_when_the_catalog_has_no_matching_device(tmp_path) -> None:
    catalog = _catalog_file(tmp_path, _hex("another-device"))
    _run, result = _avb_run(tmp_path, catalog=catalog, fingerprint=_hex("device"))

    assert result.outcome is StageOutcome.BLOCKED
    assert result.payload["catalog_sha256"] == hashlib.sha256(catalog.read_bytes()).hexdigest()
    assert any("no key was anchored" in w for w in result.warnings)


def test_wizard_avb_stage_ignores_the_catalog_without_a_fingerprint(tmp_path) -> None:
    catalog = _catalog_file(tmp_path, _hex("device"))
    _run, result = _avb_run(tmp_path, catalog=catalog, fingerprint=None)

    assert result.outcome is StageOutcome.BLOCKED
    assert "trusted_key_source" not in result.payload
    assert "catalog_sha256" not in result.payload
