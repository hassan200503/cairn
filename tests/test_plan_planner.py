from __future__ import annotations

import json
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from cairn.core.tristate import Tri
from cairn.package.archive import PackageKind, PackageManifest, load_package
from cairn.plan.planner import (
    PlanAction,
    PlanError,
    PlanFacts,
    PlanOptions,
    SlotPolicy,
    build_plan,
    verify_plan_hash,
)
from cairn.provenance.hash_index import ProvenanceResult

FASTBOOT_INFO = """version 1
flash bootloader bootloader.img
reboot bootloader
flash boot boot.img
flash vbmeta vbmeta.img --apply-vbmeta
update-super
if-wipe erase metadata
reboot fastboot
"""


def _package(
    tmp_path: Path,
    *,
    info: str | None = FASTBOOT_INFO,
    entries: list[tuple[str, bytes]] | None = None,
) -> PackageManifest:
    path = tmp_path / "factory.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries or [
            ("bootloader.img", b"bootloader"),
            ("boot.img", b"boot"),
            ("vbmeta.img", b"vbmeta"),
        ]:
            archive.writestr(name, data)
        if info is not None:
            archive.writestr("fastboot-info.txt", info)
    return load_package(path, hash_files=True, hash_archive=True)


def _true() -> ProvenanceResult:
    return ProvenanceResult(
        Tri.TRUE,
        package_id="test-package",
        reasons=("archive and entry hashes match the local index",),
    )


def test_plan_preserves_vendor_order(tmp_path: Path) -> None:
    manifest = _package(tmp_path)

    plan = build_plan(manifest, _true())

    assert plan.executable is True
    assert [step.action for step in plan.steps] == [
        PlanAction.FLASH,
        PlanAction.REBOOT,
        PlanAction.FLASH,
        PlanAction.FLASH,
        PlanAction.UPDATE_SUPER,
        PlanAction.REBOOT,
    ]
    assert plan.steps[0].partition == "bootloader"
    assert plan.steps[0].source_line == 2
    assert "critical partition write: bootloader" in plan.steps[0].annotations
    assert "vendor requests --apply-vbmeta" in plan.steps[3].annotations
    assert any("update-super requires" in note for note in plan.steps[4].annotations)
    assert plan.deviations == ("skipped if-wipe command at line 7 (wipe disabled)",)
    assert len(plan.plan_sha256) == 64
    assert verify_plan_hash(plan) is True
    assert plan.fallback.action == "stop-and-reprobe"


def test_wipe_includes_if_wipe_commands(tmp_path: Path) -> None:
    manifest = _package(tmp_path)

    plan = build_plan(manifest, _true(), options=PlanOptions(wipe=True))

    assert plan.executable is True
    assert len(plan.steps) == 7
    erase = plan.steps[5]
    assert erase.action is PlanAction.ERASE
    assert erase.partition == "metadata"
    assert erase.if_wipe is True
    assert "erase is destructive" in erase.annotations
    assert "included because wipe is enabled" in erase.annotations
    assert plan.deviations == ()


def test_plan_hash_is_stable_and_sensitive(tmp_path: Path) -> None:
    manifest = _package(tmp_path)

    first = build_plan(manifest, _true())
    second = build_plan(manifest, _true())
    wiped = build_plan(manifest, _true(), options=PlanOptions(wipe=True))

    assert first.plan_sha256 == second.plan_sha256
    assert first.plan_sha256 != wiped.plan_sha256
    assert verify_plan_hash(first) is True
    assert verify_plan_hash(wiped) is True


def test_unknown_provenance_is_not_executable(tmp_path: Path) -> None:
    manifest = _package(tmp_path)

    plan = build_plan(
        manifest,
        ProvenanceResult(Tri.UNKNOWN, reasons=("not in the local index",)),
    )

    assert plan.executable is False
    assert any("provenance is UNKNOWN" in warning for warning in plan.warnings)
    assert len(plan.steps) == 6


def test_false_provenance_is_not_executable(tmp_path: Path) -> None:
    manifest = _package(tmp_path)

    plan = build_plan(
        manifest,
        ProvenanceResult(Tri.FALSE, reasons=("entry hash mismatch",)),
    )

    assert plan.executable is False
    assert any("provenance is FALSE" in warning for warning in plan.warnings)


def test_missing_fastboot_info_raises(tmp_path: Path) -> None:
    manifest = _package(tmp_path, info=None)

    with pytest.raises(PlanError, match="no fastboot-info"):
        build_plan(manifest, _true())


def test_missing_archive_hash_raises(tmp_path: Path) -> None:
    manifest = _package(tmp_path)
    unhashed = load_package(manifest.path)

    with pytest.raises(PlanError, match="archive sha256"):
        build_plan(unhashed, _true())


def test_absent_version_raises(tmp_path: Path) -> None:
    manifest = _package(tmp_path, info="flash boot boot.img\n")

    with pytest.raises(PlanError, match="version is absent"):
        build_plan(manifest, _true())


def test_missing_image_is_not_executable(tmp_path: Path) -> None:
    manifest = _package(
        tmp_path,
        info="version 1\nflash boot boot.img\nflash vbmeta vbmeta.img\n",
        entries=[("boot.img", b"boot")],
    )

    plan = build_plan(manifest, _true())

    assert plan.executable is False
    assert any("image not found" in note for note in plan.steps[1].annotations)


def test_unsafe_partition_raises(tmp_path: Path) -> None:
    manifest = _package(tmp_path, info="version 1\nflash ../boot boot.img\n")

    with pytest.raises(PlanError, match="unsafe partition"):
        build_plan(manifest, _true())


def test_unsafe_image_raises(tmp_path: Path) -> None:
    manifest = _package(tmp_path, info="version 1\nflash boot ../boot.img\n")

    with pytest.raises(PlanError, match="unsafe image"):
        build_plan(manifest, _true())


def test_slot_other_without_facts_is_not_executable(tmp_path: Path) -> None:
    manifest = _package(tmp_path)

    plan = build_plan(
        manifest,
        _true(),
        options=PlanOptions(slot_policy=SlotPolicy.OTHER),
    )

    assert plan.executable is False
    assert any("requires verified slot facts" in warning for warning in plan.warnings)
    assert any("slot policy other unresolved" in note for note in plan.steps[0].annotations)


def test_slot_other_with_facts_is_executable(tmp_path: Path) -> None:
    manifest = _package(tmp_path)

    plan = build_plan(
        manifest,
        _true(),
        options=PlanOptions(slot_policy=SlotPolicy.OTHER),
        facts=PlanFacts(slot_count=2, current_slot="a"),
    )

    assert plan.executable is True
    assert "slot policy: other" in plan.steps[0].annotations
    assert plan.facts.slot_count == 2


def test_slot_current_has_no_slot_annotation(tmp_path: Path) -> None:
    manifest = _package(tmp_path)

    plan = build_plan(manifest, _true())

    assert not any("slot policy" in note for note in plan.steps[0].annotations)


def test_retrofit_force_is_not_executable(tmp_path: Path) -> None:
    manifest = _package(tmp_path)

    plan = build_plan(
        manifest,
        _true(),
        options=PlanOptions(retrofit_force=True),
    )

    assert plan.executable is False
    assert any("retrofit force" in warning for warning in plan.warnings)
    assert any("not modeled" in note for note in plan.steps[4].annotations)


def test_unknown_package_kind_is_not_executable(tmp_path: Path) -> None:
    manifest = _package(tmp_path)
    unknown = replace(manifest, kind=PackageKind.UNKNOWN)

    plan = build_plan(unknown, _true())

    assert plan.executable is False
    assert any("kind is UNKNOWN" in warning for warning in plan.warnings)


def test_empty_plan_is_not_executable(tmp_path: Path) -> None:
    manifest = _package(
        tmp_path,
        info="version 1\nif-wipe erase metadata\n",
    )

    plan = build_plan(manifest, _true())

    assert plan.steps == ()
    assert plan.executable is False
    assert any("no steps" in warning for warning in plan.warnings)


def test_plan_is_json_serializable(tmp_path: Path) -> None:
    manifest = _package(tmp_path)
    plan = build_plan(manifest, _true())

    payload = plan.to_dict()

    encoded = json.dumps(payload)
    assert '"executable": true' in encoded
    assert payload["schema_version"] == 1
    assert payload["plan_sha256"] == plan.plan_sha256
    assert isinstance(payload["steps"], list)
