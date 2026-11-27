from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cairn.adapters.fastboot import ProbedFact, ProbeResult
from cairn.approval import (
    ApprovalError,
    ApprovalInputs,
    ApprovalVerdict,
    DeviceBinding,
    DeviceBindingSource,
    ToolBinding,
    build_device_binding,
    caller_device_binding,
    device_fingerprint,
    encode_approval_key,
    fingerprint_facts,
    generate_approval_key,
    issue_approval,
    key_id,
    load_approval_key,
    new_nonce,
    parse_approval_token,
    verify_approval,
    write_approval_key,
)
from cairn.cli import EXIT_FAILED, EXIT_OK, EXIT_UNKNOWN, main
from cairn.core.evidence import Evidence, EvidenceSource
from cairn.core.tristate import Tri
from cairn.package.archive import load_package
from cairn.plan.planner import PlanOptions, SlotPolicy, build_plan
from cairn.provenance.hash_index import load_hash_index, verify_manifest
from cairn.safety.engine import SafetyContext, SafetyEngine

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)


def _hex(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _device() -> DeviceBinding:
    return caller_device_binding(new_nonce(), _hex("device"))


def _inputs(**overrides: object) -> ApprovalInputs:
    base: dict[str, object] = {
        "plan_sha256": _hex("plan"),
        "evidence_snapshot_sha256": _hex("snapshot"),
        "archive_sha256": _hex("archive"),
        "package_hashes": (("boot.img", _hex("boot")), ("vendor.img", _hex("vendor"))),
        "device": _device(),
        "tools": (ToolBinding(name="fastboot", version="37.0.3", sha256=_hex("fb")),),
    }
    base.update(overrides)
    return ApprovalInputs(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# binding.py
# --------------------------------------------------------------------------- #


def test_tool_binding_requires_a_version_or_sha256() -> None:
    with pytest.raises(ApprovalError):
        ToolBinding(name="fastboot")


def test_tool_binding_rejects_an_invalid_name() -> None:
    with pytest.raises(ApprovalError):
        ToolBinding(name="Fastboot!", version="1")


def test_approval_inputs_rejects_unsorted_package_hashes() -> None:
    with pytest.raises(ApprovalError):
        _inputs(package_hashes=(("vendor.img", _hex("v")), ("boot.img", _hex("b"))))


def test_approval_inputs_rejects_duplicate_package_entry() -> None:
    with pytest.raises(ApprovalError):
        _inputs(package_hashes=(("boot.img", _hex("a")), ("boot.img", _hex("b"))))


def test_approval_inputs_rejects_a_non_hex_digest() -> None:
    with pytest.raises(ApprovalError):
        _inputs(package_hashes=(("boot.img", "nothex"),))


def test_approval_inputs_requires_at_least_one_entry() -> None:
    with pytest.raises(ApprovalError):
        _inputs(package_hashes=())


def test_binding_hash_is_deterministic_for_equal_inputs() -> None:
    device = caller_device_binding("a" * 32, _hex("device"))
    assert _inputs(device=device).binding_sha256 == _inputs(device=device).binding_sha256


def test_approval_inputs_rejects_unsorted_tools() -> None:
    with pytest.raises(ApprovalError):
        _inputs(tools=(ToolBinding(name="b", version="1"), ToolBinding(name="a", version="2")))


def test_binding_hash_changes_with_every_bound_input() -> None:
    baseline = _inputs().binding_sha256
    assert _inputs(plan_sha256=_hex("plan2")).binding_sha256 != baseline
    assert _inputs(archive_sha256=_hex("archive2")).binding_sha256 != baseline
    assert _inputs(evidence_snapshot_sha256=_hex("snap2")).binding_sha256 != baseline
    assert _inputs(package_hashes=(("boot.img", _hex("changed")),)).binding_sha256 != baseline
    assert _inputs(tools=(ToolBinding(name="fastboot", version="99"),)).binding_sha256 != baseline
    other = caller_device_binding(new_nonce(), _hex("other-device"))
    assert _inputs(device=other).binding_sha256 != baseline


def test_binding_hash_is_sensitive_to_a_single_byte() -> None:
    assert (
        _inputs(archive_sha256="0" * 63 + "1").binding_sha256
        != _inputs(archive_sha256="0" * 64).binding_sha256
    )


# --------------------------------------------------------------------------- #
# device.py
# --------------------------------------------------------------------------- #


def _evidence(
    value: str | None,
    *,
    state: Tri = Tri.TRUE,
    source: EvidenceSource = EvidenceSource.PROBED,
    now: datetime = NOW,
    max_age: timedelta | None = None,
) -> Evidence[str]:
    return Evidence(
        state=state,
        source=source,
        observed_at=now,
        value=value,
        max_age=max_age,
    )


def _probe(
    facts: dict[str, tuple[Tri, str | None]],
    *,
    tool_ok: bool = True,
    now: datetime = NOW,
    max_age: timedelta | None = None,
) -> ProbeResult:
    items = tuple(
        ProbedFact(name=name, evidence=_evidence(value, state=state, now=now, max_age=max_age))
        for name, (state, value) in facts.items()
    )
    return ProbeResult(
        serial="SER123",
        facts=items,
        tool_ok=tool_ok,
        exit_code=0,
        stderr="",
        timed_out=False,
        cancelled=False,
        detail="ok",
    )


def _required_facts() -> dict[str, tuple[Tri, str | None]]:
    return {
        "serialno": (Tri.TRUE, "SER123"),
        "product": (Tri.TRUE, "shiba"),
        "hw-revision": (Tri.TRUE, "MP1.0"),
        "version-bootloader": (Tri.TRUE, "slider-1.2"),
        "serial-match": (Tri.TRUE, None),
    }


def test_new_nonce_is_lowercase_hex() -> None:
    nonce = new_nonce()
    assert len(nonce) == 64
    assert nonce == nonce.lower()
    assert all(character in "0123456789abcdef" for character in nonce)


def test_fingerprint_facts_is_order_independent() -> None:
    assert fingerprint_facts({"a": "1", "b": "2"}) == fingerprint_facts({"b": "2", "a": "1"})


def test_device_fingerprint_is_stable_and_value_sensitive() -> None:
    baseline = device_fingerprint(_probe(_required_facts()), now=NOW)
    again = device_fingerprint(_probe(_required_facts()), now=NOW)
    assert baseline == again

    facts = _required_facts()
    facts["product"] = (Tri.TRUE, "raven")
    assert device_fingerprint(_probe(facts), now=NOW) != baseline


def test_device_fingerprint_rejects_a_failed_probe() -> None:
    with pytest.raises(ApprovalError):
        device_fingerprint(_probe(_required_facts(), tool_ok=False), now=NOW)


def test_device_fingerprint_rejects_a_missing_required_fact() -> None:
    facts = _required_facts()
    del facts["hw-revision"]
    with pytest.raises(ApprovalError):
        device_fingerprint(_probe(facts), now=NOW)


def test_device_fingerprint_rejects_a_non_true_required_fact() -> None:
    facts = _required_facts()
    facts["product"] = (Tri.UNKNOWN, "?")
    with pytest.raises(ApprovalError):
        device_fingerprint(_probe(facts), now=NOW)


def test_device_fingerprint_rejects_a_serial_mismatch() -> None:
    facts = _required_facts()
    facts["serial-match"] = (Tri.FALSE, None)
    with pytest.raises(ApprovalError):
        device_fingerprint(_probe(facts), now=NOW)


def test_device_fingerprint_rejects_stale_facts() -> None:
    probe = _probe(
        _required_facts(),
        now=NOW - timedelta(hours=2),
        max_age=timedelta(minutes=5),
    )
    with pytest.raises(ApprovalError):
        device_fingerprint(probe, now=NOW)


def test_build_device_binding_marks_the_source_probed() -> None:
    binding = build_device_binding(_probe(_required_facts()), new_nonce(), now=NOW)
    assert binding.source is DeviceBindingSource.PROBED
    assert binding.fingerprint_sha256 == device_fingerprint(_probe(_required_facts()), now=NOW)


def test_caller_device_binding_marks_the_source_caller() -> None:
    binding = caller_device_binding(new_nonce(), _hex("fp"))
    assert binding.source is DeviceBindingSource.CALLER


def test_device_binding_rejects_a_short_nonce() -> None:
    with pytest.raises(ApprovalError):
        DeviceBinding(nonce="abc", fingerprint_sha256=_hex("fp"), source=DeviceBindingSource.CALLER)


def test_device_binding_rejects_an_uppercase_nonce() -> None:
    with pytest.raises(ApprovalError):
        DeviceBinding(
            nonce="A" * 32,
            fingerprint_sha256=_hex("fp"),
            source=DeviceBindingSource.CALLER,
        )


# --------------------------------------------------------------------------- #
# token.py - keys
# --------------------------------------------------------------------------- #


def test_generated_key_is_32_bytes_and_key_id_is_16_hex() -> None:
    key = generate_approval_key()
    assert len(key) == 32
    identifier = key_id(key)
    assert len(identifier) == 16
    assert all(character in "0123456789abcdef" for character in identifier)


def test_key_id_is_stable_for_the_same_key() -> None:
    key = generate_approval_key()
    assert key_id(key) == key_id(key)


def test_encode_and_load_key_round_trip(tmp_path: Path) -> None:
    key = generate_approval_key()
    path = tmp_path / "approval.key"
    write_approval_key(path, key)
    assert load_approval_key(path) == key
    assert encode_approval_key(key) == key.hex()


def test_write_key_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    path = tmp_path / "approval.key"
    write_approval_key(path, generate_approval_key())
    with pytest.raises(ApprovalError):
        write_approval_key(path, generate_approval_key())
    write_approval_key(path, generate_approval_key(), overwrite=True)


def test_load_key_rejects_wrong_length(tmp_path: Path) -> None:
    path = tmp_path / "approval.key"
    path.write_text("abcd", encoding="ascii")
    with pytest.raises(ApprovalError):
        load_approval_key(path)


def test_load_key_rejects_uppercase_hex(tmp_path: Path) -> None:
    path = tmp_path / "approval.key"
    path.write_text("A" * 64 + "\n", encoding="ascii")
    with pytest.raises(ApprovalError):
        load_approval_key(path)


def test_issue_rejects_a_short_reason() -> None:
    key = generate_approval_key()
    with pytest.raises(ApprovalError):
        issue_approval(_inputs(), key, operator="tech", reason="short")


# --------------------------------------------------------------------------- #
# token.py - issue / parse / verify
# --------------------------------------------------------------------------- #


def _issued() -> tuple[str, ApprovalInputs, bytes]:
    key = generate_approval_key()
    inputs = _inputs()
    token = issue_approval(inputs, key, operator="tech", reason="approved on the bench")
    return token.to_json(), inputs, key


def test_issue_and_parse_round_trip() -> None:
    text, inputs, key = _issued()
    token = parse_approval_token(text, key)
    assert token.operator == "tech"
    assert token.binding_sha256 == inputs.binding_sha256
    assert token.inputs.binding_sha256 == inputs.binding_sha256


def test_parse_rejects_a_token_signed_by_another_key() -> None:
    text, _, _ = _issued()
    with pytest.raises(ApprovalError):
        parse_approval_token(text, generate_approval_key())


def test_parse_rejects_a_tampered_signature() -> None:
    text, _, key = _issued()
    document = json.loads(text)
    document["signature"] = "0" * 64
    with pytest.raises(ApprovalError):
        parse_approval_token(json.dumps(document), key)


def test_parse_rejects_a_duplicate_json_key() -> None:
    text, _, key = _issued()
    duplicated = text.replace('"operator": "tech"', '"operator": "tech", "operator": "other"')
    with pytest.raises(ApprovalError):
        parse_approval_token(duplicated, key)


def test_parse_rejects_an_unknown_field() -> None:
    text, _, key = _issued()
    document = json.loads(text)
    document["extra"] = 1
    with pytest.raises(ApprovalError):
        parse_approval_token(json.dumps(document), key)


def test_parse_rejects_a_wrong_kind() -> None:
    text, _, key = _issued()
    document = json.loads(text)
    document["kind"] = "cairn.other"
    with pytest.raises(ApprovalError):
        parse_approval_token(json.dumps(document), key)


def test_parse_rejects_a_binding_hash_that_does_not_match_its_payload() -> None:
    text, _, key = _issued()
    document = json.loads(text)
    document["binding_sha256"] = _hex("tampered")
    with pytest.raises(ApprovalError):
        parse_approval_token(json.dumps(document), key)


def test_verify_returns_true_for_matching_inputs() -> None:
    text, inputs, key = _issued()
    verdict = verify_approval(text, key, inputs)
    assert verdict.state is Tri.TRUE
    assert verdict.mismatches == ()
    assert verdict.token_sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_verify_warns_when_the_device_binding_is_caller_supplied() -> None:
    text, inputs, key = _issued()
    verdict = verify_approval(text, key, inputs)
    assert any("caller-supplied" in warning for warning in verdict.warnings)


def test_verify_is_false_when_the_plan_hash_changed() -> None:
    text, _, key = _issued()
    verdict = verify_approval(text, key, _inputs(plan_sha256=_hex("plan2")))
    assert verdict.state is Tri.FALSE
    assert "plan_sha256" in verdict.mismatches


def test_verify_is_false_when_the_evidence_snapshot_changed() -> None:
    text, _, key = _issued()
    verdict = verify_approval(text, key, _inputs(evidence_snapshot_sha256=_hex("snap2")))
    assert verdict.state is Tri.FALSE
    assert "evidence_snapshot_sha256" in verdict.mismatches


def test_verify_is_false_when_the_archive_hash_changed() -> None:
    text, _, key = _issued()
    verdict = verify_approval(text, key, _inputs(archive_sha256=_hex("archive2")))
    assert verdict.state is Tri.FALSE
    assert "archive_sha256" in verdict.mismatches


def test_verify_is_false_when_a_package_entry_changed() -> None:
    text, _, key = _issued()
    changed = _inputs(package_hashes=(("boot.img", _hex("boot")), ("vendor.img", _hex("changed"))))
    verdict = verify_approval(text, key, changed)
    assert verdict.state is Tri.FALSE
    assert "package_hashes" in verdict.mismatches


def test_verify_is_false_when_a_package_entry_is_removed() -> None:
    text, _, key = _issued()
    verdict = verify_approval(text, key, _inputs(package_hashes=(("boot.img", _hex("boot")),)))
    assert verdict.state is Tri.FALSE
    assert "package_hashes" in verdict.mismatches


def test_verify_is_false_when_a_tool_changed() -> None:
    text, _, key = _issued()
    verdict = verify_approval(
        text, key, _inputs(tools=(ToolBinding(name="fastboot", version="99"),))
    )
    assert verdict.state is Tri.FALSE
    assert "tools" in verdict.mismatches


def test_verify_is_false_when_the_device_changed() -> None:
    text, _, key = _issued()
    other = caller_device_binding(new_nonce(), _hex("other-device"))
    verdict = verify_approval(text, key, _inputs(device=other))
    assert verdict.state is Tri.FALSE
    assert "device.fingerprint_sha256" in verdict.mismatches


def test_verify_is_false_for_an_unparseable_token() -> None:
    _, inputs, key = _issued()
    verdict = verify_approval("not a token", key, inputs)
    assert verdict.state is Tri.FALSE
    assert verdict.mismatches == ("token",)


def test_verdict_must_cite_the_token_hash_when_true() -> None:
    with pytest.raises(ApprovalError):
        ApprovalVerdict(state=Tri.TRUE, reasons=("ok",))


def test_verdict_rejects_a_true_result_with_mismatches() -> None:
    with pytest.raises(ApprovalError):
        ApprovalVerdict(state=Tri.TRUE, reasons=("ok",), mismatches=("plan_sha256",))


def test_verdict_rejects_a_false_result_without_a_mismatch() -> None:
    with pytest.raises(ApprovalError):
        ApprovalVerdict(state=Tri.FALSE, reasons=("nope",))


def test_verdict_to_check_state_carries_the_token_hash_as_evidence() -> None:
    text, inputs, key = _issued()
    verdict = verify_approval(text, key, inputs)
    check = verdict.to_check_state()
    assert check.state is Tri.TRUE
    assert check.evidence_ids == (verdict.token_sha256,)


# --------------------------------------------------------------------------- #
# Integration: manifest + plan + safety report -> approval inputs
# --------------------------------------------------------------------------- #


def _write_plan_package(path: Path, tag: str = "") -> Path:
    info = (
        "version 1\n"
        "flash bootloader bootloader.img\n"
        "flash boot boot.img\n"
        "if-wipe erase metadata\n"
        "reboot fastboot\n"
    )
    suffix = tag.encode("utf-8")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bootloader.img", b"bootloader" + suffix)
        archive.writestr("boot.img", b"boot" + suffix)
        archive.writestr("fastboot-info.txt", info)
    return path


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
                        "id": "approval-test",
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


def _manifest_plan_report(tmp_path: Path):
    package = _write_plan_package(tmp_path / "factory.zip")
    index = _write_index_for(package, tmp_path / "index.json")
    manifest = load_package(package, hash_files=True, hash_archive=True)
    provenance = verify_manifest(load_hash_index(index), manifest)
    plan = build_plan(
        manifest,
        provenance,
        options=PlanOptions(wipe=False, slot_policy=SlotPolicy.CURRENT, retrofit_force=False),
    )
    report = SafetyEngine.pre_approval().evaluate(SafetyContext(provenance=provenance))
    return manifest, plan, report


def test_from_manifest_binds_the_plan_and_package(tmp_path: Path) -> None:
    manifest, plan, report = _manifest_plan_report(tmp_path)
    inputs = ApprovalInputs.from_manifest(manifest, plan, report, _device())

    assert inputs.plan_sha256 == plan.plan_sha256
    assert inputs.evidence_snapshot_sha256 == report.evidence_snapshot_sha256
    assert inputs.archive_sha256 == manifest.archive_sha256
    names = [name for name, _ in inputs.package_hashes]
    assert names == sorted(names)
    assert "boot.img" in names


def test_from_manifest_round_trips_through_a_token(tmp_path: Path) -> None:
    manifest, plan, report = _manifest_plan_report(tmp_path)
    inputs = ApprovalInputs.from_manifest(manifest, plan, report, _device())
    key = generate_approval_key()

    token = issue_approval(inputs, key, operator="tech", reason="approved on the bench")
    verdict = verify_approval(token.to_json(), key, inputs)

    assert verdict.state is Tri.TRUE


def test_from_manifest_sorts_tool_bindings_by_name(tmp_path: Path) -> None:
    manifest, plan, report = _manifest_plan_report(tmp_path)
    inputs = ApprovalInputs.from_manifest(
        manifest,
        plan,
        report,
        _device(),
        tools=(ToolBinding(name="zipalign", version="1"), ToolBinding(name="avbtool", version="2")),
    )
    assert [tool.name for tool in inputs.tools] == ["avbtool", "zipalign"]


def test_from_manifest_rejects_a_plan_for_a_different_package(tmp_path: Path) -> None:
    inspected = _write_plan_package(tmp_path / "inspected.zip")
    planned = _write_plan_package(tmp_path / "planned.zip", tag="other")
    index = _write_index_for(planned, tmp_path / "planned-index.json")
    planned_manifest = load_package(planned, hash_files=True, hash_archive=True)
    provenance = verify_manifest(load_hash_index(index), planned_manifest)
    plan = build_plan(
        planned_manifest,
        provenance,
        options=PlanOptions(wipe=False, slot_policy=SlotPolicy.CURRENT, retrofit_force=False),
    )
    report = SafetyEngine.pre_approval().evaluate(SafetyContext(provenance=provenance))
    inspected_manifest = load_package(inspected, hash_files=True, hash_archive=True)
    assert inspected_manifest.archive_sha256 != planned_manifest.archive_sha256

    with pytest.raises(ApprovalError):
        ApprovalInputs.from_manifest(inspected_manifest, plan, report, _device())


def test_from_manifest_requires_entry_hashes(tmp_path: Path) -> None:
    manifest, plan, report = _manifest_plan_report(tmp_path)
    unhashed = load_package(tmp_path / "factory.zip", hash_files=False, hash_archive=True)
    assert unhashed.archive_sha256 == manifest.archive_sha256
    assert any(entry.sha256 is None for entry in unhashed.entries)

    with pytest.raises(ApprovalError):
        ApprovalInputs.from_manifest(unhashed, plan, report, _device())


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_keygen_then_inspect_round_trip(tmp_path: Path, capsys) -> None:
    key_path = tmp_path / "approval.key"
    assert main(["approval", "keygen", "--out", str(key_path), "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["bytes"] == 32
    assert len(payload["key_id"]) == 16

    manifest, plan, report = _manifest_plan_report(tmp_path)
    inputs = ApprovalInputs.from_manifest(manifest, plan, report, _device())
    token = issue_approval(
        inputs,
        load_approval_key(key_path),
        operator="tech",
        reason="approved on the bench",
    )
    token_path = tmp_path / "approval.json"
    token_path.write_text(token.to_json(), encoding="utf-8")

    assert main(["approval", "inspect", str(token_path), "--key", str(key_path)]) == EXIT_OK
    output = capsys.readouterr().out
    assert "consistency boundary, not an authorization boundary" in output


def test_cli_keygen_refuses_to_overwrite_without_force(tmp_path: Path, capsys) -> None:
    key_path = tmp_path / "approval.key"
    assert main(["approval", "keygen", "--out", str(key_path)]) == EXIT_OK
    capsys.readouterr()

    assert main(["approval", "keygen", "--out", str(key_path)]) == EXIT_FAILED
    assert "already exists" in capsys.readouterr().err


def test_cli_issue_is_blocked_without_catalog_bound_evidence(tmp_path: Path, capsys) -> None:
    package = _write_plan_package(tmp_path / "factory.zip")
    index = _write_index_for(package, tmp_path / "index.json")
    key_path = tmp_path / "approval.key"
    assert main(["approval", "keygen", "--out", str(key_path)]) == EXIT_OK
    capsys.readouterr()

    exit_code = main(
        [
            "approval",
            "issue",
            str(package),
            "--index",
            str(index),
            "--key",
            str(key_path),
            "--operator",
            "tech",
            "--reason",
            "approved on the bench",
            "--nonce",
            new_nonce(),
            "--device-fingerprint",
            _hex("device"),
        ]
    )

    assert exit_code == EXIT_UNKNOWN
    assert "pre-approval safety report blocks" in capsys.readouterr().err


def test_cli_verify_reports_true_for_a_matching_token(tmp_path: Path, capsys) -> None:
    manifest, plan, report = _manifest_plan_report(tmp_path)
    package = tmp_path / "factory.zip"
    index = tmp_path / "index.json"
    nonce = new_nonce()
    inputs = ApprovalInputs.from_manifest(
        manifest, plan, report, caller_device_binding(nonce, _hex("device"))
    )
    key_path = tmp_path / "approval.key"
    assert main(["approval", "keygen", "--out", str(key_path)]) == EXIT_OK
    capsys.readouterr()
    token = issue_approval(
        inputs,
        load_approval_key(key_path),
        operator="tech",
        reason="approved on the bench",
    )
    token_path = tmp_path / "approval.json"
    token_path.write_text(token.to_json(), encoding="utf-8")

    exit_code = main(
        [
            "approval",
            "verify",
            str(token_path),
            "--key",
            str(key_path),
            "--nonce",
            nonce,
            "--device-fingerprint",
            _hex("device"),
            str(package),
            "--index",
            str(index),
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_OK
    assert payload["state"] == "TRUE"
    assert payload["mismatches"] == []


def test_cli_verify_reports_false_when_the_device_fingerprint_changed(
    tmp_path: Path, capsys
) -> None:
    manifest, plan, report = _manifest_plan_report(tmp_path)
    package = tmp_path / "factory.zip"
    index = tmp_path / "index.json"
    nonce = new_nonce()
    inputs = ApprovalInputs.from_manifest(
        manifest, plan, report, caller_device_binding(nonce, _hex("device"))
    )
    key_path = tmp_path / "approval.key"
    assert main(["approval", "keygen", "--out", str(key_path)]) == EXIT_OK
    capsys.readouterr()
    token = issue_approval(
        inputs,
        load_approval_key(key_path),
        operator="tech",
        reason="approved on the bench",
    )
    token_path = tmp_path / "approval.json"
    token_path.write_text(token.to_json(), encoding="utf-8")

    exit_code = main(
        [
            "approval",
            "verify",
            str(token_path),
            "--key",
            str(key_path),
            "--nonce",
            nonce,
            "--device-fingerprint",
            _hex("a-different-device"),
            str(package),
            "--index",
            str(index),
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_FAILED
    assert payload["state"] == "FALSE"
    assert "device.fingerprint_sha256" in payload["mismatches"]
