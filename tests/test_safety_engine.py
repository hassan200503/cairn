from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cairn.core.evidence import Evidence, EvidenceSource
from cairn.core.tristate import Tri
from cairn.provenance.hash_index import ProvenanceResult
from cairn.safety import (
    DEFAULT_RULES,
    CheckState,
    DeviceIdentity,
    OverrideRequest,
    PackageIdentity,
    RuleResult,
    RuleSpec,
    SafetyContext,
    SafetyEngine,
    SafetyError,
    SafetyReport,
)
from cairn.tools.manifest import ToolReport

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)
ENGINE = SafetyEngine()


def _lock(
    state: Tri,
    *,
    source: EvidenceSource = EvidenceSource.PROBED,
    observed_at: datetime = NOW - timedelta(seconds=30),
    max_age: timedelta | None = timedelta(minutes=5),
) -> Evidence[bool]:
    return Evidence(
        state=state,
        source=source,
        observed_at=observed_at,
        max_age=max_age,
        detail="bootloader lock state",
        boot_id="boot-1",
    )


def _tool(
    *,
    name: str = "fastboot",
    sha256_match: bool | None = True,
    sha256_pinned: bool = True,
    version: str | None = "37.0.3",
    min_version: str | None = "37.0.3",
    meets_minimum: bool | None = True,
    gpl: bool = False,
) -> ToolReport:
    return ToolReport(
        name=name,
        path=Path("fastboot"),
        license="Apache-2.0",
        gpl=gpl,
        version=version,
        sha256="a" * 64,
        sha256_pinned=sha256_pinned,
        sha256_match=sha256_match,
        min_version=min_version,
        meets_minimum=meets_minimum,
        detail="test report",
    )


def _context(**overrides: object) -> SafetyContext:
    base = SafetyContext(
        provenance=ProvenanceResult(
            Tri.TRUE,
            package_id="pkg-1",
            reasons=("archive and entry hashes match the local index",),
        ),
        tool=_tool(),
        expected_tool="fastboot",
        lock_state=_lock(Tri.TRUE),
        avb_key=CheckState(Tri.TRUE, "trusted key matches", ("ev-key",)),
        avb_chain=CheckState(Tri.TRUE, "AVB chain verified", ("ev-avb",)),
        rollback_oracle=CheckState(Tri.TRUE, "rollback index is safe", ("ev-rollback",)),
        device_identity=DeviceIdentity("panther", "US", "rev-1"),
        package_identity=PackageIdentity("panther", "US", "rev-1"),
        identity_evidence_ids=("ev-device",),
    )
    return replace(base, **overrides)


def _rule(report: SafetyReport, rule_id: str) -> RuleResult:
    result = report.rule(rule_id)
    assert result is not None
    return result


def test_sr001_true_when_identity_matches() -> None:
    report = ENGINE.evaluate(_context(), now=NOW)
    result = _rule(report, "SR-001")
    assert result.state is Tri.TRUE
    assert result.evidence_ids == ("ev-device",)
    assert any("build fingerprint" in warning for warning in result.warnings)


def test_sr001_false_on_product_mismatch() -> None:
    context = _context(
        package_identity=PackageIdentity("cheetah", "US", "rev-1"),
    )
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-001")
    assert result.state is Tri.FALSE
    assert "product" in result.reason


def test_sr001_unknown_when_package_does_not_declare_variant() -> None:
    context = _context(
        package_identity=PackageIdentity("panther"),
    )
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-001")
    assert result.state is Tri.UNKNOWN
    assert "variant" in result.reason


def test_sr001_unknown_when_device_does_not_expose_variant() -> None:
    context = _context(
        device_identity=DeviceIdentity("panther"),
    )
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-001")
    assert result.state is Tri.UNKNOWN
    assert "not exposed" in result.reason


def test_sr001_unknown_without_evidence_even_when_identities_match() -> None:
    context = _context(identity_evidence_ids=())
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-001")
    assert result.state is Tri.UNKNOWN
    assert "no evidence references" in result.reason


def test_sr001_mismatch_without_evidence_is_unknown() -> None:
    context = _context(
        package_identity=PackageIdentity("cheetah", "US", "rev-1"),
        identity_evidence_ids=(),
    )
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-001")
    assert result.state is Tri.UNKNOWN
    assert "without evidence references" in result.reason


def test_sr002_true_cites_provenance_and_warns_about_authenticity() -> None:
    result = _rule(ENGINE.evaluate(_context(), now=NOW), "SR-002")
    assert result.state is Tri.TRUE
    assert result.evidence_ids
    assert any("not a signature" in warning for warning in result.warnings)


def test_sr002_false_on_entry_mismatch() -> None:
    context = _context(
        provenance=ProvenanceResult(
            Tri.FALSE,
            package_id="pkg-1",
            reasons=("entry hash mismatch: boot.img",),
        )
    )
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-002")
    assert result.state is Tri.FALSE
    assert "boot.img" in result.reason


def test_sr002_unknown_when_package_is_not_indexed() -> None:
    context = _context(
        provenance=ProvenanceResult(
            Tri.UNKNOWN,
            reasons=("archive sha256 is not in the local index",),
        )
    )
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-002")
    assert result.state is Tri.UNKNOWN
    assert "not in the local index" in result.reason


def test_sr002_true_without_package_id_is_unknown() -> None:
    context = _context(provenance=ProvenanceResult(Tri.TRUE, reasons=("matched",)))
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-002")
    assert result.state is Tri.UNKNOWN
    assert "package id" in result.reason


def test_sr003_is_unknown_when_avb_check_is_absent() -> None:
    context = _context(avb_chain=None)
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-003")
    assert result.state is Tri.UNKNOWN
    assert "AVB chain" in result.reason


def test_sr003_true_requires_evidence() -> None:
    context = _context(avb_chain=CheckState(Tri.TRUE, "chain verified"))
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-003")
    assert result.state is Tri.UNKNOWN
    assert "no evidence references" in result.reason


def test_sr003_false_with_evidence_blocks() -> None:
    context = _context(avb_chain=CheckState(Tri.FALSE, "chain digest mismatch", ("ev-avb",)))
    report = ENGINE.evaluate(context, now=NOW)
    result = _rule(report, "SR-003")
    assert result.state is Tri.FALSE
    assert report.can_proceed is False
    assert "SR-003" in report.blocking


def test_sr004_passes_through_a_verified_rollback_check() -> None:
    result = _rule(ENGINE.evaluate(_context(), now=NOW), "SR-004")
    assert result.state is Tri.TRUE
    assert result.evidence_ids == ("ev-rollback",)


def test_sr012_true_when_hash_matches() -> None:
    result = _rule(ENGINE.evaluate(_context(), now=NOW), "SR-012")
    assert result.state is Tri.TRUE
    assert "SHA-256" in result.reason


def test_sr012_false_on_hash_mismatch() -> None:
    context = _context(tool=_tool(sha256_match=False))
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-012")
    assert result.state is Tri.FALSE
    assert "SHA-256" in result.reason


def test_sr012_false_on_version_below_minimum() -> None:
    context = _context(tool=_tool(version="36.0.0", meets_minimum=False))
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-012")
    assert result.state is Tri.FALSE
    assert "below" in result.reason


def test_sr012_true_by_minimum_version_without_pinned_hash() -> None:
    context = _context(
        tool=_tool(
            sha256_match=None,
            sha256_pinned=False,
            min_version="37.0.3",
            meets_minimum=True,
        )
    )
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-012")
    assert result.state is Tri.TRUE
    assert "pinned minimum" in result.reason


def test_sr012_unknown_for_unpinned_version() -> None:
    context = _context(
        tool=_tool(
            sha256_match=None,
            sha256_pinned=False,
            version="99.1.2",
            min_version=None,
            meets_minimum=None,
        )
    )
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-012")
    assert result.state is Tri.UNKNOWN
    assert "not pinned" in result.reason


def test_sr012_false_for_wrong_tool_name() -> None:
    context = _context(tool=_tool(name="odin"))
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-012")
    assert result.state is Tri.FALSE
    assert "expected tool" in result.reason


def test_sr012_warns_for_gpl_tools() -> None:
    context = _context(tool=_tool(gpl=True))
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-012")
    assert result.state is Tri.TRUE
    assert any("GPL" in warning for warning in result.warnings)


def test_sr013_unlocked_passes_with_warning() -> None:
    context = _context(avb_key=None)
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-013")
    assert result.state is Tri.TRUE
    assert any("unlocked" in warning for warning in result.warnings)
    assert any("not checked" in warning for warning in result.warnings)


def test_sr013_locked_with_verified_key_passes() -> None:
    context = _context(lock_state=_lock(Tri.FALSE))
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-013")
    assert result.state is Tri.TRUE
    assert "ev-key" in result.evidence_ids


def test_sr013_locked_without_key_check_is_unknown() -> None:
    context = _context(lock_state=_lock(Tri.FALSE), avb_key=None)
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-013")
    assert result.state is Tri.UNKNOWN
    assert "locked" in result.reason


def test_sr013_locked_with_mismatched_key_is_false() -> None:
    context = _context(
        lock_state=_lock(Tri.FALSE),
        avb_key=CheckState(Tri.FALSE, "trusted key does not match", ("ev-key",)),
    )
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-013")
    assert result.state is Tri.FALSE


def test_sr013_key_match_without_evidence_is_unknown() -> None:
    context = _context(
        lock_state=_lock(Tri.FALSE),
        avb_key=CheckState(Tri.TRUE, "trusted key matches"),
    )
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-013")
    assert result.state is Tri.UNKNOWN
    assert "no evidence references" in result.reason


def test_sr013_stale_lock_state_is_unknown() -> None:
    context = _context(
        lock_state=_lock(
            Tri.TRUE,
            observed_at=NOW - timedelta(minutes=10),
            max_age=timedelta(minutes=5),
        )
    )
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-013")
    assert result.state is Tri.UNKNOWN
    assert "stale" in result.reason


def test_sr013_inferred_lock_state_is_unknown() -> None:
    context = _context(lock_state=_lock(Tri.TRUE, source=EvidenceSource.INFERRED))
    result = _rule(ENGINE.evaluate(context, now=NOW), "SR-013")
    assert result.state is Tri.UNKNOWN
    assert "inferred" in result.reason


def test_unknown_rule_does_not_allow_proceeding() -> None:
    context = _context(avb_chain=None)
    report = ENGINE.evaluate(context, now=NOW)
    assert report.verdict is Tri.UNKNOWN
    assert report.can_proceed is False
    assert "SR-003" in report.blocking


def test_override_keeps_verdict_unknown_but_allows_proceeding() -> None:
    context = _context(
        provenance=ProvenanceResult(
            Tri.UNKNOWN,
            reasons=("archive sha256 is not in the local index",),
        )
    )
    base = ENGINE.evaluate(context, now=NOW)
    assert base.can_proceed is False
    assert "SR-002" in base.blocking

    request = OverrideRequest(
        "SR-002",
        "alice",
        "package supplied by the shop lead; hashes to be added",
        NOW,
    )
    report = ENGINE.evaluate(context, overrides=(request,), now=NOW)
    assert report.verdict is Tri.UNKNOWN
    assert report.can_proceed is True
    assert report.blocking == ()
    assert report.evidence_snapshot_sha256 == base.evidence_snapshot_sha256

    override = report.overrides[0]
    assert override.rule_id == "SR-002"
    assert override.operator == "alice"
    assert override.timestamp == NOW.isoformat()
    assert override.evidence_snapshot_sha256 == report.evidence_snapshot_sha256
    assert override.report_text == report.report_text
    assert "hashes to be added" in report.report_text
    assert "does not turn UNKNOWN into TRUE" in report.report_text


def test_false_may_never_be_overridden() -> None:
    context = _context(
        provenance=ProvenanceResult(
            Tri.FALSE,
            package_id="pkg-1",
            reasons=("entry hash mismatch: boot.img",),
        )
    )
    request = OverrideRequest("SR-002", "alice", "attempted bypass of a mismatch", NOW)
    with pytest.raises(SafetyError, match="FALSE may never be overridden"):
        ENGINE.evaluate(context, overrides=(request,), now=NOW)


def test_true_rule_does_not_need_an_override() -> None:
    request = OverrideRequest("SR-002", "alice", "redundant override of a true rule", NOW)
    with pytest.raises(SafetyError, match="already TRUE"):
        ENGINE.evaluate(_context(), overrides=(request,), now=NOW)


def test_non_overridable_unknown_cannot_be_overridden() -> None:
    context = _context(avb_chain=None)
    request = OverrideRequest("SR-003", "alice", "skip the AVB gate for this repair", NOW)
    with pytest.raises(SafetyError, match="does not allow UNKNOWN overrides"):
        ENGINE.evaluate(context, overrides=(request,), now=NOW)


def test_duplicate_overrides_are_rejected() -> None:
    context = _context(provenance=ProvenanceResult(Tri.UNKNOWN, reasons=("not indexed",)))
    request = OverrideRequest("SR-002", "alice", "package supplied by the shop lead", NOW)
    with pytest.raises(SafetyError, match="duplicate override"):
        ENGINE.evaluate(context, overrides=(request, request), now=NOW)


def test_override_reason_must_be_typed_and_long_enough() -> None:
    with pytest.raises(SafetyError, match="at least 10 characters"):
        OverrideRequest("SR-002", "alice", "short", NOW)


def test_override_timestamp_must_be_timezone_aware() -> None:
    with pytest.raises(SafetyError, match="timezone-aware"):
        OverrideRequest(
            "SR-002", "alice", "package supplied by the shop lead", datetime(2026, 1, 1)
        )


def test_report_is_deterministic_and_json_serializable() -> None:
    first = ENGINE.evaluate(_context(), now=NOW)
    second = ENGINE.evaluate(_context(), now=NOW)
    assert first.to_dict() == second.to_dict()
    assert first.report_text == second.report_text
    assert first.verdict is Tri.TRUE
    assert first.can_proceed is True
    assert first.blocking == ()
    assert first.rule("SR-999") is None
    encoded = json.dumps(first.to_dict(), sort_keys=True)
    assert '"verdict": "TRUE"' in encoded
    assert [result.rule_id for result in first.rules] == sorted(
        spec.rule_id for spec, _ in DEFAULT_RULES
    )


def test_naive_now_is_rejected() -> None:
    with pytest.raises(SafetyError, match="timezone-aware"):
        ENGINE.evaluate(_context(), now=datetime(2026, 11, 25, 12, 0))


def test_override_for_unknown_rule_is_rejected() -> None:
    request = OverrideRequest("SR-999", "alice", "override of a rule that does not exist", NOW)
    with pytest.raises(SafetyError, match="unknown rule"):
        ENGINE.evaluate(_context(), overrides=(request,), now=NOW)


def test_engine_rejects_duplicate_or_empty_rule_sets() -> None:
    with pytest.raises(SafetyError, match="at least one"):
        SafetyEngine(())
    with pytest.raises(SafetyError, match="duplicate safety rule"):
        SafetyEngine((DEFAULT_RULES[0], DEFAULT_RULES[0]))


def test_rule_exception_becomes_unknown() -> None:
    def boom(_context: SafetyContext, _now: datetime, _spec: RuleSpec) -> RuleResult:
        raise RuntimeError("boom")

    engine = SafetyEngine(((RuleSpec("SR-900", "boom"), boom),))
    report = engine.evaluate(SafetyContext(), now=NOW)
    result = _rule(report, "SR-900")
    assert result.state is Tri.UNKNOWN
    assert "RuntimeError: boom" in result.reason
    assert report.can_proceed is False


def test_rule_must_return_its_own_id() -> None:
    def wrong(_context: SafetyContext, _now: datetime, _spec: RuleSpec) -> RuleResult:
        return RuleResult(rule_id="SR-901", state=Tri.TRUE, reason="wrong")

    engine = SafetyEngine(((RuleSpec("SR-900", "wrong"), wrong),))
    with pytest.raises(SafetyError, match="returned a result"):
        engine.evaluate(SafetyContext(), now=NOW)


def test_rule_must_return_the_registered_override_policy() -> None:
    def wrong(_context: SafetyContext, _now: datetime, spec: RuleSpec) -> RuleResult:
        return RuleResult(
            rule_id=spec.rule_id,
            state=Tri.UNKNOWN,
            reason="wrong override policy",
            overridable=True,
        )

    engine = SafetyEngine(((RuleSpec("SR-900", "wrong policy"), wrong),))
    with pytest.raises(SafetyError, match="override policy"):
        engine.evaluate(SafetyContext(), now=NOW)


def test_rule_spec_rejects_invalid_or_overridable_critical_rules() -> None:
    with pytest.raises(SafetyError, match="invalid rule id"):
        RuleSpec("SR-1", "bad id")
    with pytest.raises(SafetyError, match="must have a title"):
        RuleSpec("SR-900", " ")
    with pytest.raises(SafetyError, match="critical"):
        RuleSpec("SR-003", "AVB", unknown_overridable=True)


def test_identity_and_check_inputs_reject_empty_values() -> None:
    with pytest.raises(SafetyError, match="product"):
        DeviceIdentity(" ")
    with pytest.raises(SafetyError, match="variant"):
        PackageIdentity("panther", variant="")
    with pytest.raises(SafetyError, match="detail"):
        CheckState(Tri.TRUE, " ")
    with pytest.raises(SafetyError, match="evidence ids"):
        CheckState(Tri.TRUE, "ok", ("",))
