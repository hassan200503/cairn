"""Read-only wizard stage implementations.

Each stage is a pure-ish function over ``WizardRun``: it consumes the inputs that
earlier stages produced and returns one ``StageResult``. The runner owns ordering,
resume policy, and persistence. A stage never writes to a device.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from dataclasses import replace as dataclass_replace
from datetime import datetime
from pathlib import Path

from cairn import __version__
from cairn.adapters.fastboot import IDENTITY_VARS, STATE_VARS, ProbeResult
from cairn.adapters.prepare import (
    PreparedFastboot,
    PrepareError,
    prepare_fastboot,
    tool_binding_from_payload,
)
from cairn.approval import (
    MAX_TOKEN_BYTES,
    ApprovalError,
    ApprovalInputs,
    ToolBinding,
    new_nonce,
    verify_approval,
)
from cairn.catalog import CatalogError, DeviceEntry, parse_catalog
from cairn.core.evidence import Evidence, EvidenceSource
from cairn.core.tristate import Tri
from cairn.host.doctor import SOAK_ATTEMPTS_DEFAULT, HostDoctor
from cairn.package.archive import PackageError, PackageManifest, load_package, sha256_file
from cairn.plan.planner import (
    Plan,
    PlanError,
    PlanFacts,
    PlanOptions,
    SlotPolicy,
    build_plan,
)
from cairn.provenance.avb import (
    AvbError,
    VbmetaImage,
    load_vbmeta,
    verify_vbmeta_chain,
    verify_vbmeta_signature,
)
from cairn.provenance.hash_index import (
    HashIndex,
    HashIndexError,
    ProvenanceResult,
    load_hash_index,
    verify_manifest,
)
from cairn.rollback.device import DeviceRollbackRead, read_stored_rollback_indexes
from cairn.rollback.oracle import (
    RollbackError,
    RollbackReport,
    evaluate_avb_rollback,
)
from cairn.safety.engine import (
    CheckState,
    DeviceIdentity,
    PackageIdentity,
    SafetyContext,
    SafetyEngine,
    SafetyReport,
)
from cairn.tools.runner import ToolRunner
from cairn.wizard.session import (
    ApprovalBundle,
    DeviceRecord,
    StageOutcome,
    WizardError,
    WizardSession,
    new_session,
)


@dataclass(frozen=True, slots=True)
class WizardOptions:
    package: Path
    index: Path
    state: Path
    fastboot: Path | None = None
    serial: str | None = None
    simulate: Path | None = None
    device_fingerprint: str | None = None
    soak: int = SOAK_ATTEMPTS_DEFAULT
    vbmeta: Path | None = None
    chain: Mapping[str, Path] = field(default_factory=dict)
    key: Path | None = None
    catalog: Path | None = None
    catalog_key: Path | None = None
    catalog_signature: Path | None = None
    lock_state: str | None = None
    stored: Mapping[int, int] = field(default_factory=dict)
    slot_policy: SlotPolicy = SlotPolicy.CURRENT
    rollback_slot: str | None = None
    wipe: bool = False
    retrofit_force: bool = False
    tools: tuple[ToolBinding, ...] = ()
    approval: Path | None = None
    approval_key: Path | None = None
    resume: bool = False
    force: bool = False


@dataclass(slots=True)
class WizardRun:
    options: WizardOptions
    prepared: PreparedFastboot | None = None
    prepare_error: str | None = None
    manifest: PackageManifest | None = None
    index: HashIndex | None = None
    index_sha256: str | None = None
    provenance: ProvenanceResult | None = None
    probe: ProbeResult | None = None
    device: DeviceRecord | None = None
    lock_evidence: Evidence[str] | None = None
    vbmeta: VbmetaImage | None = None
    chain: Mapping[str, VbmetaImage] = field(default_factory=dict)
    avb_check: CheckState | None = None
    rollback_read: DeviceRollbackRead | None = None
    rollback_report: RollbackReport | None = None
    rollback_check: CheckState | None = None
    plan: Plan | None = None
    pre_safety: SafetyReport | None = None
    bundle: ApprovalBundle | None = None
    tool_binding: ToolBinding | None = None
    safety_context: SafetyContext | None = None
    approval_check: CheckState | None = None
    post_safety: SafetyReport | None = None


@dataclass(frozen=True, slots=True)
class StageResult:
    stage: str
    outcome: StageOutcome
    detail: str
    input_fingerprint: str | None = None
    evidence_ids: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    payload: Mapping[str, object] | None = None


@dataclass(frozen=True, slots=True)
class ReloadedPlan:
    manifest: PackageManifest
    index: HashIndex
    provenance: ProvenanceResult
    plan: Plan


def stage_doctor(
    run: WizardRun,
    *,
    runner: ToolRunner,
    now: datetime,
) -> StageResult:
    prepared = _ensure_prepared(run, runner)
    simulated = prepared.simulated if prepared is not None else run.options.simulate is not None
    prefix = prepared.prefix if prepared is not None else None
    label = prepared.label if prepared is not None else (run.prepare_error or "not found")
    extra_env = prepared.extra_env if prepared is not None else None
    report = HostDoctor(runner).run(
        fastboot_prefix=prefix,
        fastboot_label=label,
        adb_path=None,
        serial=run.options.serial,
        soak_attempts=run.options.soak,
        simulated=simulated,
        fastboot_extra_env=extra_env,
    )
    payload = report.to_dict()
    if simulated:
        outcome = StageOutcome.SIMULATED
        detail = "simulated host and link checks; not device evidence"
    elif report.verdict is Tri.TRUE:
        outcome = StageOutcome.PASS
        detail = "required host checks passed"
    elif report.verdict is Tri.FALSE:
        outcome = StageOutcome.FAIL
        detail = "a required host check failed; do not continue on this host"
    else:
        outcome = StageOutcome.BLOCKED
        detail = "required host checks did not complete"
    warnings = () if run.prepare_error is None else (run.prepare_error,)
    return StageResult(
        stage="doctor",
        outcome=outcome,
        detail=detail,
        input_fingerprint=doctor_fingerprint(run.options),
        warnings=warnings,
        payload=payload,
    )


def stage_inspect(run: WizardRun, *, now: datetime) -> StageResult:
    try:
        manifest = load_package(
            run.options.package,
            hash_files=True,
            hash_archive=True,
        )
    except PackageError as exc:
        return StageResult("inspect", StageOutcome.FAIL, str(exc))
    run.manifest = manifest
    fingerprint = _fingerprint(
        "inspect",
        str(manifest.path),
        str(manifest.archive_size),
        manifest.archive_sha256 or "",
    )
    return StageResult(
        stage="inspect",
        outcome=StageOutcome.PASS,
        detail=(
            f"{manifest.kind.value} package with {len(manifest.entries)} entries; "
            "archive was not extracted"
        ),
        input_fingerprint=fingerprint,
        warnings=manifest.warnings,
        payload=manifest.to_dict(),
    )


def stage_provenance(run: WizardRun, *, now: datetime) -> StageResult:
    if run.manifest is None:
        return StageResult(
            "provenance", StageOutcome.BLOCKED, "package inspection did not complete"
        )
    try:
        index = load_hash_index(run.options.index)
        index_sha256 = sha256_file(run.options.index)
        result = verify_manifest(index, run.manifest)
    except (HashIndexError, OSError) as exc:
        return StageResult("provenance", StageOutcome.FAIL, str(exc))
    run.index = index
    run.index_sha256 = index_sha256
    run.provenance = result
    if result.state is Tri.TRUE:
        outcome = StageOutcome.PASS
    elif result.state is Tri.FALSE:
        outcome = StageOutcome.FAIL
    else:
        outcome = StageOutcome.BLOCKED
    return StageResult(
        stage="provenance",
        outcome=outcome,
        detail="; ".join(result.reasons) or "no provenance detail",
        input_fingerprint=_fingerprint("provenance", index_sha256, result.state.name),
        evidence_ids=(_stable_id("provenance", result.state.name, *result.reasons),),
        payload=result.to_dict() | {"index_sha256": index_sha256},
    )


def stage_probe(run: WizardRun, *, runner: ToolRunner, now: datetime) -> StageResult:
    options = run.options
    device: DeviceRecord | None
    if options.device_fingerprint is not None:
        device = DeviceRecord(
            source="caller",
            simulated=False,
            nonce=new_nonce(),
            fingerprint_sha256=options.device_fingerprint,
            lock_state=options.lock_state,
        )
        run.device = device
        return StageResult(
            stage="probe",
            outcome=StageOutcome.SKIPPED,
            detail="caller-supplied device fingerprint; no device probe was performed",
            warnings=("a caller-supplied fingerprint is not device evidence",),
            payload=device.to_dict(),
        )

    prepared = _ensure_prepared(run, runner)
    if prepared is None:
        return StageResult(
            "probe",
            StageOutcome.BLOCKED,
            run.prepare_error or "fastboot is unavailable; the device was not probed",
        )
    client = prepared.client
    result = client.probe(
        serial=options.serial,
        expected_serial=options.serial,
        source=EvidenceSource.INFERRED if prepared.simulated else EvidenceSource.PROBED,
        now=now,
    )
    run.probe = result
    device = _device_from_probe(result, prepared.simulated, now)
    run.device = device
    run.lock_evidence = _lock_evidence(result, prepared.simulated)
    payload = _probe_payload(result, prepared, device)
    if prepared.simulated:
        outcome = StageOutcome.SIMULATED
        detail = "simulated transcript replay; this is not device evidence"
    elif not result.tool_ok:
        outcome = StageOutcome.FAIL
        detail = f"device probe failed: {result.detail}"
    elif device is None or device.fingerprint_sha256 is None:
        outcome = StageOutcome.BLOCKED
        detail = "probe did not produce a usable identity fingerprint"
    else:
        outcome = StageOutcome.PASS
        detail = "fresh read-only probe completed"
    warnings = () if device is None else _device_warnings(device)
    return StageResult(
        stage="probe",
        outcome=outcome,
        detail=detail,
        input_fingerprint=probe_fingerprint(run.options),
        evidence_ids=() if device is None else device.identity_evidence_ids,
        warnings=warnings,
        payload=payload,
    )


def _catalog_entry_for_run(run: WizardRun) -> tuple[DeviceEntry | None, str | None]:
    """Resolve the catalog device entry for this run, with the catalog sha256.

    The entry is selected by the caller-supplied device fingerprint or, when
    the device was probed, by the probed fingerprint from the session device.
    A caller-supplied detached signature is verified against the exact file
    bytes before anything from the catalog is used.
    """
    options = run.options
    if options.catalog is None:
        return None, None
    fingerprint = options.device_fingerprint
    if fingerprint is None and run.device is not None:
        fingerprint = run.device.fingerprint_sha256
    if fingerprint is None:
        return None, None
    catalog_bytes = options.catalog.read_bytes()
    catalog_sha256 = hashlib.sha256(catalog_bytes).hexdigest()
    hmac_key: bytes | None = None
    signature: str | None = None
    if options.catalog_key is not None:
        hmac_key = options.catalog_key.read_bytes()
        if options.catalog_signature is None:
            raise CatalogError("--catalog-signature is required with --catalog-key")
        signature = options.catalog_signature.read_text(encoding="ascii").strip()
    if hmac_key is not None and signature is not None:
        expected = hmac.new(hmac_key, catalog_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature.lower()):
            raise CatalogError("catalog signature does not match its bytes")
    catalog = parse_catalog(json.loads(catalog_bytes.decode("utf-8")))
    return catalog.device_by_fingerprint(fingerprint), catalog_sha256


def _anchored_key(run: WizardRun) -> tuple[bytes | None, str | None, str | None]:
    """Resolve the expected AVB key from a catalog entry (T30).

    The catalog anchors *which key* is expected and is caller-supplied input,
    never device evidence, so the stage keeps its warning.
    """
    if run.options.catalog is None or run.options.key is not None:
        return None, None, None
    entry, catalog_sha256 = _catalog_entry_for_run(run)
    if entry is None:
        return None, None, catalog_sha256
    if entry.trusted_key is None:
        return None, None, catalog_sha256
    return entry.trusted_key, entry.source, catalog_sha256


def stage_avb(run: WizardRun, *, now: datetime) -> StageResult:
    options = run.options
    if options.vbmeta is None:
        return StageResult(
            "avb",
            StageOutcome.SKIPPED,
            "no VBMeta image was supplied; AVB checks were skipped",
        )
    try:
        image = load_vbmeta(options.vbmeta)
        chain = {name: load_vbmeta(path) for name, path in options.chain.items()}
        expected_key = None if options.key is None else _read_key(options.key)
        anchored_source: str | None = None
        catalog_sha256: str | None = None
        if options.key is None and options.catalog is not None:
            expected_key, anchored_source, catalog_sha256 = _anchored_key(run)
        if chain:
            report = verify_vbmeta_chain(image, chain, expected_key=expected_key)
            valid = report.valid
            detail = report.reason
            payload = report.to_dict()
            signature = report.signature
        else:
            signature = verify_vbmeta_signature(image, expected_key=expected_key)
            valid = signature.valid
            detail = signature.reason
            payload = signature.to_dict()
    except (AvbError, OSError, CatalogError, ValueError) as exc:
        return StageResult("avb", StageOutcome.BLOCKED, f"AVB input could not be read: {exc}")
    run.vbmeta = image
    run.chain = chain
    warnings: tuple[str, ...] = ()
    if anchored_source is not None and catalog_sha256 is not None:
        payload["trusted_key_source"] = anchored_source
        payload["catalog_sha256"] = catalog_sha256
        warnings = ("the expected key came from a caller-supplied catalog entry",)
    elif catalog_sha256 is not None:
        payload["catalog_sha256"] = catalog_sha256
        warnings = (
            "the catalog had no entry with an embedded key for this fingerprint; "
            "no key was anchored",
        )
    if valid is False:
        check = _check(Tri.FALSE, detail, payload, ("AVB signature or chain is invalid",))
        outcome = StageOutcome.FAIL
    elif valid is None:
        check = _check(Tri.UNKNOWN, detail, payload)
        outcome = StageOutcome.BLOCKED
    elif expected_key is None:
        no_key_warnings = [
            "internally consistent is not trust; supply --key to compare a trusted key"
        ]
        if catalog_sha256 is not None:
            no_key_warnings.append(
                "the catalog had no entry with an embedded key for this fingerprint; "
                "no key was anchored"
            )
        check = _check(
            Tri.UNKNOWN,
            "AVB is internally consistent but no expected key was supplied",
            payload,
            tuple(no_key_warnings),
        )
        warnings = check.warnings
        outcome = StageOutcome.BLOCKED
    else:
        true_warnings = ["the expected key is caller-supplied and not device-bound"]
        if anchored_source is not None:
            true_warnings.append("the expected key came from a caller-supplied catalog entry")
        check = _check(
            Tri.TRUE,
            detail,
            payload,
            tuple(true_warnings),
        )
        warnings = check.warnings
        outcome = StageOutcome.PASS
    run.avb_check = check
    return StageResult(
        stage="avb",
        outcome=outcome,
        detail=check.detail,
        evidence_ids=check.evidence_ids,
        warnings=warnings,
        payload=payload,
    )


def stage_rollback(run: WizardRun, *, runner: ToolRunner, now: datetime) -> StageResult:
    options = run.options
    if run.vbmeta is None:
        return StageResult(
            "rollback",
            StageOutcome.SKIPPED,
            "no VBMeta image was supplied; rollback counters were not evaluated",
        )
    catalog_bounds: dict[int, tuple[int | None, int | None]] = {}
    bounds_source: str | None = None
    if options.catalog is not None:
        try:
            entry, _ = _catalog_entry_for_run(run)
        except (OSError, CatalogError, ValueError) as exc:
            return StageResult(
                "rollback", StageOutcome.BLOCKED, f"catalog could not be read: {exc}"
            )
        if entry is not None and entry.rollback_bounds:
            catalog_bounds = {
                location: (bound.minimum, bound.maximum)
                for location, bound in entry.rollback_bounds.items()
            }
            bounds_source = entry.source
    if not options.stored and not options.simulate and not catalog_bounds:
        prepared = _ensure_prepared(run, runner)
        if prepared is None or run.device is None or run.device.source == "caller":
            return StageResult(
                "rollback",
                StageOutcome.SKIPPED,
                "no stored indexes or usable device read; rollback counters were not evaluated",
            )
    stored: Mapping[int, int] | None
    stored_source: str
    simulated = False
    if options.stored:
        stored = options.stored
        stored_source = "caller"
    elif catalog_bounds:
        # Catalog bounds alone can prove safety or a downgrade (STATE.md,
        # SR-004); no device read is needed for a verdict in that case.
        stored = None
        stored_source = "catalog bounds"
    else:
        prepared = _ensure_prepared(run, runner)
        if prepared is None:
            return StageResult(
                "rollback",
                StageOutcome.SKIPPED,
                "fastboot is unavailable; stored rollback indexes were not read",
            )
        read = read_stored_rollback_indexes(
            prepared.client,
            serial=options.serial,
            slot=options.rollback_slot,
        )
        run.rollback_read = read
        stored = read.stored
        stored_source = "fastboot getvar all"
        simulated = prepared.simulated
    try:
        report = evaluate_avb_rollback(
            run.vbmeta,
            run.chain,
            slot=options.rollback_slot,
            stored=stored,
            stored_source=stored_source,
            catalog_bounds=catalog_bounds or None,
        )
    except RollbackError as exc:
        return StageResult("rollback", StageOutcome.BLOCKED, str(exc))
    if run.rollback_read is not None:
        extra = run.rollback_read.warnings + run.rollback_read.unresolved
        if extra:
            report = dataclass_replace(report, warnings=report.warnings + extra)
    run.rollback_report = report
    check = _check(
        report.state,
        "; ".join(report.reasons) or "rollback counters were evaluated",
        report.to_dict(),
        report.warnings
        + (
            ("rollback bounds came from a caller-supplied catalog entry",)
            if bounds_source is not None
            else ()
        ),
    )
    run.rollback_check = check
    if report.state is Tri.FALSE:
        outcome = StageOutcome.FAIL
    elif simulated:
        outcome = StageOutcome.SIMULATED
    elif report.state is Tri.TRUE:
        outcome = StageOutcome.PASS
    else:
        outcome = StageOutcome.BLOCKED
    payload = report.to_dict() | {"stored_source": stored_source, "simulated": simulated}
    if bounds_source is not None:
        payload["rollback_bounds_source"] = bounds_source
    return StageResult(
        stage="rollback",
        outcome=outcome,
        detail=check.detail,
        input_fingerprint=rollback_fingerprint(run.options),
        evidence_ids=check.evidence_ids,
        warnings=check.warnings,
        payload=payload,
    )


def stage_plan(run: WizardRun, *, runner: ToolRunner, now: datetime) -> StageResult:
    if run.manifest is None or run.provenance is None:
        return StageResult(
            "plan",
            StageOutcome.BLOCKED,
            "package inspection or provenance did not complete",
        )
    _ensure_prepared(run, runner)
    facts = PlanFacts(
        slot_count=None if run.device is None else run.device.slot_count,
        current_slot=None if run.device is None else run.device.current_slot,
    )
    options = PlanOptions(
        wipe=run.options.wipe,
        slot_policy=run.options.slot_policy,
        retrofit_force=run.options.retrofit_force,
    )
    try:
        plan = build_plan(run.manifest, run.provenance, options=options, facts=facts)
    except PlanError as exc:
        return StageResult("plan", StageOutcome.FAIL, str(exc))
    run.plan = plan

    package_identity, identity_warnings = _package_identity(run.manifest)
    device_identity = _device_identity(run.device)
    tool_binding = _fastboot_binding(run.prepared)
    tools, merge_error = _merge_tools(run.options.tools, tool_binding)
    if merge_error is not None:
        return StageResult("plan", StageOutcome.BLOCKED, merge_error)
    run.tool_binding = tool_binding
    context = SafetyContext(
        provenance=run.provenance,
        tool=None if run.prepared is None else run.prepared.tool_report,
        expected_tool="fastboot",
        lock_state=run.lock_evidence,
        avb_key=None,
        avb_chain=run.avb_check,
        rollback_oracle=run.rollback_check,
        device_identity=device_identity,
        package_identity=package_identity,
        identity_evidence_ids=() if run.device is None else run.device.identity_evidence_ids,
        approval=None,
    )
    pre_safety = SafetyEngine.pre_approval().evaluate(context)
    run.pre_safety = pre_safety
    run.safety_context = context
    warnings = (*identity_warnings, *_report_warnings(pre_safety))
    bundle: ApprovalBundle | None = None
    if run.device is None:
        detail = "no device record; approval cannot be bound"
        outcome = StageOutcome.BLOCKED
    else:
        binding = run.device.binding()
        if binding is None:
            detail = "device fingerprint or nonce is unavailable; approval cannot be bound"
            outcome = StageOutcome.BLOCKED
        else:
            try:
                inputs = ApprovalInputs.from_manifest(
                    run.manifest,
                    plan,
                    pre_safety,
                    binding,
                    tools=tools,
                )
            except ApprovalError as exc:
                return StageResult("plan", StageOutcome.BLOCKED, str(exc))
            bundle = ApprovalBundle(
                plan_sha256=inputs.plan_sha256,
                evidence_snapshot_sha256=inputs.evidence_snapshot_sha256,
                archive_sha256=inputs.archive_sha256,
                package_hashes=inputs.package_hashes,
                tools=inputs.tools,
                pre_safety=pre_safety.to_dict(),
                plan_options=plan.options.to_dict(),
                plan_facts=plan.facts.to_dict(),
            )
            run.bundle = bundle
            if pre_safety.verdict is Tri.FALSE:
                detail = "pre-approval safety has a FALSE rule"
                outcome = StageOutcome.FAIL
            elif plan.executable and pre_safety.can_proceed:
                detail = "plan is structurally executable and the pre-approval safety gate passes"
                outcome = StageOutcome.PASS
            else:
                detail = (
                    "plan or pre-approval safety is not executable; approval will not be issued"
                )
                outcome = StageOutcome.BLOCKED
    payload: dict[str, object] = {
        "plan": plan.to_dict(),
        "safety": pre_safety.to_dict(),
        "package_identity": _identity_payload(package_identity),
        "device_identity": _identity_payload(device_identity),
    }
    return StageResult(
        stage="plan",
        outcome=outcome,
        detail=detail,
        input_fingerprint=_fingerprint(
            "plan",
            plan.plan_sha256,
            pre_safety.evidence_snapshot_sha256,
            "" if bundle is None else bundle.archive_sha256,
        ),
        evidence_ids=(_stable_id("plan", plan.plan_sha256),),
        warnings=warnings,
        payload=payload,
    )


def stage_approval(run: WizardRun, *, now: datetime) -> StageResult:
    options = run.options
    if options.approval is None:
        run.post_safety = run.pre_safety
        return StageResult(
            "approval",
            StageOutcome.SKIPPED,
            "no approval token was supplied",
        )
    if options.approval_key is None:
        return StageResult(
            "approval",
            StageOutcome.BLOCKED,
            "--approval requires --approval-key",
        )
    if run.bundle is None or run.device is None or run.pre_safety is None:
        return StageResult(
            "approval",
            StageOutcome.BLOCKED,
            "the plan stage did not produce a bindable approval bundle",
        )
    binding = run.device.binding()
    if binding is None:
        return StageResult("approval", StageOutcome.BLOCKED, "device binding is unavailable")
    try:
        token_text = _read_token_text(options.approval)
        key = _read_key(options.approval_key)
        current = ApprovalInputs(
            plan_sha256=run.bundle.plan_sha256,
            evidence_snapshot_sha256=run.bundle.evidence_snapshot_sha256,
            archive_sha256=run.bundle.archive_sha256,
            package_hashes=run.bundle.package_hashes,
            device=binding,
            tools=run.bundle.tools,
        )
        verdict = verify_approval(token_text, key, current)
    except (ApprovalError, OSError) as exc:
        return StageResult("approval", StageOutcome.FAIL, str(exc))
    check = verdict.to_check_state()
    run.approval_check = check
    if run.safety_context is None:
        return StageResult("approval", StageOutcome.BLOCKED, "safety context is unavailable")
    post_safety = SafetyEngine().evaluate(dataclass_replace(run.safety_context, approval=check))
    run.post_safety = post_safety
    if post_safety.evidence_snapshot_sha256 != run.pre_safety.evidence_snapshot_sha256:
        return StageResult(
            "approval",
            StageOutcome.FAIL,
            "post-approval evidence snapshot differs from the pre-approval snapshot",
        )
    if verdict.state is Tri.FALSE:
        outcome = StageOutcome.FAIL
    elif verdict.state is Tri.TRUE:
        outcome = StageOutcome.PASS
    else:
        outcome = StageOutcome.BLOCKED
    return StageResult(
        stage="approval",
        outcome=outcome,
        detail="; ".join(verdict.reasons),
        evidence_ids=check.evidence_ids,
        warnings=check.warnings,
        payload=verdict.to_dict() | {"post_safety": post_safety.to_dict()},
    )


def reload_session_plan(session: WizardSession) -> ReloadedPlan:
    """Rebuild and cross-check the plan recorded in a session."""
    bundle = session.bundle
    if bundle is None:
        raise WizardError("session has no approval bundle")
    if session.archive_sha256 is None or session.index_sha256 is None:
        raise WizardError("session is missing package or index hashes")
    try:
        manifest = load_package(Path(session.package_path), hash_files=True, hash_archive=True)
        index = load_hash_index(Path(session.index_path))
        index_sha256 = sha256_file(Path(session.index_path))
    except (PackageError, HashIndexError, OSError) as exc:
        raise WizardError(f"cannot reload session inputs: {exc}") from exc
    if manifest.archive_sha256 != session.archive_sha256:
        raise WizardError("package archive hash changed since the session was recorded")
    if index_sha256 != session.index_sha256:
        raise WizardError("hash index changed since the session was recorded")
    entries = {entry.name: entry.sha256 for entry in manifest.entries}
    if entries != dict(bundle.package_hashes):
        raise WizardError("package entry hashes changed since the session was recorded")
    provenance = verify_manifest(index, manifest)
    try:
        plan = build_plan(
            manifest,
            provenance,
            options=bundle.options(),
            facts=bundle.facts(),
        )
    except PlanError as exc:
        raise WizardError(f"cannot rebuild the recorded plan: {exc}") from exc
    if plan.plan_sha256 != bundle.plan_sha256:
        raise WizardError("rebuilt plan hash does not match the recorded approval bundle")
    return ReloadedPlan(manifest=manifest, index=index, provenance=provenance, plan=plan)


def new_wizard_session(options: WizardOptions, *, now: datetime | None = None) -> WizardSession:
    return new_session(
        package_path=options.package,
        index_path=options.index,
        cairn_version=__version__,
        now=now,
    )


def _ensure_prepared(run: WizardRun, runner: ToolRunner) -> PreparedFastboot | None:
    if run.prepared is not None:
        return run.prepared
    if run.prepare_error is not None:
        return None
    try:
        run.prepared = prepare_fastboot(
            fastboot=run.options.fastboot,
            simulate=run.options.simulate,
            runner=runner,
        )
    except PrepareError as exc:
        run.prepare_error = str(exc)
        return None
    return run.prepared


def _device_from_probe(
    result: ProbeResult,
    simulated: bool,
    now: datetime,
) -> DeviceRecord | None:
    if not result.tool_ok:
        return None
    facts: dict[str, str] = {}
    identity: dict[str, str | None] = {}
    identity_ids: list[str] = []
    for name in (*IDENTITY_VARS, *STATE_VARS):
        fact = result.fact(name)
        if fact is None:
            continue
        evidence = fact.evidence
        if name in ("serialno", "system-fingerprint", "vendor-fingerprint"):
            continue
        if evidence.value is not None:
            facts[name] = evidence.value
        if (
            name in ("product", "variant", "hw-revision")
            and evidence.state is Tri.TRUE
            and evidence.value is not None
        ):
            identity[name] = evidence.value
            identity_ids.append(evidence.evidence_id)
    serial_fact = result.fact("serialno")
    serial_hash = None
    if serial_fact is not None and serial_fact.evidence.value:
        serial_hash = hashlib.sha256(serial_fact.evidence.value.encode("utf-8")).hexdigest()
    fingerprint = None
    if not simulated:
        try:
            from cairn.approval.device import device_fingerprint

            fingerprint = device_fingerprint(result, now=now)
        except ApprovalError:
            fingerprint = None
    unlocked = result.fact("unlocked")
    lock_state = None
    if unlocked is not None and unlocked.evidence.state is Tri.TRUE:
        lock_state = "unlocked" if unlocked.evidence.value == "yes" else "locked"
    slot_count = None
    slot_fact = result.fact("slot-count")
    if slot_fact is not None and slot_fact.evidence.state is Tri.TRUE:
        try:
            slot_count = int(slot_fact.evidence.value or "", 10)
        except ValueError:
            slot_count = None
    current_slot = None
    current_fact = result.fact("current-slot")
    if current_fact is not None and current_fact.evidence.state is Tri.TRUE:
        current_slot = current_fact.evidence.value
    max_age_s = None
    if result.facts:
        observed = result.facts[0].evidence.max_age
        max_age_s = None if observed is None else observed.total_seconds()
    return DeviceRecord(
        source="simulated" if simulated else "probed",
        simulated=simulated,
        nonce=new_nonce(),
        fingerprint_sha256=fingerprint,
        serial_sha256=serial_hash,
        probed_at=now,
        max_age_s=max_age_s,
        facts=facts,
        identity=identity,
        identity_evidence_ids=tuple(identity_ids),
        lock_state=lock_state,
        slot_count=slot_count,
        current_slot=current_slot,
    )


def _lock_evidence(result: ProbeResult, simulated: bool) -> Evidence[str] | None:
    fact = result.fact("unlocked")
    if fact is None:
        return None
    return Evidence(
        state=fact.evidence.state,
        source=EvidenceSource.INFERRED if simulated else EvidenceSource.PROBED,
        observed_at=fact.evidence.observed_at,
        value=fact.evidence.value,
        max_age=fact.evidence.max_age,
        detail=fact.evidence.detail,
    )


def _probe_payload(
    result: ProbeResult,
    prepared: PreparedFastboot,
    device: DeviceRecord | None,
) -> dict[str, object]:
    return {
        "tool": prepared.tool_payload,
        "serial_sha256": None if device is None else device.serial_sha256,
        "tool_ok": result.tool_ok,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "cancelled": result.cancelled,
        "detail": result.detail,
        "device": None if device is None else device.to_dict(),
        "facts": [
            {
                "name": fact.name,
                "state": fact.evidence.state.name,
                "value_sha256": (
                    None
                    if fact.evidence.value is None
                    else hashlib.sha256(fact.evidence.value.encode("utf-8")).hexdigest()
                ),
                "detail": fact.evidence.detail,
            }
            for fact in result.facts
        ],
    }


def _device_warnings(device: DeviceRecord) -> tuple[str, ...]:
    if device.fingerprint_sha256 is None:
        return ("device identity fingerprint is unavailable; approval cannot be bound",)
    if device.source == "simulated":
        return ("simulated probe facts are not device evidence",)
    return ()


def _device_identity(device: DeviceRecord | None) -> DeviceIdentity | None:
    if device is None or not device.identity:
        return None
    product = device.identity.get("product")
    if not product:
        return None
    return DeviceIdentity(
        product=product,
        variant=device.identity.get("variant"),
        hw_revision=device.identity.get("hw-revision"),
    )


def _package_identity(manifest: PackageManifest) -> tuple[PackageIdentity | None, tuple[str, ...]]:
    if manifest.ota_metadata is None:
        return None, ()
    values = manifest.ota_metadata.values("pre-device")
    if not values:
        return None, ()
    unique = sorted(set(values))
    if len(unique) > 1:
        return None, ("package metadata reports conflicting pre-device values",)
    product = unique[0].strip()
    if not product:
        return None, ("package metadata reports an empty pre-device value",)
    if "," in product or any(character.isspace() for character in product):
        return None, (
            "package pre-device value contains a comma or whitespace; the target is ambiguous",
        )
    return PackageIdentity(product=product), ()


def _fastboot_binding(prepared: PreparedFastboot | None) -> ToolBinding | None:
    if prepared is None:
        return None
    return tool_binding_from_payload(prepared.tool_payload)


def _merge_tools(
    tools: tuple[ToolBinding, ...],
    probed: ToolBinding | None,
) -> tuple[tuple[ToolBinding, ...], str | None]:
    if probed is None:
        return tools, None
    if any(tool.name == probed.name for tool in tools):
        return tools, f"--tool {probed.name!r} duplicates the probed fastboot binding"
    return tuple(sorted((*tools, probed), key=lambda tool: tool.name)), None


def _check(
    state: Tri,
    detail: str,
    payload: Mapping[str, object],
    warnings: tuple[str, ...] = (),
) -> CheckState:
    evidence_id = _stable_id("check", state.name, detail, _json(payload))
    return CheckState(
        state=state,
        detail=detail,
        evidence_ids=(evidence_id,),
        warnings=warnings,
    )


def _read_key(path: Path) -> bytes:
    if not path.is_file():
        raise AvbError(f"AVB public key not found at {path}")
    data = path.read_bytes()
    if not data:
        raise AvbError(f"AVB public key at {path} is empty")
    if len(data) > 8192:
        raise AvbError(f"AVB public key at {path} is above the 8192-byte limit")
    return data


def _read_token_text(path: Path) -> str:
    size = path.stat().st_size
    if size > MAX_TOKEN_BYTES:
        raise ApprovalError(f"approval token at {path} is above the {MAX_TOKEN_BYTES}-byte limit")
    return path.read_text(encoding="utf-8")


def doctor_fingerprint(options: WizardOptions) -> str:
    return _fingerprint(
        "doctor",
        str(options.fastboot),
        str(options.simulate),
        options.serial or "",
        str(options.soak),
    )


def probe_fingerprint(options: WizardOptions) -> str:
    return _fingerprint(
        "probe",
        str(options.fastboot),
        str(options.simulate),
        options.serial or "",
        options.device_fingerprint or "",
    )


def rollback_fingerprint(options: WizardOptions) -> str:
    chain = sorted((name, str(path)) for name, path in options.chain.items())
    stored = sorted(options.stored.items())
    return _fingerprint(
        "rollback",
        str(options.vbmeta),
        _json(chain),
        _json(stored),
        options.rollback_slot or "",
        str(options.simulate),
    )


def _report_warnings(report: SafetyReport) -> tuple[str, ...]:
    return tuple(warning for rule in report.rules for warning in rule.warnings)


def _identity_payload(
    identity: DeviceIdentity | PackageIdentity | None,
) -> dict[str, object] | None:
    if identity is None:
        return None
    return {
        "product": identity.product,
        "variant": identity.variant,
        "hw_revision": identity.hw_revision,
    }


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256(_json(list(parts)).encode("utf-8")).hexdigest()


def _stable_id(*parts: str) -> str:
    return hashlib.sha256(_json(list(parts)).encode("utf-8")).hexdigest()[:32]


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr)
