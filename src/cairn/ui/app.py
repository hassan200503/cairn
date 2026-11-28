"""UI endpoint implementations: JSON adapters over the audited core.

Every endpoint composes the same public building blocks the CLI composes —
never a parallel implementation. Where input parsing is non-trivial and already
exists in the CLI (chain specs, stored indexes, fastboot resolution), the CLI's
helper is imported so there is exactly one source of truth. Nothing here can
write to a device: the only transports this module can construct are the
transcript simulator and read-only probes (ADR-027).
"""

from __future__ import annotations

import hashlib
import platform
import sys
import tempfile
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cairn import __version__
from cairn.adapters.fastboot import FastbootClient, ProbeResult
from cairn.adapters.prepare import prepare_fastboot
from cairn.approval.binding import ApprovalError, ApprovalInputs
from cairn.approval.device import caller_device_binding
from cairn.approval.token import load_approval_key, verify_approval
from cairn.catalog import (
    CatalogError,
    DeviceEntry,
    load_catalog,
    load_catalog_verified,
    sign_catalog_bytes,
)
from cairn.cli import _resolve_fastboot
from cairn.core.tristate import Tri
from cairn.core.verification import VerificationLevel
from cairn.executor.executor import (
    ExecutionRequest,
    ExecutorRefused,
    SafetyGate,
    SimulatedFastbootTransport,
    execute_plan,
)
from cairn.executor.journal import JournalCorruptError, JournalWriteError
from cairn.host.doctor import HostDoctor
from cairn.package.archive import PackageError, load_package
from cairn.plan.planner import PlanError, PlanOptions, build_plan
from cairn.plan.safety import assess_plan
from cairn.provenance.avb import (
    AvbError,
    load_vbmeta,
    verify_vbmeta_chain,
    verify_vbmeta_signature,
)
from cairn.provenance.hash_index import HashIndexError, load_hash_index, verify_manifest
from cairn.provenance.trust import LockState, evaluate_lock_key
from cairn.recovery.drill import DrillError, DrillInputs, run_drill
from cairn.recovery.vault import VaultDevice, VaultError, create_vault, save_vault
from cairn.rollback.device import read_stored_rollback_indexes
from cairn.rollback.oracle import evaluate_avb_rollback
from cairn.safety.engine import SafetyContext, SafetyEngine
from cairn.sim.transcript import TRANSCRIPT_ENV
from cairn.tools.manifest import TOOL_MANIFEST
from cairn.tools.runner import ToolRunner
from cairn.vab.dynpart import read_dynpart
from cairn.vab.merge_state import read_merge_state
from cairn.wizard.render import session_exit_code
from cairn.wizard.runner import run_wizard
from cairn.wizard.session import SessionOutcome, WizardError, load_session
from cairn.wizard.stages import WizardOptions, reload_session_plan

MAX_BODY_BYTES = 1 * 1024 * 1024


class UIError(Exception):
    """An endpoint-level failure with a user-facing message."""

    def __init__(self, message: str, *, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _require(body: dict[str, Any], key: str) -> Any:
    value = body.get(key)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise UIError(f"missing required field: {key}")
    return value


def _opt_path(body: dict[str, Any], key: str) -> Path | None:
    value = body.get(key)
    return None if value in (None, "") else Path(str(value))


def _opt_str(body: dict[str, Any], key: str) -> str | None:
    value = body.get(key)
    return None if value in (None, "") else str(value)


def _chain_map(body: dict[str, Any]) -> dict[str, Path]:
    chain: dict[str, Path] = {}
    for spec in body.get("chain", []) or []:
        name, separator, path_text = str(spec).partition("=")
        if not separator or not name or not path_text:
            raise UIError(f"malformed chain spec {spec!r}; use NAME=PATH")
        if name in chain:
            raise UIError(f"duplicate chain {name!r}")
        chain[name] = Path(path_text)
    return chain


def _stored_map(body: dict[str, Any]) -> dict[int, int]:
    stored: dict[int, int] = {}
    for spec in body.get("stored", []) or []:
        location_text, separator, value_text = str(spec).partition("=")
        if not separator:
            raise UIError(f"malformed stored spec {spec!r}; use LOCATION=VALUE")
        try:
            stored[int(location_text, 0)] = int(value_text, 0)
        except ValueError as exc:
            raise UIError(f"malformed stored spec {spec!r}; use integers") from exc
    return stored


def _prepared_client(
    body: dict[str, Any],
) -> tuple[FastbootClient, dict[str, object], bool]:
    """A read-only fastboot client or a transcript-replay client (ADR-027)."""
    simulate = _opt_path(body, "simulate")
    if simulate is not None:
        prefix: tuple[str, ...] = (sys.executable, "-m", "cairn.sim.fastboot_sim")
        extra_env = {TRANSCRIPT_ENV: str(simulate)}
        return (
            FastbootClient(prefix, runner=ToolRunner(), extra_env=extra_env),
            {
                "kind": "simulated",
                "name": "fastboot",
                "transcript": str(simulate),
                "simulated": True,
            },
            True,
        )
    fastboot = _resolve_fastboot(_opt_path(body, "fastboot"))
    if fastboot is None:
        raise UIError("fastboot not found; supply fastboot or simulate", status=400)
    runner = ToolRunner()
    try:
        report = TOOL_MANIFEST.verify("fastboot", fastboot, runner)
    except Exception as exc:  # ToolError
        raise UIError(str(exc)) from exc
    return (
        FastbootClient((str(fastboot),), runner=runner),
        {
            "kind": "fastboot",
            "name": "fastboot",
            "path": str(report.path),
            "version": report.version,
            "sha256": report.sha256,
            "manifest_ok": report.ok,
            "simulated": False,
        },
        False,
    )


def _probe_payload(result: ProbeResult, *, simulated: bool) -> dict[str, object]:
    return {
        "simulated": simulated,
        "tool_ok": result.tool_ok,
        "detail": result.detail,
        "serial": result.serial,
        "facts": [
            {
                "name": fact.name,
                "state": fact.evidence.state.name,
                "value": fact.evidence.value,
                "detail": fact.evidence.detail,
                "source": fact.evidence.source.name,
            }
            for fact in result.facts
        ],
    }


# ---------------------------------------------------------------- endpoints


def _state(_body: dict[str, Any]) -> dict[str, object]:
    return {
        "version": __version__,
        "platform": f"{platform.system()} {platform.release()}",
        "python": sys.version.split()[0],
        "levels": {level.name: level.label for level in VerificationLevel},
        "boundary": (
            "Every write verb reaches the transcript simulator only (ADR-027). "
            "A real-device write transport does not exist until the M6 gate passes."
        ),
    }


def _doctor(body: dict[str, Any]) -> dict[str, object]:
    simulate = _opt_path(body, "simulate")
    fastboot_prefix: tuple[str, ...] | None = None
    fastboot_label = "not requested"
    extra_env = None
    simulated = False
    if simulate is not None:
        fastboot_prefix = (sys.executable, "-m", "cairn.sim.fastboot_sim")
        extra_env = {TRANSCRIPT_ENV: str(simulate)}
        fastboot_label = "transcript simulator"
        simulated = True
    elif body.get("run_link_soak"):
        fastboot = _resolve_fastboot(_opt_path(body, "fastboot"))
        if fastboot is None:
            raise UIError("fastboot not found; supply fastboot or simulate")
        fastboot_prefix = (str(fastboot),)
        fastboot_label = str(fastboot)
    soak = int(body.get("soak", 3) or 0)
    doctor = HostDoctor(ToolRunner())
    return doctor.run(
        fastboot_prefix=fastboot_prefix,
        fastboot_label=fastboot_label,
        adb_path=None,
        serial=_opt_str(body, "serial"),
        soak_attempts=soak,
        simulated=simulated,
        fastboot_extra_env=extra_env,
    ).to_dict()


def _probe(body: dict[str, Any]) -> dict[str, object]:
    client, tool, simulated = _prepared_client(body)
    result = client.probe(serial=_opt_str(body, "serial"))
    return _probe_payload(result, simulated=simulated) | {"tool": tool}


def _wizard(body: dict[str, Any]) -> dict[str, object]:
    options = WizardOptions(
        package=Path(str(_require(body, "package"))),
        index=Path(str(_require(body, "index"))),
        state=Path(str(_require(body, "state"))),
        fastboot=_opt_path(body, "fastboot"),
        serial=_opt_str(body, "serial"),
        simulate=_opt_path(body, "simulate"),
        device_fingerprint=_opt_str(body, "device_fingerprint"),
        soak=int(body.get("soak", 3) or 0),
        vbmeta=_opt_path(body, "vbmeta"),
        chain=_chain_map(body),
        key=_opt_path(body, "key"),
        catalog=_opt_path(body, "catalog"),
        catalog_key=_opt_path(body, "catalog_key"),
        catalog_signature=_opt_path(body, "catalog_signature"),
        lock_state=_opt_str(body, "lock_state"),
        stored=_stored_map(body),
        wipe=bool(body.get("wipe")),
        retrofit_force=bool(body.get("retrofit_force")),
        approval=_opt_path(body, "approval"),
        approval_key=_opt_path(body, "approval_key"),
        resume=bool(body.get("resume")),
        force=bool(body.get("force")),
    )
    try:
        session = run_wizard(options)
    except (WizardError, OSError) as exc:
        raise UIError(str(exc), status=400) from exc
    return session.to_dict() | {"exit_code": session_exit_code(session)}


def _plan(body: dict[str, Any]) -> dict[str, object]:
    try:
        index = load_hash_index(Path(str(_require(body, "index"))))
        manifest = load_package(
            Path(str(_require(body, "package"))),
            hash_files=True,
            hash_archive=True,
        )
        provenance = verify_manifest(index, manifest)
        plan = build_plan(
            manifest,
            provenance,
            options=PlanOptions(
                wipe=bool(body.get("wipe")),
                retrofit_force=bool(body.get("retrofit_force")),
            ),
        )
        pre_safety = SafetyEngine.pre_approval().evaluate(SafetyContext(provenance=provenance))
        assessment = assess_plan(plan, pre_safety)
    except (HashIndexError, PackageError, PlanError) as exc:
        raise UIError(str(exc), status=400) from exc
    return assessment.to_dict()


def _execute(body: dict[str, Any]) -> dict[str, object]:
    state_path = Path(str(_require(body, "state")))
    token_path = Path(str(_require(body, "token")))
    key_path = Path(str(_require(body, "key")))
    simulate = _opt_path(body, "simulate")
    if simulate is None:
        raise UIError("execute runs in the transcript simulator only; supply simulate")
    try:
        session = load_session(state_path)
    except WizardError as exc:
        raise UIError(str(exc), status=400) from exc
    allowed = (SessionOutcome.READY, SessionOutcome.CLEARED, SessionOutcome.SIMULATED)
    if session.outcome not in allowed:
        raise UIError(
            f"wizard session outcome is {session.outcome.value}; execution requires "
            "READY, CLEARED, or SIMULATED",
            status=409,
        )
    if session.bundle is None or session.plan is None or session.pre_safety is None:
        raise UIError("wizard session has no plan or approval bundle to execute", status=409)
    verdict_name = session.pre_safety.get("verdict")
    if verdict_name not in {"TRUE", "FALSE", "UNKNOWN"}:
        raise UIError("session pre-approval safety verdict is missing or invalid", status=409)
    if verdict_name == "FALSE":
        raise UIError("the session's safety verdict is FALSE and is never overridable", status=409)
    try:
        reloaded = reload_session_plan(session)
    except WizardError as exc:
        raise UIError(str(exc), status=400) from exc

    binding = None
    if session.device is not None:
        candidate = session.device.binding()
        if candidate is not None and candidate.source.value == "probed":
            binding = candidate
    if binding is None:
        nonce = _opt_str(body, "nonce")
        fingerprint = _opt_str(body, "device_fingerprint")
        if nonce is None or fingerprint is None:
            raise UIError(
                "the session has no probed device binding; supply nonce and "
                "device_fingerprint exactly as used at issue time",
                status=400,
            )
        try:
            binding = caller_device_binding(nonce, fingerprint)
        except ApprovalError as exc:
            raise UIError(str(exc), status=400) from exc

    try:
        key = load_approval_key(key_path)
        token_text = token_path.read_text(encoding="utf-8")
    except ApprovalError as exc:
        raise UIError(str(exc), status=400) from exc
    except OSError as exc:
        raise UIError(str(exc), status=400) from exc
    current = ApprovalInputs(
        plan_sha256=session.bundle.plan_sha256,
        evidence_snapshot_sha256=session.bundle.evidence_snapshot_sha256,
        archive_sha256=session.bundle.archive_sha256,
        package_hashes=session.bundle.package_hashes,
        device=binding,
        tools=session.bundle.tools,
    )
    approval = verify_approval(token_text, key, current)
    if approval.state is not Tri.TRUE:
        return {"approval": approval.to_dict(), "executed": False}

    prepared = prepare_fastboot(fastboot=None, simulate=simulate)
    try:
        transport = SimulatedFastbootTransport.from_prepared(prepared)
    except Exception as exc:  # ExecutorRefused
        raise UIError(str(exc), status=409) from exc

    blocking_raw = session.pre_safety.get("blocking")
    blocking = tuple(blocking_raw) if isinstance(blocking_raw, list) else ()
    safety = SafetyGate(verdict=Tri[str(verdict_name)], blocking=blocking)
    journal = _opt_path(body, "journal") or Path(f"{state_path}.journal")
    staging_dir = _opt_path(body, "staging_dir") or Path(tempfile.mkdtemp(prefix="cairn-stage-"))
    request = ExecutionRequest(
        plan=reloaded.plan,
        package_path=Path(session.package_path),
        expected_entry_hashes=dict(session.bundle.package_hashes),
        safety=safety,
        approval=approval,
        transport=transport,
        staging_dir=staging_dir,
        timeout_s=int(body.get("timeout_s", 600) or 600),
    )
    try:
        result = execute_plan(request, journal)
    except ExecutorRefused as exc:
        raise UIError(str(exc), status=409) from exc
    except (JournalWriteError, JournalCorruptError) as exc:
        raise UIError(f"journal: {exc}", status=500) from exc
    return result.to_dict() | {"journal_path": str(result.journal_path), "simulated": True}


def _avb(body: dict[str, Any]) -> dict[str, object]:
    action = str(_require(body, "action"))
    image_path = Path(str(_require(body, "image")))
    chain = _chain_map(body)
    try:
        image = load_vbmeta(image_path)
        if action == "info":
            return image.to_dict()
        if action == "verify":
            key = _opt_path(body, "key")
            expected = key.read_bytes() if key is not None else None
            if chain:
                chained = {n: load_vbmeta(p) for n, p in chain.items()}
                report = verify_vbmeta_chain(image, chained, expected_key=expected)
                return report.to_dict()
            return verify_vbmeta_signature(image, expected_key=expected).to_dict()
        if action == "key-check":
            catalog = _opt_path(body, "catalog")
            trusted_key = None
            trusted_key_source = None
            if catalog is not None:
                entry = _catalog_entry(body, catalog, "ui avb key-check")
                if entry is not None:
                    if entry.trusted_key is None:
                        raise UIError("the catalog entry carries no trusted_key_b64")
                    trusted_key = entry.trusted_key
                    trusted_key_source = entry.source
            result = evaluate_lock_key(
                verify_vbmeta_signature(image, expected_key=trusted_key),
                lock_state=LockState(str(_require(body, "lock_state"))),
                trusted_key=trusted_key,
                trusted_key_source=trusted_key_source,
            )
            return result.to_dict()
    except AvbError as exc:
        raise UIError(str(exc), status=400) from exc
    except CatalogError as exc:
        raise UIError(str(exc), status=400) from exc
    raise UIError(f"unknown avb action {action!r}")


def _catalog_entry(body: dict[str, Any], catalog_path: Path, what: str) -> DeviceEntry:
    key_path = _opt_path(body, "catalog_key")
    signature_path = _opt_path(body, "catalog_signature")
    hmac_key: bytes | None = None
    signature: str | None = None
    if key_path is not None:
        if signature_path is None:
            raise UIError("catalog-signature is required with catalog-key")
        hmac_key = key_path.read_bytes()
        signature = signature_path.read_text(encoding="ascii").strip()
    if hmac_key is None:
        catalog = load_catalog(catalog_path)
    else:
        catalog = load_catalog_verified(catalog_path, hmac_key=hmac_key, signature=signature)
    fingerprint = _opt_str(body, "device_fingerprint")
    product = _opt_str(body, "product")
    entry = (
        catalog.device_by_fingerprint(fingerprint)
        if fingerprint is not None
        else catalog.device_by_product(product)
        if product is not None
        else None
    )
    if entry is None:
        raise UIError(f"{what}: no catalog device matches the supplied identity")
    return entry


def _rollback(body: dict[str, Any]) -> dict[str, object]:
    action = str(_require(body, "action"))
    if action == "read":
        client, _tool, _sim = _prepared_client(body)
        read = read_stored_rollback_indexes(client, serial=_opt_str(body, "serial"))
        return read.to_dict()
    if action != "check":
        raise UIError(f"unknown rollback action {action!r}")
    image_path = Path(str(_require(body, "image")))
    stored = _stored_map(body)
    simulated = False
    device_read = None
    if not stored:
        client, _tool, simulated = _prepared_client(body)
        device_read = read_stored_rollback_indexes(client, serial=_opt_str(body, "serial"))
        stored = device_read.stored
    catalog_bounds: dict[int, tuple[int | None, int | None]] = {}
    bounds_source = None
    catalog = _opt_path(body, "catalog")
    if catalog is not None:
        try:
            entry = _catalog_entry(body, catalog, "ui rollback check")
        except CatalogError as exc:
            raise UIError(str(exc), status=400) from exc
        if entry.rollback_bounds:
            catalog_bounds = {
                location: (bound.minimum, bound.maximum)
                for location, bound in entry.rollback_bounds.items()
            }
            bounds_source = entry.source
    chain = _chain_map(body)
    if device_read is not None:
        stored_source = "device" if stored else "unknown"
    else:
        stored_source = "caller" if stored else "unknown"
    try:
        report = evaluate_avb_rollback(
            load_vbmeta(image_path),
            {n: load_vbmeta(p) for n, p in chain.items()},
            stored=stored or None,
            stored_source=stored_source,
            catalog_bounds=catalog_bounds or None,
        )
    except AvbError as exc:
        raise UIError(str(exc), status=400) from exc
    if device_read is not None:
        extra = device_read.warnings + device_read.unresolved
        if extra:
            report = replace(report, warnings=report.warnings + extra)
    payload = report.to_dict() | {"simulated": simulated}
    if bounds_source is not None:
        payload["rollback_bounds_source"] = bounds_source
    return payload


def _vab(body: dict[str, Any]) -> dict[str, object]:
    action = str(_require(body, "action"))
    client, _tool, simulated = _prepared_client(body)
    if action == "status":
        read = read_merge_state(client, serial=_opt_str(body, "serial"), simulated=simulated)
        return read.to_dict()
    if action == "dynpart":
        mode = str(_require(body, "mode"))
        dyn = read_dynpart(
            client,
            job_mode=mode,
            serial=_opt_str(body, "serial"),
            simulated=simulated,
        )
        return dyn.to_dict() | {"job_mode": mode}
    raise UIError(f"unknown vab action {action!r}")


def _catalog(body: dict[str, Any]) -> dict[str, object]:
    action = str(_require(body, "action"))
    catalog_path = Path(str(_require(body, "catalog")))
    key_path = _opt_path(body, "key")
    if action == "check":
        try:
            catalog = load_catalog(catalog_path)
        except CatalogError as exc:
            raise UIError(str(exc), status=400) from exc
        return {
            "devices": [entry.to_dict() for entry in catalog.devices],
            "packages": [
                {
                    "archive_sha256": entry.archive_sha256,
                    "label": entry.label,
                    "source": entry.source,
                    "notes": entry.notes,
                }
                for entry in catalog.packages
            ],
        }
    if action == "sign":
        if key_path is None:
            raise UIError("sign requires key")
        key = key_path.read_bytes()
        data = catalog_path.read_bytes()
        signature_path = _opt_path(body, "signature") or Path(str(catalog_path) + ".sig")
        signature_path.write_text(sign_catalog_bytes(data, key) + "\n", encoding="ascii")
        return {"signed": str(catalog_path), "signature": str(signature_path)}
    if action == "verify":
        if key_path is None:
            raise UIError("verify requires key")
        signature_path = _opt_path(body, "signature") or Path(str(catalog_path) + ".sig")
        try:
            load_catalog_verified(
                catalog_path,
                hmac_key=key_path.read_bytes(),
                signature=signature_path.read_text(encoding="ascii").strip(),
            )
        except CatalogError as exc:
            raise UIError(str(exc), status=400) from exc
        return {"verified": str(catalog_path)}
    raise UIError(f"unknown catalog action {action!r}")


def _recovery(body: dict[str, Any]) -> dict[str, object]:
    action = str(_require(body, "action"))
    if action == "backup":
        return _recovery_backup(body)
    if action == "drill":
        return _recovery_drill(body)
    raise UIError(f"unknown recovery action {action!r}; the UI offers backup and drill")


def _recovery_backup(body: dict[str, Any]) -> dict[str, object]:
    passphrase = _passphrase(body)
    try:
        device = VaultDevice(
            product=str(_require(body, "product")),
            serial_sha256=str(_require(body, "serial_sha256")),
            fingerprint_sha256=str(_require(body, "device_fingerprint")),
        )
    except VaultError as exc:
        raise UIError(str(exc), status=400) from exc
    asset_path = Path(str(_require(body, "asset")))
    try:
        plaintext = asset_path.read_bytes()
        vault = create_vault(
            device=device,
            entries={str(_require(body, "partition")): plaintext},
            passphrase=passphrase,
        )
        vault_path = Path(str(_require(body, "vault")))
        save_vault(vault_path, vault, passphrase=passphrase)
    except (VaultError, OSError) as exc:
        raise UIError(str(exc), status=400) from exc
    return {
        "vault": str(vault_path),
        "partition": str(body.get("partition")),
        "sha256": hashlib.sha256(plaintext).hexdigest(),
        "device": device.to_dict(),
        "refusal": "restore is refused for any other device identity; never overridable",
    }


def _passphrase(body: dict[str, Any]) -> str:
    passphrase_file = _opt_path(body, "passphrase_file")
    if passphrase_file is not None:
        text = passphrase_file.read_text(encoding="utf-8").strip()
        if not text:
            raise UIError("passphrase file is empty")
        return text
    raise UIError("no passphrase; supply passphrase_file")


def _recovery_drill(body: dict[str, Any]) -> dict[str, object]:
    simulate = _opt_path(body, "simulate")
    if simulate is None:
        raise UIError("the drill restores through the transcript simulator; supply simulate")
    passphrase = _passphrase(body)
    try:
        device = VaultDevice(
            product=str(_require(body, "product")),
            serial_sha256=str(_require(body, "serial_sha256")),
            fingerprint_sha256=str(_require(body, "device_fingerprint")),
        )
        other = VaultDevice(
            product=f"{body.get('product')}-other",
            serial_sha256=str(_require(body, "other_serial_sha256")),
            fingerprint_sha256=str(_require(body, "other_fingerprint")),
        )
    except VaultError as exc:
        raise UIError(str(exc), status=400) from exc
    vault_path = Path(str(_require(body, "vault")))
    prepared = prepare_fastboot(fastboot=None, simulate=simulate)
    try:
        transport = SimulatedFastbootTransport.from_prepared(prepared)
    except Exception as exc:  # ExecutorRefused
        raise UIError(str(exc), status=409) from exc
    inputs = DrillInputs(
        partition=str(_require(body, "partition")),
        asset_path=Path(str(_require(body, "asset"))),
        asset_sha256=str(_require(body, "expected_sha256")),
        device=device,
        other_device=other,
        vault_path=vault_path,
        staging_dir=vault_path.parent / "drill-staging",
        passphrase=passphrase,
        journal_path=Path(f"{vault_path}.drill-journal"),
        last_resort_path=str(_require(body, "last_resort")),
    )
    try:
        report = run_drill(inputs, transport, now=datetime.now(UTC))
    except (DrillError, VaultError) as exc:
        raise UIError(str(exc), status=400) from exc
    return report.to_dict() | {"simulated": True}


# ---------------------------------------------------------------- dispatch

_ENDPOINTS = {
    ("POST", "state"): _state,
    ("POST", "doctor"): _doctor,
    ("POST", "probe"): _probe,
    ("POST", "wizard"): _wizard,
    ("POST", "plan"): _plan,
    ("POST", "execute"): _execute,
    ("POST", "avb"): _avb,
    ("POST", "rollback"): _rollback,
    ("POST", "vab"): _vab,
    ("POST", "catalog"): _catalog,
    ("POST", "recovery"): _recovery,
}


def dispatch(method: str, name: str, body: dict[str, Any]) -> tuple[int, dict[str, object]]:
    """Run one UI endpoint; returns (http status, JSON payload)."""
    handler = _ENDPOINTS.get((method, name))
    if handler is None:
        return 404, {"error": f"no such endpoint: {method} /api/{name}"}
    try:
        return 200, handler(body)
    except UIError as exc:
        return exc.status, {"error": str(exc)}
    except (OSError, ValueError, TypeError) as exc:
        return 400, {"error": str(exc)}
    except Exception as exc:  # unexpected: fail closed with the message
        return 500, {"error": f"{type(exc).__name__}: {exc}"}
