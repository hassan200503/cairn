"""Tests for the local UI: JSON endpoints and the loopback server.

The UI must add no safety logic of its own (ADR-031): these tests pin that it
exposes the audited core honestly — simulator-gated writes, 4xx on bad input,
and the ADR-027 boundary statement — and that the recovery drill passes end to
end through the same dispatch path the browser uses.
"""

from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
import zipfile
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from cairn.approval import (
    ApprovalInputs,
    DeviceBinding,
    DeviceBindingSource,
    issue_approval,
    write_approval_key,
)
from cairn.catalog import CATALOG_SCHEMA_VERSION
from cairn.core.tristate import Tri
from cairn.executor import staged_image_path
from cairn.package.archive import load_package
from cairn.plan.planner import PlanFacts, PlanOptions, build_plan
from cairn.provenance.hash_index import load_hash_index, verify_manifest
from cairn.sim.transcript import Transcript, TranscriptStep, dump_transcript
from cairn.ui.app import MAX_BODY_BYTES, dispatch
from cairn.ui.server import _Handler
from cairn.wizard.session import (
    STAGE_TITLES,
    ApprovalBundle,
    DeviceRecord,
    SessionOutcome,
    StageOutcome,
    StageRecord,
    new_session,
    save_session,
)

PIXEL_TRANSCRIPT = Path(__file__).parent / "fixtures" / "fastboot" / "pixel8_getvar_all.json"

INFO_TEXT = """\
version 1
flash boot boot.img
erase cache
reboot bootloader
"""

_BOOT_BYTES = b"boot-image-bytes"
_NONCE = "a" * 32
_FINGERPRINT = hashlib.sha256(b"device").hexdigest()


def _hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _package(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("boot.img", _BOOT_BYTES)
        archive.writestr("fastboot-info.txt", INFO_TEXT)
    return path


def _index(path: Path, package: Path) -> Path:
    manifest = load_package(package, hash_files=True, hash_archive=True)
    payload = {
        "schema_version": 1,
        "packages": [
            {
                "id": "ui-test",
                "archive_sha256": manifest.archive_sha256,
                "entries": {entry.name: entry.sha256 for entry in manifest.entries},
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _plan(package: Path, index: Path):
    manifest = load_package(package, hash_files=True, hash_archive=True)
    provenance = verify_manifest(load_hash_index(index), manifest)
    return build_plan(manifest, provenance, options=PlanOptions(), facts=PlanFacts())


def _ready_session(path: Path, package: Path, index: Path) -> Path:
    manifest = load_package(package, hash_files=True, hash_archive=True)
    plan = _plan(package, index)
    snapshot = _hex("snapshot")
    pre_safety = {
        "can_proceed": True,
        "evidence_snapshot_sha256": snapshot,
        "verdict": "TRUE",
        "blocking": [],
    }
    now = datetime.now(UTC)
    device = DeviceRecord(
        source="probed",
        simulated=False,
        nonce=_NONCE,
        fingerprint_sha256=_FINGERPRINT,
        probed_at=now,
        max_age_s=600,
    )
    bundle = ApprovalBundle(
        plan_sha256=plan.plan_sha256,
        evidence_snapshot_sha256=snapshot,
        archive_sha256=manifest.archive_sha256,
        package_hashes=tuple(sorted((entry.name, entry.sha256) for entry in manifest.entries)),
        tools=(),
        pre_safety=pre_safety,
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
            for name in ("doctor", "inspect", "provenance", "probe", "avb", "rollback", "plan")
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
        index_path=index,
        cairn_version="test",
        now=now,
        session_id="c" * 32,
    ).replace(
        stages=stages,
        device=device,
        bundle=bundle,
        archive_sha256=manifest.archive_sha256,
        index_sha256=hashlib.sha256(index.read_bytes()).hexdigest(),
        plan=plan.to_dict(),
        pre_safety=pre_safety,
        outcome=SessionOutcome.READY,
    )
    save_session(path, session)
    return path


def _issue_token(package: Path, index: Path, key_path: Path, token_path: Path) -> None:
    """Same approval issuance as the executor CLI tests; one trust semantics."""
    from cairn.safety.engine import SafetyReport

    manifest = load_package(package, hash_files=True, hash_archive=True)
    plan = _plan(package, index)
    safety = SafetyReport(
        rules=(),
        overrides=(),
        verdict=Tri.TRUE,
        can_proceed=True,
        blocking=(),
        evidence_snapshot_sha256=_hex("snapshot"),
        report_text="test",
    )
    key = hashlib.sha256(b"approval-key").digest()
    write_approval_key(key_path, key)
    inputs = ApprovalInputs.from_manifest(
        manifest,
        plan,
        safety,
        DeviceBinding(
            nonce=_NONCE,
            fingerprint_sha256=_FINGERPRINT,
            source=DeviceBindingSource.PROBED,
        ),
    )
    token = issue_approval(inputs, key, operator="op", reason="ui test run")
    token_path.write_text(token.to_json(), encoding="utf-8", newline="\n")


def _write_transcript(staging: Path, path: Path) -> Path:
    transcript = Transcript(
        schema_version=1,
        device={"product": "ui-test"},
        steps=(
            TranscriptStep(
                argv=("flash", "boot", str(staged_image_path(staging, "boot.img"))),
                stdout="OKAY",
            ),
            TranscriptStep(argv=("erase", "cache"), stdout="OKAY"),
            TranscriptStep(argv=("reboot", "bootloader"), stdout="OKAY"),
        ),
    )
    dump_transcript(transcript, path)
    return path


# --------------------------------------------------------------- dispatch tests


def test_state_reports_version_and_the_simulator_boundary() -> None:
    status, payload = dispatch("POST", "state", {})
    assert status == 200
    assert payload["version"]
    assert "ADR-027" in str(payload["boundary"])
    assert set(payload["levels"]) == {"V0", "V1", "V2", "V3"}


def test_unknown_endpoint_is_404() -> None:
    status, payload = dispatch("POST", "nope", {})
    assert status == 404
    assert "no such endpoint" in payload["error"]


def test_get_is_refused() -> None:
    status, _payload = dispatch("GET", "state", {})
    assert status == 404


def test_probe_simulated_replays_the_transcript() -> None:
    status, payload = dispatch(
        "POST", "probe", {"simulate": str(PIXEL_TRANSCRIPT), "serial": "SIM123"}
    )
    assert status == 200
    assert payload["simulated"] is True
    assert payload["tool_ok"] is True
    assert payload["facts"]


def test_probe_requires_fastboot_or_simulate() -> None:
    status, payload = dispatch("POST", "probe", {})
    assert status == 400
    assert "fastboot not found" in payload["error"]


def test_doctor_simulated_returns_checks() -> None:
    status, payload = dispatch("POST", "doctor", {"simulate": str(PIXEL_TRANSCRIPT)})
    assert status == 200
    assert payload["simulated"] is True
    assert payload["checks"]


def test_plan_assesses_a_verified_package(tmp_path: Path) -> None:
    package = _package(tmp_path / "factory.zip")
    index = _index(tmp_path / "index.json", package)
    status, payload = dispatch("POST", "plan", {"package": str(package), "index": str(index)})
    assert status == 200
    assert payload["plan_sha256"]

    status, payload = dispatch(
        "POST", "plan", {"package": str(package), "index": str(tmp_path / "missing.json")}
    )
    assert status == 400


def test_wizard_reports_a_failed_outcome_for_a_missing_package(tmp_path: Path) -> None:
    status, payload = dispatch(
        "POST",
        "wizard",
        {
            "package": str(tmp_path / "nope.zip"),
            "index": str(tmp_path / "nope.json"),
            "state": str(tmp_path / "state.json"),
            "simulate": str(PIXEL_TRANSCRIPT),
        },
    )
    assert status == 200
    assert payload["outcome"] == "failed"
    assert payload["exit_code"] == 1


def test_execute_requires_the_simulator(tmp_path: Path) -> None:
    package = _package(tmp_path / "factory.zip")
    index = _index(tmp_path / "index.json", package)
    state = _ready_session(tmp_path / "wizard.json", package, index)
    status, payload = dispatch(
        "POST",
        "execute",
        {"state": str(state), "token": str(tmp_path / "t.json"), "key": str(tmp_path / "k.key")},
    )
    assert status == 400
    assert "simulator only" in payload["error"]


def test_execute_runs_an_approved_plan_in_the_simulator(tmp_path: Path) -> None:
    package = _package(tmp_path / "factory.zip")
    index = _index(tmp_path / "index.json", package)
    state = _ready_session(tmp_path / "wizard.json", package, index)
    key_path = tmp_path / "approval.key"
    token_path = tmp_path / "token.json"
    _issue_token(package, index, key_path, token_path)
    staging = tmp_path / "stage"
    transcript = _write_transcript(staging, tmp_path / "writes.json")

    status, payload = dispatch(
        "POST",
        "execute",
        {
            "state": str(state),
            "token": str(token_path),
            "key": str(key_path),
            "simulate": str(transcript),
            "staging_dir": str(staging),
            "journal": str(tmp_path / "journal.jsonl"),
        },
    )
    assert status == 200, payload
    assert payload["verdict"] == "TRUE"
    assert payload["simulated"] is True
    assert Path(str(payload["journal_path"])).exists()


def test_execute_with_a_stale_token_reports_not_executed(tmp_path: Path) -> None:
    package = _package(tmp_path / "factory.zip")
    index = _index(tmp_path / "index.json", package)
    state = _ready_session(tmp_path / "wizard.json", package, index)
    key_path = tmp_path / "approval.key"
    token_path = tmp_path / "token.json"
    # The token binds a different archive: it must not authorize this plan.
    with zipfile.ZipFile(other := tmp_path / "other.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("boot.img", b"different-boot-bytes")
        archive.writestr("fastboot-info.txt", INFO_TEXT)
    other_index = _index(tmp_path / "other.json", other)
    _issue_token(other, other_index, key_path, token_path)
    transcript = _write_transcript(tmp_path / "stage", tmp_path / "writes.json")

    status, payload = dispatch(
        "POST",
        "execute",
        {
            "state": str(state),
            "token": str(token_path),
            "key": str(key_path),
            "simulate": str(transcript),
            "staging_dir": str(tmp_path / "stage"),
            "nonce": "b" * 32,
            "device_fingerprint": _hex("other-device"),
        },
    )
    assert status == 200
    assert payload["executed"] is False


def test_catalog_sign_and_verify_roundtrip(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    catalog.write_text(
        json.dumps(
            {
                "kind": "cairn.catalog",
                "schema_version": CATALOG_SCHEMA_VERSION,
                "devices": [],
                "packages": [],
            }
        ),
        encoding="utf-8",
    )
    key_path = tmp_path / "catalog.key"
    key_path.write_bytes(hashlib.sha256(b"catalog-key").digest())

    status, payload = dispatch(
        "POST", "catalog", {"action": "sign", "catalog": str(catalog), "key": str(key_path)}
    )
    assert status == 200
    assert Path(str(payload["signature"])).exists()

    status, payload = dispatch(
        "POST", "catalog", {"action": "verify", "catalog": str(catalog), "key": str(key_path)}
    )
    assert status == 200

    catalog.write_text(catalog.read_text(encoding="utf-8") + " ", encoding="utf-8")
    status, payload = dispatch(
        "POST", "catalog", {"action": "verify", "catalog": str(catalog), "key": str(key_path)}
    )
    assert status == 400


def test_catalog_verify_requires_a_key(tmp_path: Path) -> None:
    status, _payload = dispatch(
        "POST", "catalog", {"action": "verify", "catalog": str(tmp_path / "c.json")}
    )
    assert status == 400


def test_avb_refuses_a_non_vbmeta_image(tmp_path: Path) -> None:
    image = tmp_path / "boot.img"
    image.write_bytes(b"not-a-vbmeta-image" * 16)
    status, _payload = dispatch("POST", "avb", {"action": "info", "image": str(image)})
    assert status == 400


def test_recovery_backup_then_drill_passes_end_to_end(tmp_path: Path) -> None:
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("drill-passphrase-1234", encoding="utf-8")
    asset = tmp_path / "persist.img"
    data = b"persist-partition-content-0123456789"
    asset.write_bytes(data)
    device = {
        "product": "pixel-test",
        "serial_sha256": _hex("serial-a"),
        "device_fingerprint": _hex("fp-a"),
    }
    vault = tmp_path / "vault.json"

    status, backup = dispatch(
        "POST",
        "recovery",
        {
            "action": "backup",
            "partition": "persist",
            "asset": str(asset),
            "vault": str(vault),
            "passphrase_file": str(passphrase),
        }
        | device,
    )
    assert status == 200, backup
    assert backup["sha256"] == hashlib.sha256(data).hexdigest()

    staged = tmp_path / "drill-staging" / "drill-persist.img"
    transcript = Transcript(
        schema_version=1,
        device={"product": "pixel-test"},
        steps=(TranscriptStep(argv=("flash", "persist", str(staged)), stdout="OKAY"),),
    )
    transcript_path = tmp_path / "restore.json"
    dump_transcript(transcript, transcript_path)

    status, drill = dispatch(
        "POST",
        "recovery",
        {
            "action": "drill",
            "partition": "persist",
            "asset": str(asset),
            "expected_sha256": hashlib.sha256(data).hexdigest(),
            "vault": str(vault),
            "passphrase_file": str(passphrase),
            "last_resort": "EDL 9008 entry via test point, service only",
            "simulate": str(transcript_path),
            "other_serial_sha256": _hex("serial-b"),
            "other_fingerprint": _hex("fp-b"),
        }
        | device,
    )
    assert status == 200, drill
    assert drill["verdict"] == "TRUE"
    assert drill["same_device_restored"] is True
    assert drill["cross_device_refused"] is True
    assert staged.read_bytes() == data


def test_recovery_drill_without_a_last_resort_path_fails(tmp_path: Path) -> None:
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_text("drill-passphrase-1234", encoding="utf-8")
    asset = tmp_path / "persist.img"
    asset.write_bytes(b"persist-partition-content-0123456789")
    status, payload = dispatch(
        "POST",
        "recovery",
        {
            "action": "drill",
            "partition": "persist",
            "asset": str(asset),
            "expected_sha256": _hex("x"),
            "vault": str(tmp_path / "vault.json"),
            "passphrase_file": str(passphrase),
            "last_resort": "",
            "simulate": str(PIXEL_TRANSCRIPT),
            "other_serial_sha256": _hex("serial-b"),
            "other_fingerprint": _hex("fp-b"),
            "product": "pixel-test",
            "serial_sha256": _hex("serial-a"),
            "device_fingerprint": _hex("fp-a"),
        },
    )
    assert status == 400
    assert "last_resort" in payload["error"]


def test_recovery_refuses_a_bad_serial_hash(tmp_path: Path) -> None:
    status, _payload = dispatch(
        "POST",
        "recovery",
        {
            "action": "backup",
            "partition": "persist",
            "asset": str(tmp_path / "a.img"),
            "vault": str(tmp_path / "vault.json"),
            "product": "pixel-test",
            "serial_sha256": "NOT-HEX",
            "device_fingerprint": _hex("fp-a"),
            "passphrase_file": str(tmp_path / "p.txt"),
        },
    )
    assert status == 400


# ---------------------------------------------------------------- server tests


class _Server:
    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def get(self, path: str) -> tuple[int, bytes, str]:
        try:
            with urllib.request.urlopen(f"{self.url}{path}", timeout=10) as resp:
                return resp.status, resp.read(), resp.headers["Content-Type"] or ""
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.headers["Content-Type"] or ""

    def post(self, path: str, raw: bytes) -> tuple[int, dict[str, object]]:
        request = urllib.request.Request(
            f"{self.url}{path}", data=raw, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)


@pytest.fixture
def server() -> _Server:
    handle = _Server()
    yield handle
    handle.close()


def test_server_serves_the_dashboard(server: _Server) -> None:
    status, body, content_type = server.get("/")
    assert status == 200
    assert b"<html" in body.lower()
    assert "text/html" in content_type


def test_server_get_of_an_unknown_path_is_404(server: _Server) -> None:
    status, body, _ = server.get("/etc/passwd")
    assert status == 404
    assert b"not found" in body


def test_server_post_api_state(server: _Server) -> None:
    status, payload = server.post("/api/state", b"{}")
    assert status == 200
    assert "boundary" in payload


def test_server_rejects_invalid_json(server: _Server) -> None:
    status, payload = server.post("/api/state", b"{not json")
    assert status == 400
    assert "not valid JSON" in payload["error"]


def test_server_rejects_a_non_object_body(server: _Server) -> None:
    status, payload = server.post("/api/state", b"[1, 2]")
    assert status == 400
    assert "JSON object" in payload["error"]


def test_server_rejects_an_oversized_body(server: _Server) -> None:
    import socket

    with socket.create_connection(
        ("127.0.0.1", server.server.server_address[1]), timeout=10
    ) as sock:
        head = (
            "POST /api/state HTTP/1.1\r\n"
            f"Content-Length: {MAX_BODY_BYTES + 1}\r\n"
            "Content-Type: application/json\r\n\r\n"
        ).encode("ascii")
        sock.sendall(head)
        sock.shutdown(socket.SHUT_WR)
        response = sock.recv(4096).decode("latin-1")
    assert "413" in response.splitlines()[0]
