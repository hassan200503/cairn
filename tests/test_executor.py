"""Journal, executor gates, idempotency, resume, and crash-at-every-point tests.

The crash harness kills the executor after every journal record and proves that a
resumed run reaches exactly the same final state as an uninterrupted run. All
execution here is simulator or in-memory transport; no real device is touched.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from cairn.approval import (
    ApprovalInputs,
    ApprovalVerdict,
    DeviceBinding,
    DeviceBindingSource,
    generate_approval_key,
    issue_approval,
)
from cairn.core.tristate import Tri
from cairn.executor import (
    ExecutionRequest,
    ExecutorRefused,
    Idempotency,
    Journal,
    JournalCorruptError,
    JournalKind,
    JournalWriteError,
    SafetyGate,
    execute_plan,
    idempotency_of,
    staged_image_path,
)
from cairn.executor.executor import SimulatedCrash, WriteTransport
from cairn.package.archive import PackageManifest, load_package
from cairn.plan.planner import Plan, PlanAction, PlanFacts, PlanOptions, build_plan
from cairn.provenance.hash_index import load_hash_index, verify_manifest
from cairn.safety.engine import SafetyReport
from cairn.tools.runner import ToolResult

INFO_TEXT = """\
version 1
flash boot boot.img
erase cache
reboot bootloader
"""

_BOOT_BYTES = b"boot-image-bytes"


def _hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _package(path: Path, images: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, blob in images.items():
            archive.writestr(name, blob)
        archive.writestr("fastboot-info.txt", INFO_TEXT)
    return path


def _index(path: Path, package: Path) -> Path:
    manifest = load_package(package, hash_files=True, hash_archive=True)
    payload = {
        "schema_version": 1,
        "packages": [
            {
                "id": "executor-test",
                "archive_sha256": manifest.archive_sha256,
                "entries": {entry.name: entry.sha256 for entry in manifest.entries},
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _manifest(package: Path) -> PackageManifest:
    return load_package(package, hash_files=True, hash_archive=True)


def _plan(package: Path, index: Path) -> Plan:
    manifest = _manifest(package)
    provenance = verify_manifest(load_hash_index(index), manifest)
    plan = build_plan(manifest, provenance, options=PlanOptions(), facts=PlanFacts())
    assert plan.executable
    return plan


def _entry_hashes(package: Path) -> dict[str, str]:
    return {entry.name: (entry.sha256 or "").lower() for entry in _manifest(package).entries}


def _safety_report() -> SafetyReport:
    return SafetyReport(
        rules=(),
        overrides=(),
        verdict=Tri.TRUE,
        can_proceed=True,
        blocking=(),
        evidence_snapshot_sha256=_hex("snapshot"),
        report_text="test report",
    )


def _token(package: Path, plan: Plan, nonce: str, fingerprint: str) -> tuple[bytes, str]:
    key = generate_approval_key()
    inputs = ApprovalInputs.from_manifest(
        _manifest(package),
        plan,
        _safety_report(),
        DeviceBinding(
            nonce=nonce,
            fingerprint_sha256=fingerprint,
            source=DeviceBindingSource.CALLER,
        ),
    )
    return key, issue_approval(inputs, key, operator="op", reason="executor test run").to_json()


def _verdict(state: Tri) -> ApprovalVerdict:
    return ApprovalVerdict(
        state=state,
        reasons=("ok",) if state is Tri.TRUE else ("refused",),
        mismatches=(),
        token_sha256=_hex("token"),
    )


def _request(
    env: tuple[Plan, Path, dict[str, str], Path],
    transport: WriteTransport,
    approval_state: Tri = Tri.TRUE,
    *,
    hashes_override: dict[str, str] | None = None,
    safety: SafetyGate | None = None,
) -> ExecutionRequest:
    plan, package, hashes, tmp_path = env
    return ExecutionRequest(
        plan=plan,
        package_path=package,
        expected_entry_hashes=hashes_override if hashes_override is not None else hashes,
        safety=safety if safety is not None else SafetyGate(verdict=Tri.TRUE),
        approval=_verdict(approval_state),
        transport=transport,
        staging_dir=tmp_path / "staging",
    )


class FakeDevice:
    """In-memory stand-in for device state across crashes in one test process."""

    def __init__(self) -> None:
        self.flashed: dict[str, bytes] = {}
        self.erased: set[str] = set()
        self.reboots: list[str] = []


class FakeTransport(WriteTransport):
    def __init__(
        self,
        device: FakeDevice,
        *,
        fail_partitions: frozenset[str] = frozenset(),
    ) -> None:
        self.device = device
        self.fail_partitions = fail_partitions
        self.calls: list[tuple[str, ...]] = []

    def run_write(self, step: object, *, image_path: Path | None, timeout_s: float) -> ToolResult:
        from cairn.plan.planner import PlanStep

        assert isinstance(step, PlanStep)
        argv = (step.action.value, step.partition or "", str(image_path or ""))
        self.calls.append(argv)
        if step.partition in self.fail_partitions:
            return ToolResult(
                argv=argv,
                exit_code=1,
                stdout="",
                stderr="FAILED (remote: 'simulated failure')",
                duration_s=0.0,
            )
        if step.action is PlanAction.FLASH:
            assert image_path is not None
            self.device.flashed[step.partition] = image_path.read_bytes()
        elif step.action is PlanAction.ERASE:
            assert step.partition is not None
            self.device.erased.add(step.partition)
        elif step.action is PlanAction.REBOOT:
            assert step.target is not None
            self.device.reboots.append(step.target)
        return ToolResult(argv=argv, exit_code=0, stdout="OKAY", stderr="", duration_s=0.0)


@pytest.fixture
def env(tmp_path: Path) -> tuple[Plan, Path, dict[str, str], Path]:
    package = _package(tmp_path / "factory.zip", {"boot.img": _BOOT_BYTES})
    index = _index(tmp_path / "index.json", package)
    plan = _plan(package, index)
    hashes = _entry_hashes(package)
    return plan, package, hashes, tmp_path


# ---------------------------------------------------------------------------
# Journal
# ---------------------------------------------------------------------------


def test_journal_chain_survives_reload(tmp_path: Path) -> None:
    path = tmp_path / "journal.jsonl"
    journal = Journal.create(path, {"plan_sha256": _hex("p")})
    journal.append(JournalKind.STEP_STARTED, {"number": 1})
    journal.append(JournalKind.STEP_DONE, {"number": 1})

    loaded = Journal.load(path)
    assert not loaded.torn_tail
    assert [record.seq for record in loaded.records] == [0, 1, 2]
    assert loaded.records[0].kind is JournalKind.SESSION
    assert loaded.records[2].prev_sha256 == loaded.records[1].record_sha256


def test_journal_refuses_duplicate_creation_and_corruption(tmp_path: Path) -> None:
    path = tmp_path / "journal.jsonl"
    Journal.create(path, {"plan_sha256": _hex("p")})
    with pytest.raises(JournalWriteError):
        Journal.create(path, {"plan_sha256": _hex("p")})

    lines = path.read_text(encoding="utf-8").splitlines()
    document = json.loads(lines[0])
    document["payload"]["plan_sha256"] = _hex("tampered")
    lines[0] = json.dumps(document)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(JournalCorruptError):
        Journal.load(path)


def test_journal_torn_tail_is_reported_and_earlier_records_survive(tmp_path: Path) -> None:
    path = tmp_path / "journal.jsonl"
    journal = Journal.create(path, {"plan_sha256": _hex("p")})
    journal.append(JournalKind.STEP_STARTED, {"number": 1})
    with open(path, "ab") as handle:
        handle.write(b'{"seq":2,"kind":"step_d')  # torn write, no newline

    loaded = Journal.load(path)
    assert loaded.torn_tail
    assert len(loaded.records) == 2
    resumed = Journal.resume(path)
    record = resumed.append(JournalKind.STEP_DONE, {"number": 1})
    assert record.seq == 2
    reloaded = Journal.load(path)
    assert not reloaded.torn_tail
    assert reloaded.records[2].prev_sha256 == loaded.records[1].record_sha256


# ---------------------------------------------------------------------------
# Executor gates and happy path
# ---------------------------------------------------------------------------


def test_execute_happy_path_records_every_step(env) -> None:
    _, _, _, tmp_path = env
    device = FakeDevice()
    result = execute_plan(_request(env, FakeTransport(device)), tmp_path / "journal.jsonl")

    assert result.verdict is Tri.TRUE
    assert result.completed
    assert result.simulated
    assert device.flashed["boot"] == _BOOT_BYTES
    assert "cache" in device.erased
    assert device.reboots == ["bootloader"]
    journal = Journal.load(tmp_path / "journal.jsonl")
    kinds = [record.kind for record in journal.records]
    assert kinds == [
        JournalKind.SESSION,
        JournalKind.STEP_STARTED,
        JournalKind.STEP_DONE,
        JournalKind.STEP_STARTED,
        JournalKind.STEP_DONE,
        JournalKind.STEP_STARTED,
        JournalKind.STEP_DONE,
        JournalKind.COMPLETED,
    ]


def test_execute_refuses_unverified_plan_hash(env) -> None:
    plan, package, hashes, tmp_path = env
    from dataclasses import replace

    tampered = replace(plan, plan_sha256="0" * 64)
    device = FakeDevice()
    request = ExecutionRequest(
        plan=tampered,
        package_path=package,
        expected_entry_hashes=hashes,
        safety=SafetyGate(verdict=Tri.TRUE),
        approval=_verdict(Tri.TRUE),
        transport=FakeTransport(device),
        staging_dir=tmp_path / "staging",
    )
    with pytest.raises(ExecutorRefused, match="plan hash"):
        execute_plan(request, tmp_path / "journal.jsonl")
    assert device.flashed == {}


def test_execute_refuses_false_safety_and_unverified_approval(env) -> None:
    _, _, _, tmp_path = env
    device = FakeDevice()

    with pytest.raises(ExecutorRefused, match="FALSE"):
        execute_plan(
            _request(
                env,
                FakeTransport(device),
                safety=SafetyGate(verdict=Tri.FALSE, blocking=("SR-004",)),
            ),
            tmp_path / "journal.jsonl",
        )
    with pytest.raises(ExecutorRefused, match="approval"):
        execute_plan(
            _request(env, FakeTransport(device), approval_state=Tri.UNKNOWN),
            tmp_path / "journal.jsonl",
        )
    assert device.flashed == {}


def test_execute_refuses_image_that_changed_after_approval(env) -> None:
    _, _, _, tmp_path = env
    tampered = {"boot.img": _hex("different-bytes")}
    device = FakeDevice()
    request = _request(env, FakeTransport(device), hashes_override=tampered)
    with pytest.raises(ExecutorRefused, match="changed after approval"):
        execute_plan(request, tmp_path / "journal.jsonl")
    assert device.flashed == {}
    assert list((tmp_path / "staging").glob("*")) == []


def test_execute_refuses_image_not_covered_by_binding(env) -> None:
    _, _, _, tmp_path = env
    device = FakeDevice()
    request = _request(env, FakeTransport(device), hashes_override={"other.img": _hex("x")})
    with pytest.raises(ExecutorRefused, match="not covered by the approval binding"):
        execute_plan(request, tmp_path / "journal.jsonl")
    assert device.flashed == {}


def test_execute_stops_on_failed_step_and_resume_does_not_blindly_retry(env) -> None:
    _, _, _, tmp_path = env
    journal_path = tmp_path / "journal.jsonl"
    device = FakeDevice()
    failing = FakeTransport(device, fail_partitions=frozenset({"cache"}))
    result = execute_plan(_request(env, failing), journal_path)
    assert result.verdict is Tri.FALSE
    assert result.aborted_step == 2
    assert device.flashed == {"boot": _BOOT_BYTES}

    # Resume refuses to retry the failed step; the fallback demands a human.
    healthy = FakeTransport(device)
    resumed = execute_plan(_request(env, healthy), journal_path)
    assert resumed.verdict is Tri.UNKNOWN
    assert resumed.aborted_step == 2
    assert healthy.calls == []  # nothing was re-executed


def test_idempotency_classification(env) -> None:
    plan, _, _, _ = env
    flash, erase, reboot = plan.steps
    assert idempotency_of(flash) is Idempotency.IDEMPOTENT
    assert idempotency_of(erase) is Idempotency.IDEMPOTENT
    assert idempotency_of(reboot) is Idempotency.NON_IDEMPOTENT


# ---------------------------------------------------------------------------
# Resume semantics
# ---------------------------------------------------------------------------


def _run_until(
    env: tuple[Plan, Path, dict[str, str], Path],
    device: FakeDevice,
    journal_path: Path,
    *,
    kill_after: int,
) -> tuple[str, dict[str, object]]:
    """Kill execution after ``kill_after`` hook calls; return the killed record."""
    counter = {"n": 0}
    killed: dict[str, object] = {}

    def hook(record: object) -> None:
        from cairn.executor import JournalRecord

        assert isinstance(record, JournalRecord)
        counter["n"] += 1
        killed["kind"] = record.kind.value
        killed["payload"] = dict(record.payload)
        if counter["n"] >= kill_after:
            raise SimulatedCrash()

    with pytest.raises(SimulatedCrash):
        execute_plan(_request(env, FakeTransport(device)), journal_path, crash_hook=hook)
    return str(killed["kind"]), dict(killed["payload"])


def test_resume_after_interrupted_idempotent_step_reruns_it(env) -> None:
    _, _, _, tmp_path = env
    journal_path = tmp_path / "journal.jsonl"
    device = FakeDevice()
    # session + started(step1) = 2 durable records, then die before the write.
    _run_until(env, device, journal_path, kill_after=2)
    assert device.flashed == {}

    resumed = execute_plan(_request(env, FakeTransport(device)), journal_path)
    assert resumed.verdict is Tri.TRUE
    assert resumed.completed
    assert device.flashed["boot"] == _BOOT_BYTES
    assert {step.number: step.state for step in resumed.steps} == {
        1: "done",
        2: "done",
        3: "done",
    }


def test_resume_after_interrupted_reboot_refuses_to_rerun(env) -> None:
    _, _, _, tmp_path = env
    journal_path = tmp_path / "journal.jsonl"
    device = FakeDevice()
    # session + 2 full steps + started(reboot) = 6 records, then die before reboot.
    _run_until(env, device, journal_path, kill_after=6)
    assert device.reboots == []

    resumed = execute_plan(_request(env, FakeTransport(device)), journal_path)
    assert resumed.verdict is Tri.UNKNOWN
    assert resumed.aborted_step == 3
    assert device.reboots == []  # the reboot was NOT blindly repeated
    assert "stop-and-reprobe" in resumed.reason


def test_resume_rejects_journal_for_a_different_plan(env) -> None:
    _, _, hashes, tmp_path = env
    journal_path = tmp_path / "journal.jsonl"
    device = FakeDevice()
    execute_plan(_request(env, FakeTransport(device)), journal_path)

    other = _package(tmp_path / "other.zip", {"boot.img": b"other"})
    other_plan = _plan(other, _index(tmp_path / "other-index.json", other))
    request = ExecutionRequest(
        plan=other_plan,
        package_path=other,
        expected_entry_hashes=hashes,
        safety=SafetyGate(verdict=Tri.TRUE),
        approval=_verdict(Tri.TRUE),
        transport=FakeTransport(device),
        staging_dir=tmp_path / "staging",
    )
    with pytest.raises(ExecutorRefused, match="different plan"):
        execute_plan(request, journal_path)


# ---------------------------------------------------------------------------
# Crash harness: kill at every journal point
# ---------------------------------------------------------------------------


def test_crash_at_every_journal_point_reaches_the_same_final_state(env) -> None:
    _, _, _, tmp_path = env
    reference_device = FakeDevice()
    reference = execute_plan(
        _request(env, FakeTransport(reference_device)), tmp_path / "reference.jsonl"
    )
    assert reference.verdict is Tri.TRUE
    reference_records = len(Journal.load(tmp_path / "reference.jsonl").records)

    for kill_after in range(1, reference_records + 1):
        workdir = tmp_path / f"crash-{kill_after}"
        workdir.mkdir()
        device = FakeDevice()
        killed_kind, killed_payload = _run_until(
            env, device, workdir / "journal.jsonl", kill_after=kill_after
        )
        resumed = execute_plan(_request(env, FakeTransport(device)), workdir / "journal.jsonl")

        if killed_kind == "step_started" and killed_payload.get("action") == "reboot":
            # An interrupted non-idempotent step must abort, not resume to completion.
            assert resumed.verdict is Tri.UNKNOWN
            assert not resumed.completed
            assert resumed.aborted_step == killed_payload.get("number")
            assert device.reboots == []
            assert device.flashed == {"boot": _BOOT_BYTES}
            assert "cache" in device.erased
            continue

        assert resumed.completed, f"crash after {kill_after} records did not resume"
        assert resumed.verdict is Tri.TRUE
        assert device.flashed == {"boot": _BOOT_BYTES}
        assert "cache" in device.erased
        assert device.reboots == ["bootloader"]
        assert Journal.load(workdir / "journal.jsonl").torn_tail is False


# ---------------------------------------------------------------------------
# Real simulator transport (subprocess) end to end
# ---------------------------------------------------------------------------


def test_simulated_transport_runs_against_the_fastboot_simulator(env, tmp_path) -> None:
    from cairn.adapters.prepare import prepare_fastboot
    from cairn.sim.transcript import Transcript, TranscriptStep, dump_transcript

    plan, package, hashes, _ = env
    staging = tmp_path / "stage"
    transcript = Transcript(
        schema_version=1,
        device={"product": "executor-test"},
        steps=(
            TranscriptStep(
                argv=("flash", "boot", str(staged_image_path(staging, "boot.img"))),
                stdout="OKAY",
            ),
            TranscriptStep(argv=("erase", "cache"), stdout="OKAY"),
            TranscriptStep(argv=("reboot", "bootloader"), stdout="OKAY"),
        ),
    )
    transcript_path = tmp_path / "writes.json"
    dump_transcript(transcript, transcript_path)

    prepared = prepare_fastboot(fastboot=None, simulate=transcript_path)
    assert prepared.simulated
    transport = __import__(
        "cairn.executor", fromlist=["SimulatedFastbootTransport"]
    ).SimulatedFastbootTransport.from_prepared(prepared)

    request = ExecutionRequest(
        plan=plan,
        package_path=package,
        expected_entry_hashes=hashes,
        safety=SafetyGate(verdict=Tri.TRUE),
        approval=_verdict(Tri.TRUE),
        transport=transport,
        staging_dir=staging,
    )
    result = execute_plan(request, tmp_path / "journal.jsonl")
    assert result.verdict is Tri.TRUE
    assert result.completed
    assert all(step.exit_code == 0 for step in result.steps)
