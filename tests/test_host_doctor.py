from __future__ import annotations

from pathlib import Path

from cairn.core.tristate import Tri
from cairn.host import doctor
from cairn.host.doctor import (
    HostCheck,
    HostReport,
    SoakResult,
    assess_antivirus,
    assess_driver_paths,
    assess_power,
    assess_usb_controllers,
    check_tool,
    classify_soak,
    classify_usb_selective_suspend,
    detect_vm,
    detect_wsl,
)
from cairn.tools.runner import ToolResult


def probe(exit_code: int = 0, duration_s: float = 0.1) -> ToolResult:
    return ToolResult(
        argv=("fastboot", "getvar", "all"),
        exit_code=exit_code,
        stdout="",
        stderr="",
        duration_s=duration_s,
    )


def make_report(*checks: HostCheck, soak: SoakResult | None = None) -> HostReport:
    return HostReport(
        environment={},
        checks=checks,
        soak=soak,
        tool={},
        simulated=False,
    )


def test_detect_wsl() -> None:
    assert detect_wsl("5.15.153.1-microsoft-standard-WSL2", {})
    assert detect_wsl("6.8.0-azure", {"WSL_DISTRO_NAME": "Ubuntu"})
    assert not detect_wsl("6.8.0-1017-azure", {})


def test_detect_vm() -> None:
    assert detect_vm("VMware Virtual Platform") == "vmware"
    assert detect_vm("VirtualBox") == "virtualbox"
    assert detect_vm("Dell Inc. XPS 13") is None


def test_usb_selective_suspend_parser() -> None:
    disabled = (
        "  Power Setting GUID: 48e6b7a6-50f5-4782-a5d4-53bb8f07e226\n"
        "    Current AC Power Setting Index: 0x00000000\n"
    )
    enabled = (
        "  Power Setting GUID: 48e6b7a6-50f5-4782-a5d4-53bb8f07e226\n"
        "    Current AC Power Setting Index: 0x00000001\n"
    )
    assert classify_usb_selective_suspend(disabled) is Tri.TRUE
    assert classify_usb_selective_suspend(enabled) is Tri.FALSE
    assert classify_usb_selective_suspend("no settings") is Tri.UNKNOWN


def test_usb_controller_assessment() -> None:
    assert assess_usb_controllers(2).state is Tri.TRUE
    assert assess_usb_controllers(0).state is Tri.FALSE
    assert assess_usb_controllers(None).state is Tri.UNKNOWN
    assert assess_usb_controllers(0).required


def test_driver_assessment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(doctor, "WINDOWS_DRIVER_PATHS", (str(tmp_path / "driver"),))
    missing = assess_driver_paths("Windows", home=tmp_path)
    assert missing.state is Tri.UNKNOWN
    assert not missing.required

    (tmp_path / "driver").mkdir()
    found = assess_driver_paths("Windows", home=tmp_path)
    assert found.state is Tri.TRUE
    assert not found.required

    other = assess_driver_paths("Linux")
    assert other.state is Tri.TRUE
    assert not other.required


def test_power_assessment() -> None:
    assert assess_power("Windows", None).state is Tri.UNKNOWN
    assert assess_power("Linux", None).state is Tri.TRUE
    assert not assess_power("Linux", None).required


def test_antivirus_assessment() -> None:
    assert assess_antivirus("Windows", ()).state is Tri.TRUE
    warning = assess_antivirus("Windows", ("Defender",))
    assert warning.state is Tri.UNKNOWN
    assert not warning.required
    assert warning.data["products"] == ["Defender"]


def test_soak_classification() -> None:
    healthy = classify_soak([probe(), probe(duration_s=0.2)])
    assert healthy.state is Tri.TRUE
    assert healthy.failures == 0

    failed = classify_soak([probe(), probe(exit_code=1)])
    assert failed.state is Tri.FALSE
    assert failed.failures == 1

    slow = classify_soak([probe(duration_s=2.5)])
    assert slow.state is Tri.UNKNOWN

    too_slow = classify_soak([probe(duration_s=5.5)])
    assert too_slow.state is Tri.FALSE

    empty = classify_soak([])
    assert empty.state is Tri.UNKNOWN


def test_report_verdict_uses_required_checks_only() -> None:
    passing = make_report(
        HostCheck("a", Tri.TRUE, "ok"),
        HostCheck("warning", Tri.UNKNOWN, "advisory", required=False),
        HostCheck("note", Tri.FALSE, "advisory", required=False),
    )
    assert passing.verdict is Tri.TRUE
    assert passing.exit_code == 0

    failed = make_report(HostCheck("a", Tri.FALSE, "bad"))
    assert failed.verdict is Tri.FALSE
    assert failed.exit_code == 1

    incomplete = make_report(HostCheck("a", Tri.UNKNOWN, "unknown"))
    assert incomplete.verdict is Tri.UNKNOWN
    assert incomplete.exit_code == 3


def test_report_serializes_soak() -> None:
    soak = classify_soak([probe()])
    report = make_report(
        HostCheck("a", Tri.TRUE, "ok"),
        soak.to_check(),
        soak=soak,
    )
    payload = report.to_dict()
    assert payload["verdict"] == "TRUE"
    assert payload["soak"]["attempts"] == 1
    assert payload["message"].startswith("Read-only")


def test_check_tool_states() -> None:
    assert check_tool("fastboot", None, None, simulated=False).state is Tri.UNKNOWN
    simulated = check_tool("fastboot", None, None, simulated=True)
    assert simulated.state is Tri.TRUE
    assert simulated.data["simulated"] is True
