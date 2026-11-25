"""Host Doctor: read-only host, driver, tool, and link checks."""

from __future__ import annotations

import glob
import os
import platform
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from cairn.core.errors import ToolError
from cairn.core.tristate import Tri
from cairn.tools.manifest import BUNDLED_FASTBOOT_WINDOWS, TOOL_MANIFEST, ToolReport
from cairn.tools.runner import ToolResult, ToolRunner

SOAK_ATTEMPTS_DEFAULT: Final = 5
SOAK_WARN_MS: Final = 2000.0
SOAK_FAIL_MS: Final = 5000.0
POWERSHELL_TIMEOUT_S: Final = 15.0
USB_SUBGROUP_GUID: Final = "2a737441-1930-4402-8d77-b2bebba308a3"

WINDOWS_DRIVER_PATHS: Final[tuple[str, ...]] = (
    r"C:\Program Files\Google\USB Driver",
    r"C:\Program Files (x86)\Google\USB Driver",
    r"~\AppData\Local\Android\Sdk\extras\google\usb_driver",
)
VM_MARKERS: Final[tuple[str, ...]] = (
    "vmware",
    "virtualbox",
    "innotek",
    "qemu",
    "kvm",
    "xen",
    "hyper-v",
    "virtual machine",
    "parallels",
    "bhyve",
)


@dataclass(frozen=True, slots=True)
class HostCheck:
    name: str
    state: Tri
    detail: str
    required: bool = True
    data: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "state": self.state.name,
            "required": self.required,
            "detail": self.detail,
            "data": dict(self.data),
        }


@dataclass(frozen=True, slots=True)
class SoakResult:
    attempts: int
    failures: int
    max_ms: float
    state: Tri
    detail: str

    def to_check(self) -> HostCheck:
        return HostCheck(
            name="link-soak",
            state=self.state,
            detail=self.detail,
            required=True,
            data={
                "attempts": self.attempts,
                "failures": self.failures,
                "max_ms": round(self.max_ms, 3),
                "warn_ms": SOAK_WARN_MS,
                "fail_ms": SOAK_FAIL_MS,
            },
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "attempts": self.attempts,
            "failures": self.failures,
            "max_ms": round(self.max_ms, 3),
            "state": self.state.name,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class HostReport:
    environment: Mapping[str, str]
    checks: tuple[HostCheck, ...]
    soak: SoakResult | None
    tool: Mapping[str, object]
    simulated: bool

    @property
    def verdict(self) -> Tri:
        required = [check.state for check in self.checks if check.required]
        return Tri.all_of(required)

    @property
    def exit_code(self) -> int:
        if self.verdict is Tri.TRUE:
            return 0
        if self.verdict is Tri.FALSE:
            return 1
        return 3

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "ok",
            "verdict": self.verdict.name,
            "simulated": self.simulated,
            "environment": dict(self.environment),
            "tool": dict(self.tool),
            "checks": [check.to_dict() for check in self.checks],
            "soak": None if self.soak is None else self.soak.to_dict(),
            "message": "Read-only host checks. No device writes were performed.",
        }


def detect_wsl(release: str, environ: Mapping[str, str]) -> bool:
    if "microsoft" in release.lower() or "wsl" in release.lower():
        return True
    return "WSL_DISTRO_NAME" in environ or "WSL_INTEROP" in environ


def detect_vm(text: str) -> str | None:
    haystack = text.lower()
    for marker in VM_MARKERS:
        if marker in haystack:
            return marker
    return None


def classify_usb_selective_suspend(output: str) -> Tri:
    """TRUE means selective suspend is off (safer for long transfers)."""
    values = re.findall(r"Current AC Power Setting Index:\s*(0x[0-9a-fA-F]+|\d+)", output)
    if not values:
        return Tri.UNKNOWN
    enabled = any(int(value, 0) != 0 for value in values)
    return Tri.FALSE if enabled else Tri.TRUE


def classify_soak(results: Sequence[ToolResult]) -> SoakResult:
    if not results:
        return SoakResult(
            attempts=0,
            failures=0,
            max_ms=0.0,
            state=Tri.UNKNOWN,
            detail="link soak did not run",
        )
    failures = sum(1 for result in results if not result.ok)
    max_ms = max(result.duration_s * 1000.0 for result in results)
    if failures:
        state = Tri.FALSE
        detail = f"{failures} of {len(results)} probes failed; suspect cable, port, or hub"
    elif max_ms > SOAK_FAIL_MS:
        state = Tri.FALSE
        detail = f"slowest probe {max_ms:.0f} ms exceeds the {SOAK_FAIL_MS:.0f} ms limit"
    elif max_ms > SOAK_WARN_MS:
        state = Tri.UNKNOWN
        detail = f"slowest probe {max_ms:.0f} ms exceeds the {SOAK_WARN_MS:.0f} ms warning line"
    else:
        state = Tri.TRUE
        detail = f"{len(results)} probes passed; slowest {max_ms:.0f} ms"
    return SoakResult(
        attempts=len(results),
        failures=failures,
        max_ms=max_ms,
        state=state,
        detail=detail,
    )


def assess_driver_paths(platform_name: str, home: Path | None = None) -> HostCheck:
    if platform_name != "Windows":
        return HostCheck(
            name="driver",
            state=Tri.TRUE,
            detail="Windows driver check is not applicable on this host",
            required=False,
        )
    root = home if home is not None else Path.home()
    found: list[str] = []
    for raw_path in WINDOWS_DRIVER_PATHS:
        expanded = Path(raw_path.replace("~", str(root)))
        if expanded.exists():
            found.append(str(expanded))
    if found:
        return HostCheck(
            name="driver",
            state=Tri.TRUE,
            detail="known Android USB driver package found",
            required=False,
            data={"paths": found},
        )
    return HostCheck(
        name="driver",
        state=Tri.UNKNOWN,
        detail=(
            "no known Google USB driver package found; vendor drivers may still work, "
            "and a working link soak is the stronger signal"
        ),
        required=False,
    )


def assess_usb_controllers(count: int | None) -> HostCheck:
    if count is None:
        return HostCheck(
            name="usb-controllers",
            state=Tri.UNKNOWN,
            detail="could not enumerate USB host controllers",
        )
    if count == 0:
        return HostCheck(
            name="usb-controllers",
            state=Tri.FALSE,
            detail="no USB host controllers were found",
            data={"count": 0},
        )
    return HostCheck(
        name="usb-controllers",
        state=Tri.TRUE,
        detail=f"{count} USB host controller(s) found",
        data={"count": count},
    )


def assess_power(platform_name: str, output: str | None) -> HostCheck:
    if platform_name != "Windows":
        return HostCheck(
            name="usb-power",
            state=Tri.TRUE,
            detail="Windows USB power check is not applicable on this host",
            required=False,
        )
    if output is None:
        return HostCheck(
            name="usb-power",
            state=Tri.UNKNOWN,
            detail="could not read the USB power policy",
            required=False,
        )
    state = classify_usb_selective_suspend(output)
    if state is Tri.FALSE:
        detail = "USB selective suspend is enabled; disable it for long transfers"
    elif state is Tri.TRUE:
        detail = "USB selective suspend is disabled"
    else:
        detail = "could not parse the USB selective suspend setting"
    return HostCheck(
        name="usb-power",
        state=state,
        detail=detail,
        required=False,
    )


def assess_antivirus(platform_name: str, names: Sequence[str]) -> HostCheck:
    if platform_name != "Windows":
        return HostCheck(
            name="antivirus",
            state=Tri.TRUE,
            detail="Windows antivirus check is not applicable on this host",
            required=False,
        )
    if names:
        return HostCheck(
            name="antivirus",
            state=Tri.UNKNOWN,
            detail="antivirus products present; USB filtering can slow or drop transfers",
            required=False,
            data={"products": list(names)},
        )
    return HostCheck(
        name="antivirus",
        state=Tri.TRUE,
        detail="no antivirus product reported by SecurityCenter2",
        required=False,
    )


def check_tool(
    name: str,
    report: ToolReport | None,
    error: ToolError | None,
    *,
    simulated: bool,
    required: bool = True,
) -> HostCheck:
    if simulated:
        return HostCheck(
            name=f"{name}-tool",
            state=Tri.TRUE,
            detail="simulated tool; not a real host check",
            required=required,
            data={"simulated": True},
        )
    if error is not None:
        return HostCheck(
            name=f"{name}-tool",
            state=Tri.UNKNOWN,
            detail=str(error),
            required=required,
        )
    if report is None:
        return HostCheck(
            name=f"{name}-tool",
            state=Tri.UNKNOWN,
            detail=f"{name} was not found",
            required=required,
        )
    state = Tri.TRUE if report.ok else Tri.FALSE
    return HostCheck(
        name=f"{name}-tool",
        state=state,
        detail=report.detail,
        required=required,
        data={
            "path": str(report.path),
            "version": report.version,
            "sha256": report.sha256,
            "license": report.license,
            "gpl": report.gpl,
            "sha256_pinned": report.sha256_pinned,
            "sha256_match": report.sha256_match,
            "min_version": report.min_version,
            "meets_minimum": report.meets_minimum,
        },
    )


class HostDoctor:
    """Run read-only host checks with optional dependency injection."""

    def __init__(
        self,
        runner: ToolRunner,
        *,
        platform_name: str | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._runner = runner
        self._platform = platform_name if platform_name is not None else platform.system()
        self._environ = dict(environ if environ is not None else os.environ)

    def run(
        self,
        *,
        fastboot_prefix: Sequence[str] | None,
        fastboot_label: str,
        adb_path: Path | None,
        serial: str | None,
        soak_attempts: int,
        simulated: bool,
        fastboot_extra_env: Mapping[str, str] | None = None,
    ) -> HostReport:
        if soak_attempts < 0:
            raise ValueError("soak_attempts must not be negative")

        checks: list[HostCheck] = []
        release = platform.release()
        wsl = detect_wsl(release, self._environ)
        checks.append(
            HostCheck(
                name="wsl",
                state=Tri.FALSE if wsl else Tri.TRUE,
                detail=(
                    "Windows Subsystem for Linux detected; USB passthrough is not a "
                    "supported flashing host"
                    if wsl
                    else "native host, not WSL"
                ),
            )
        )

        vm = self._detect_vm()
        checks.append(
            HostCheck(
                name="virtualization",
                state=Tri.UNKNOWN if vm else Tri.TRUE,
                detail=(
                    f"virtual machine markers found ({vm}); USB passthrough may be unstable"
                    if vm
                    else "no virtual machine markers found"
                ),
                required=False,
                data={} if vm is None else {"marker": vm},
            )
        )

        usb_count = self._usb_controller_count()
        checks.append(assess_usb_controllers(usb_count))
        checks.append(assess_driver_paths(self._platform))
        checks.append(assess_power(self._platform, self._power_output()))
        checks.append(assess_antivirus(self._platform, self._antivirus_names()))

        fastboot_report: ToolReport | None = None
        fastboot_error: ToolError | None = None
        if not simulated and fastboot_prefix is not None:
            fastboot_path = Path(fastboot_prefix[0])
            spec = (
                BUNDLED_FASTBOOT_WINDOWS if fastboot_path.name.lower() == "fastboot.exe" else None
            )
            try:
                fastboot_report = TOOL_MANIFEST.verify(
                    "fastboot", fastboot_path, self._runner, spec=spec
                )
            except ToolError as exc:
                fastboot_error = exc
        checks.append(
            check_tool(
                "fastboot",
                fastboot_report,
                fastboot_error,
                simulated=simulated,
            )
        )

        adb_report: ToolReport | None = None
        adb_error: ToolError | None = None
        if not simulated and adb_path is not None:
            try:
                adb_report = TOOL_MANIFEST.verify("adb", adb_path, self._runner)
            except ToolError as exc:
                adb_error = exc
        checks.append(
            check_tool(
                "adb",
                adb_report,
                adb_error if adb_path is not None else None,
                simulated=simulated,
                required=False,
            )
            if adb_path is not None or simulated
            else HostCheck(
                name="adb-tool",
                state=Tri.UNKNOWN,
                detail="adb was not found",
                required=False,
            )
        )

        soak: SoakResult | None = None
        if fastboot_prefix is None:
            checks.append(
                HostCheck(
                    name="link-soak",
                    state=Tri.UNKNOWN,
                    detail="fastboot was not found; the device link was not tested",
                )
            )
        elif soak_attempts == 0:
            checks.append(
                HostCheck(
                    name="link-soak",
                    state=Tri.UNKNOWN,
                    detail="link soak was disabled",
                )
            )
        else:
            from cairn.adapters.fastboot import FastbootClient, parse_fastboot_devices

            client = FastbootClient(
                fastboot_prefix,
                runner=self._runner,
                extra_env=fastboot_extra_env,
            )
            target = serial
            if target is None:
                devices = client.devices()
                candidates = parse_fastboot_devices(f"{devices.stdout}\n{devices.stderr}")
                target = candidates[0] if candidates else None
                if target is None:
                    checks.append(
                        HostCheck(
                            name="link-soak",
                            state=Tri.UNKNOWN,
                            detail=(
                                "no fastboot device detected; connect the device and rerun "
                                "to test the cable, port, and hub"
                            ),
                        )
                    )
            if target is not None:
                results = [client.getvar_all(serial=target) for _ in range(soak_attempts)]
                soak = classify_soak(results)
                checks.append(soak.to_check())

        environment = {
            "os": self._platform,
            "release": release,
            "machine": platform.machine(),
            "python": platform.python_version(),
            "fastboot": fastboot_label,
        }
        tool = {
            "fastboot": (
                {"simulated": True}
                if simulated
                else None
                if fastboot_report is None
                else {
                    "path": str(fastboot_report.path),
                    "version": fastboot_report.version,
                    "sha256": fastboot_report.sha256,
                    "license": fastboot_report.license,
                    "manifest_ok": fastboot_report.ok,
                }
            ),
        }
        return HostReport(
            environment=environment,
            checks=tuple(checks),
            soak=soak,
            tool=tool,
            simulated=simulated,
        )

    def _powershell(self, command: str) -> ToolResult | None:
        system_root = self._environ.get("SYSTEMROOT", r"C:\Windows")
        module_path = f"{system_root}\\System32\\WindowsPowerShell\\v1.0\\Modules"
        try:
            return self._runner.run(
                (
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    command,
                ),
                timeout_s=POWERSHELL_TIMEOUT_S,
                extra_env={"PSModulePath": module_path},
            )
        except ToolError:
            return None

    def _usb_controller_count(self) -> int | None:
        if self._platform == "Windows":
            result = self._powershell(
                "(Get-CimInstance -ClassName Win32_USBController | Measure-Object).Count"
            )
            if result is None or not result.ok:
                return None
            try:
                return int(result.stdout.strip())
            except ValueError:
                return None
        paths = glob.glob("/sys/bus/usb/devices/usb*")
        return len(paths) if paths else None

    def _detect_vm(self) -> str | None:
        if self._platform == "Windows":
            result = self._powershell(
                "$cs = Get-CimInstance -ClassName Win32_ComputerSystem; "
                "$cs.Manufacturer + '|' + $cs.Model"
            )
            if result is None or not result.ok:
                return None
            return detect_vm(result.stdout)
        product = _read_first(
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
        )
        return detect_vm(product) if product else None

    def _power_output(self) -> str | None:
        if self._platform != "Windows":
            return None
        try:
            result = self._runner.run(
                ("powercfg.exe", "/q", "SCHEME_CURRENT", USB_SUBGROUP_GUID),
                timeout_s=POWERSHELL_TIMEOUT_S,
            )
        except ToolError:
            return None
        return result.stdout + "\n" + result.stderr if result.exit_code == 0 else None

    def _antivirus_names(self) -> tuple[str, ...]:
        if self._platform != "Windows":
            return ()
        result = self._powershell(
            "Get-CimInstance -Namespace root/SecurityCenter2 "
            "-ClassName AntiVirusProduct -ErrorAction SilentlyContinue "
            "| ForEach-Object { $_.displayName }"
        )
        if result is None or not result.ok:
            return ()
        return tuple(line.strip() for line in result.stdout.splitlines() if line.strip())


def _read_first(*paths: str) -> str | None:
    for path in paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if text:
            return text
    return None
