"""Shared, read-only fastboot preparation.

Every command that talks to a device must agree on how the tool is resolved,
verified, labelled, and (for tests) simulated. This module is the single place
that turns CLI options into a ``FastbootClient`` and a tool-identity payload.
It never writes to a device.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from cairn.adapters.fastboot import FastbootClient
from cairn.approval.binding import ApprovalError, ToolBinding
from cairn.core.errors import CairnError, ToolError
from cairn.sim.transcript import TRANSCRIPT_ENV
from cairn.tools.manifest import TOOL_MANIFEST, ToolReport
from cairn.tools.runner import ToolRunner


class PrepareError(CairnError):
    code = "PREPARE_ERROR"


@dataclass(frozen=True, slots=True)
class PreparedFastboot:
    """A verified or simulated fastboot invocation plus its recorded identity."""

    client: FastbootClient
    tool_payload: dict[str, object]
    tool_report: ToolReport | None
    simulated: bool
    prefix: tuple[str, ...] | None
    extra_env: dict[str, str] | None
    label: str


def resolve_tool(name: str, explicit: Path | None, env_var: str) -> Path | None:
    if explicit is not None:
        return explicit
    env_value = os.environ.get(env_var)
    if env_value:
        return Path(env_value)
    found = shutil.which(name)
    return Path(found) if found is not None else None


def resolve_fastboot(explicit: Path | None) -> Path | None:
    return resolve_tool("fastboot", explicit, "CAIRN_FASTBOOT")


def prepare_fastboot(
    *,
    fastboot: Path | None,
    simulate: Path | None,
    runner: ToolRunner | None = None,
) -> PreparedFastboot:
    """Resolve and verify fastboot, or build the transcript simulator."""
    tool_runner = runner if runner is not None else ToolRunner()
    if simulate is not None:
        prefix = (sys.executable, "-m", "cairn.sim.fastboot_sim")
        extra_env = {TRANSCRIPT_ENV: str(simulate)}
        tool_payload: dict[str, object] = {
            "kind": "simulated",
            "name": "fastboot",
            "transcript": str(simulate),
            "manifest_ok": None,
            "simulated": True,
        }
        return PreparedFastboot(
            client=FastbootClient(prefix, runner=tool_runner, extra_env=extra_env),
            tool_payload=tool_payload,
            tool_report=None,
            simulated=True,
            prefix=prefix,
            extra_env=extra_env,
            label="simulated transcript",
        )

    resolved = resolve_fastboot(fastboot)
    if resolved is None:
        raise PrepareError("fastboot not found; pass --fastboot or set CAIRN_FASTBOOT")
    try:
        report = TOOL_MANIFEST.verify("fastboot", resolved, tool_runner)
    except ToolError as exc:
        raise PrepareError(str(exc)) from exc

    tool_payload = {
        "kind": "fastboot",
        "name": "fastboot",
        "path": str(report.path),
        "version": report.version,
        "sha256": report.sha256,
        "license": report.license,
        "manifest_ok": report.ok,
        "manifest_detail": report.detail,
        "simulated": False,
    }
    return PreparedFastboot(
        client=FastbootClient((str(resolved),), runner=tool_runner),
        tool_payload=tool_payload,
        tool_report=report,
        simulated=False,
        prefix=(str(resolved),),
        extra_env=None,
        label=str(resolved),
    )


def tool_binding_from_payload(tool: Mapping[str, object]) -> ToolBinding | None:
    """Reconstruct a tool binding from a recorded fastboot payload."""
    if tool.get("kind") != "fastboot":
        return None
    name = tool.get("name")
    version = tool.get("version")
    sha256 = tool.get("sha256")
    if not isinstance(name, str) or not isinstance(sha256, str):
        return None
    if version is not None and not isinstance(version, str):
        return None
    try:
        return ToolBinding(name=name, version=version, sha256=sha256)
    except ApprovalError:
        return None
