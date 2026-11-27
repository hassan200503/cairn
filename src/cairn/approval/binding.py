"""Canonical approval inputs.

An approval is a consistency boundary, not an authorization boundary. It binds the
plan hash, the safety evidence-snapshot hash, the archive hash, every package entry
hash, a device binding, and the identities of the tools used to produce the plan.
Any change to a bound input invalidates the approval.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from cairn.core.errors import ConfigurationError
from cairn.package.archive import PackageManifest
from cairn.plan.planner import Plan, verify_plan_hash
from cairn.plan.safety import PlanAssessment
from cairn.safety.engine import SafetyReport
from cairn.tools.manifest import ToolReport

APPROVAL_SCHEMA_VERSION: Final = 1
APPROVAL_KIND: Final = "cairn.approval"

_HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE: Final = re.compile(r"^[0-9a-f]{32,128}$")
_TOOL_NAME_RE: Final = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_MAX_ENTRY_NAME_CHARS: Final = 1024
_MAX_TOOL_VERSION_CHARS: Final = 128


class ApprovalError(ConfigurationError):
    code = "APPROVAL_ERROR"


class DeviceBindingSource(StrEnum):
    """How the device fingerprint was obtained."""

    PROBED = "probed"
    CALLER = "caller"


@dataclass(frozen=True, slots=True)
class ToolBinding:
    """The identity of one external tool used to produce the plan."""

    name: str
    version: str | None = None
    sha256: str | None = None

    def __post_init__(self) -> None:
        if _TOOL_NAME_RE.fullmatch(self.name) is None:
            raise ApprovalError(f"invalid tool name {self.name!r}")
        if self.version is not None:
            if not self.version or len(self.version) > _MAX_TOOL_VERSION_CHARS:
                raise ApprovalError(f"invalid tool version for {self.name!r}")
            if any(ord(character) < 32 or ord(character) == 127 for character in self.version):
                raise ApprovalError(f"tool version for {self.name!r} contains control characters")
        if self.sha256 is not None:
            _require_hex64(self.sha256, f"tool sha256 for {self.name!r}")
        if self.version is None and self.sha256 is None:
            raise ApprovalError(f"tool {self.name!r} must bind a version or a sha256")

    def to_dict(self) -> dict[str, str | None]:
        return {"name": self.name, "version": self.version, "sha256": self.sha256}

    @classmethod
    def from_report(cls, report: ToolReport) -> ToolBinding:
        return cls(name=report.name, version=report.version, sha256=report.sha256)


@dataclass(frozen=True, slots=True)
class DeviceBinding:
    """A session nonce plus a fingerprint of fresh device identity facts.

    ``PROBED`` means the fingerprint came from a fresh read-only probe. ``CALLER``
    means a caller supplied it and it is not device evidence.
    """

    nonce: str
    fingerprint_sha256: str
    source: DeviceBindingSource

    def __post_init__(self) -> None:
        if _NONCE_RE.fullmatch(self.nonce) is None:
            raise ApprovalError("device nonce must be 32-128 lowercase hex characters")
        _require_hex64(self.fingerprint_sha256, "device fingerprint_sha256")
        if not isinstance(self.source, DeviceBindingSource):
            raise ApprovalError("device binding source must be probed or caller")

    def to_dict(self) -> dict[str, str]:
        return {
            "nonce": self.nonce,
            "fingerprint_sha256": self.fingerprint_sha256,
            "source": self.source.value,
        }


@dataclass(frozen=True, slots=True)
class ApprovalInputs:
    """Every value an approval binds, in canonical form."""

    plan_sha256: str
    evidence_snapshot_sha256: str
    archive_sha256: str
    package_hashes: tuple[tuple[str, str], ...]
    device: DeviceBinding
    tools: tuple[ToolBinding, ...] = ()

    def __post_init__(self) -> None:
        _require_hex64(self.plan_sha256, "plan_sha256")
        _require_hex64(self.evidence_snapshot_sha256, "evidence_snapshot_sha256")
        _require_hex64(self.archive_sha256, "archive_sha256")
        if not self.package_hashes:
            raise ApprovalError("approval must bind at least one package entry")
        names = [name for name, _ in self.package_hashes]
        if names != sorted(names):
            raise ApprovalError("package hashes must be sorted by entry name")
        if len(names) != len(set(names)):
            raise ApprovalError("duplicate package entry name in approval")
        for name, digest in self.package_hashes:
            _validate_entry_name(name)
            _require_hex64(digest, f"package hash for {name!r}")
        tool_names = [tool.name for tool in self.tools]
        if tool_names != sorted(tool_names):
            raise ApprovalError("tools must be sorted by name")
        if len(tool_names) != len(set(tool_names)):
            raise ApprovalError("duplicate tool name in approval")

    @property
    def binding_sha256(self) -> str:
        encoded = json.dumps(
            self.binding_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def binding_payload(self) -> dict[str, object]:
        return {
            "kind": APPROVAL_KIND,
            "schema_version": APPROVAL_SCHEMA_VERSION,
            "plan_sha256": self.plan_sha256,
            "evidence_snapshot_sha256": self.evidence_snapshot_sha256,
            "archive_sha256": self.archive_sha256,
            "package_hashes": dict(self.package_hashes),
            "device": self.device.to_dict(),
            "tools": [tool.to_dict() for tool in self.tools],
        }

    def to_dict(self) -> dict[str, object]:
        return self.binding_payload() | {"binding_sha256": self.binding_sha256}

    @classmethod
    def from_manifest(
        cls,
        manifest: PackageManifest,
        plan: Plan,
        safety: SafetyReport,
        device: DeviceBinding,
        *,
        tools: Iterable[ToolBinding] = (),
    ) -> ApprovalInputs:
        if not verify_plan_hash(plan):
            raise ApprovalError("plan hash does not match the plan payload")
        if manifest.archive_sha256 is None:
            raise ApprovalError("package archive sha256 is required for approval")
        if plan.package_sha256 != manifest.archive_sha256.lower():
            raise ApprovalError("plan package hash does not match the inspected package")
        package_hashes: list[tuple[str, str]] = []
        for entry in manifest.entries:
            if entry.sha256 is None:
                raise ApprovalError(
                    f"package entry {entry.name!r} has no sha256; inspect with hash_files=True"
                )
            package_hashes.append((entry.name, entry.sha256.lower()))
        package_hashes.sort()
        ordered_tools = tuple(sorted(tools, key=lambda tool: tool.name))
        return cls(
            plan_sha256=plan.plan_sha256,
            evidence_snapshot_sha256=safety.evidence_snapshot_sha256,
            archive_sha256=manifest.archive_sha256.lower(),
            package_hashes=tuple(package_hashes),
            device=device,
            tools=ordered_tools,
        )

    @classmethod
    def from_assessment(
        cls,
        assessment: PlanAssessment,
        manifest: PackageManifest,
        device: DeviceBinding,
        *,
        tools: Iterable[ToolBinding] = (),
    ) -> ApprovalInputs:
        return cls.from_manifest(
            manifest,
            assessment.plan,
            assessment.safety,
            device,
            tools=tools,
        )


def _require_hex64(value: str, what: str) -> None:
    if _HEX64_RE.fullmatch(value) is None:
        raise ApprovalError(f"{what} must be 64 lowercase hex characters")


def _validate_entry_name(name: str) -> None:
    if not name:
        raise ApprovalError("package entry name must not be empty")
    if len(name) > _MAX_ENTRY_NAME_CHARS:
        raise ApprovalError(
            f"package entry name is above the {_MAX_ENTRY_NAME_CHARS}-character limit"
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise ApprovalError(f"package entry name {name!r} contains control characters")
