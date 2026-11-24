"""Tool manifests: pinned identities, licenses, and minimum versions.

Cairn does not vendor device tools. Each tool is identified by name, license, and
(when distributed or audited) an exact SHA-256. GPL tools are executed as separate
processes and are never imported or linked.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cairn.core.errors import ConfigurationError, ToolError
from cairn.tools.runner import ToolRunner

FASTBOOT_VERSION_ARGS: Final[tuple[str, ...]] = ("--version",)

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+)")
_VERSION_KEY_RE = re.compile(r"(\d+(?:\.\d+)*)")
_VERSION_ARG_RE = re.compile(r"version\s+(\d+(?:\.\d+)+)")


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """The identity Cairn expects for one external tool."""

    name: str
    license: str
    min_version: str | None = None
    sha256: str | None = None
    version_args: tuple[str, ...] = ("--version",)
    gpl: bool = False
    note: str = ""


@dataclass(frozen=True, slots=True)
class ToolReport:
    """Result of checking one tool against its manifest entry."""

    name: str
    path: Path
    license: str
    gpl: bool
    version: str | None
    sha256: str
    sha256_pinned: bool
    sha256_match: bool | None
    min_version: str | None
    meets_minimum: bool | None
    detail: str

    @property
    def ok(self) -> bool:
        if self.sha256_match is False:
            return False
        return self.min_version is None or self.meets_minimum is True


PINNED_TOOLS: Final[Mapping[str, ToolSpec]] = {
    "fastboot": ToolSpec(
        name="fastboot",
        license="Apache-2.0",
        min_version="37.0.3",
        note="official Android platform-tools fastboot",
    ),
    "adb": ToolSpec(
        name="adb",
        license="Apache-2.0",
        min_version="37.0.3",
        note="official Android platform-tools adb",
    ),
    "avbtool": ToolSpec(
        name="avbtool",
        license="Apache-2.0",
        version_args=(),
        note="AOSP external/avb; pinned by commit in docs, not by release",
    ),
    "heimdall": ToolSpec(
        name="heimdall",
        license="MIT",
        note="Samsung Odin-protocol host; separate process",
    ),
    "thor": ToolSpec(
        name="thor",
        license="MPL-2.0",
        note="no code copying; behavior reference only",
    ),
    "edl": ToolSpec(
        name="edl",
        license="GPL-3.0",
        gpl=True,
        note="bkerler/edl; opted-in separate process only, never imported",
    ),
    "mtkclient": ToolSpec(
        name="mtkclient",
        license="GPL-3.0",
        gpl=True,
        note="bkerler/mtkclient; opted-in separate process only, never imported",
    ),
}

BUNDLED_FASTBOOT_WINDOWS: Final[ToolSpec] = ToolSpec(
    name="fastboot",
    license="Apache-2.0",
    min_version="37.0.3",
    sha256="f8335c9f07a945aa5226418906f0be42c6349def16643343549174e55ac7c789",
    note="platform-tools 37.0.3 fastboot.exe artifact recorded 2026-11-25",
)


class ToolManifest:
    """Look up and verify tools without trusting PATH or the filesystem alone."""

    def __init__(self, tools: Mapping[str, ToolSpec] = PINNED_TOOLS) -> None:
        self._tools = dict(tools)

    def require(self, name: str) -> ToolSpec:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ConfigurationError(f"unknown tool {name!r} in manifest") from exc

    def verify(
        self,
        name: str,
        path: Path,
        runner: ToolRunner,
        *,
        spec: ToolSpec | None = None,
    ) -> ToolReport:
        expected = spec if spec is not None else self.require(name)
        if not path.is_file():
            raise ToolError(f"{name} not found at {path}")

        digest = sha256_file(path)
        version: str | None = None
        if expected.version_args:
            try:
                result = runner.run((str(path), *expected.version_args), timeout_s=10.0)
            except ToolError:
                result = None
            if result is not None and result.exit_code == 0:
                version = parse_tool_version(result.combined_output)

        sha256_match: bool | None = None
        if expected.sha256 is not None:
            sha256_match = digest == expected.sha256.lower()

        meets_minimum: bool | None = None
        if expected.min_version is not None and version is not None:
            meets_minimum = version_at_least(version, expected.min_version)

        detail_parts: list[str] = []
        if expected.sha256 is not None and sha256_match is False:
            detail_parts.append("SHA-256 does not match the pinned artifact")
        if expected.min_version is not None:
            if version is None:
                detail_parts.append("could not read a version")
            elif meets_minimum is False:
                detail_parts.append(f"version {version} is below {expected.min_version}")
        if not detail_parts:
            detail_parts.append("verified manifest entry")

        return ToolReport(
            name=name,
            path=path,
            license=expected.license,
            gpl=expected.gpl,
            version=version,
            sha256=digest,
            sha256_pinned=expected.sha256 is not None,
            sha256_match=sha256_match,
            min_version=expected.min_version,
            meets_minimum=meets_minimum,
            detail="; ".join(detail_parts),
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_tool_version(output: str) -> str | None:
    """Extract a version from ``fastboot --version`` style output."""
    match = _VERSION_ARG_RE.search(output)
    if match is not None:
        return match.group(1)
    match = _VERSION_RE.search(output)
    if match is not None:
        return match.group(1)
    return None


def version_key(version: str) -> tuple[int, ...] | None:
    match = _VERSION_KEY_RE.search(version)
    if match is None:
        return None
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None


def version_at_least(found: str, minimum: str) -> bool:
    """Compare dotted numeric versions, padding the shorter one with zeros."""
    found_key = version_key(found)
    minimum_key = version_key(minimum)
    if found_key is None or minimum_key is None:
        return False
    width = max(len(found_key), len(minimum_key))
    padded_found = found_key + (0,) * (width - len(found_key))
    padded_minimum = minimum_key + (0,) * (width - len(minimum_key))
    return padded_found >= padded_minimum


TOOL_MANIFEST = ToolManifest()

__all__: Sequence[str] = (
    "BUNDLED_FASTBOOT_WINDOWS",
    "PINNED_TOOLS",
    "TOOL_MANIFEST",
    "ToolManifest",
    "ToolReport",
    "ToolSpec",
    "parse_tool_version",
    "sha256_file",
    "version_at_least",
    "version_key",
)
