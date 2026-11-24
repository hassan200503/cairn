from __future__ import annotations

import sys
from pathlib import Path

import pytest

from cairn.core.errors import ConfigurationError, ToolError
from cairn.tools.manifest import (
    PINNED_TOOLS,
    TOOL_MANIFEST,
    ToolSpec,
    parse_tool_version,
    sha256_file,
    version_at_least,
    version_key,
)
from cairn.tools.runner import ToolRunner


def test_parse_fastboot_version() -> None:
    text = "fastboot version 37.0.3-16887417\nInstalled as C:\\platform-tools\\fastboot.exe"
    assert parse_tool_version(text) == "37.0.3"


def test_parse_tool_version_without_digits() -> None:
    assert parse_tool_version("no version here") is None


def test_version_key_and_comparison() -> None:
    assert version_key("37.0.3-16887417") == (37, 0, 3)
    assert version_at_least("37.0.3", "37.0.3")
    assert not version_at_least("37.0.2", "37.0.3")
    assert version_at_least("38", "37.0.3")
    assert version_at_least("37.0", "37.0.0")
    assert not version_at_least("not-a-version", "37.0.3")


def test_sha256_file_matches_known_digest(tmp_path: Path) -> None:
    target = tmp_path / "abc.bin"
    target.write_bytes(b"abc")
    assert sha256_file(target) == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_verify_accepts_matching_fake_tool() -> None:
    spec = ToolSpec(
        name="fake",
        license="MIT",
        min_version="37.0.3",
        version_args=("-c", "print('fake version 99.0.0')"),
    )
    report = TOOL_MANIFEST.verify("fake", Path(sys.executable), ToolRunner(), spec=spec)
    assert report.version == "99.0.0"
    assert report.meets_minimum is True
    assert report.sha256_pinned is False
    assert report.ok


def test_verify_rejects_old_fake_tool() -> None:
    spec = ToolSpec(
        name="fake",
        license="MIT",
        min_version="100.0",
        version_args=("-c", "print('fake version 1.0.0')"),
    )
    report = TOOL_MANIFEST.verify("fake", Path(sys.executable), ToolRunner(), spec=spec)
    assert report.meets_minimum is False
    assert not report.ok


def test_verify_rejects_sha256_mismatch() -> None:
    spec = ToolSpec(
        name="fake",
        license="MIT",
        sha256="00" * 32,
        version_args=("-c", "print('fake version 1.0.0')"),
    )
    report = TOOL_MANIFEST.verify("fake", Path(sys.executable), ToolRunner(), spec=spec)
    assert report.sha256_match is False
    assert not report.ok


def test_verify_accepts_matching_sha256() -> None:
    digest = sha256_file(Path(sys.executable))
    spec = ToolSpec(
        name="fake",
        license="MIT",
        sha256=digest,
        version_args=("-c", "print('fake version 1.0.0')"),
    )
    report = TOOL_MANIFEST.verify("fake", Path(sys.executable), ToolRunner(), spec=spec)
    assert report.sha256_match is True
    assert report.ok


def test_unknown_tool_is_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError, match="unknown tool"):
        TOOL_MANIFEST.require("not-a-tool")


def test_missing_tool_path_raises(tmp_path: Path) -> None:
    with pytest.raises(ToolError, match="not found"):
        TOOL_MANIFEST.verify("fastboot", tmp_path / "missing", ToolRunner())


def test_gpl_tools_are_flagged() -> None:
    assert PINNED_TOOLS["edl"].gpl
    assert PINNED_TOOLS["mtkclient"].gpl
    assert not PINNED_TOOLS["fastboot"].gpl
    assert PINNED_TOOLS["fastboot"].min_version == "37.0.3"
