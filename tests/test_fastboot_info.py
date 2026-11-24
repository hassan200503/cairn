from __future__ import annotations

from pathlib import Path

import pytest

from cairn.package.fastboot_info import (
    EraseCommand,
    FastbootInfoError,
    FlashCommand,
    RebootCommand,
    UpdateSuperCommand,
    parse_fastboot_info,
)

FIXTURE = Path(__file__).parent / "fixtures" / "fastboot" / "fastboot-info.txt"


def test_parses_golden_fixture() -> None:
    info = parse_fastboot_info(FIXTURE.read_text(encoding="utf-8"))
    assert info.version == 1
    assert len(info.commands) == 16

    first = info.commands[0]
    assert isinstance(first, FlashCommand)
    assert first.partition == "bootloader"
    assert first.image_name == "bootloader.img"
    assert not first.if_wipe

    vbmeta = next(
        command
        for command in info.commands
        if isinstance(command, FlashCommand) and command.partition == "vbmeta"
    )
    assert vbmeta.apply_vbmeta
    assert vbmeta.slot_other is False

    dtbo = next(
        command
        for command in info.commands
        if isinstance(command, FlashCommand) and command.partition == "dtbo"
    )
    assert dtbo.slot_other

    reboots = [command for command in info.commands if isinstance(command, RebootCommand)]
    assert [command.target for command in reboots] == ["bootloader", "fastboot", "fastboot"]

    updates = [command for command in info.commands if isinstance(command, UpdateSuperCommand)]
    assert len(updates) == 1

    userdata = next(
        command
        for command in info.commands
        if isinstance(command, FlashCommand) and command.partition == "userdata"
    )
    assert userdata.if_wipe
    assert userdata.image_name == "userdata.img"

    metadata = next(
        command
        for command in info.commands
        if isinstance(command, EraseCommand) and command.partition == "metadata"
    )
    assert metadata.if_wipe


def test_default_image_is_partition_dot_img() -> None:
    info = parse_fastboot_info("flash boot\n")
    command = info.commands[0]
    assert isinstance(command, FlashCommand)
    assert command.image is None
    assert command.image_name == "boot.img"


def test_explicit_image_and_apply_vbmeta() -> None:
    info = parse_fastboot_info("flash boot boot-alt.img --apply-vbmeta\n")
    command = info.commands[0]
    assert isinstance(command, FlashCommand)
    assert command.image == "boot-alt.img"
    assert command.apply_vbmeta


def test_if_wipe_applies_to_next_command_only() -> None:
    info = parse_fastboot_info("if-wipe flash userdata\nflash boot\n")
    first, second = info.commands
    assert isinstance(first, FlashCommand)
    assert isinstance(second, FlashCommand)
    assert first.if_wipe
    assert not second.if_wipe


def test_comments_and_blank_lines_are_ignored() -> None:
    info = parse_fastboot_info("# comment\n\n   \nflash boot\n")
    assert len(info.commands) == 1
    assert info.version is None


def test_crlf_is_supported() -> None:
    info = parse_fastboot_info("version 1\r\nflash boot\r\n")
    assert info.version == 1
    assert len(info.commands) == 1


def test_empty_file_is_valid() -> None:
    info = parse_fastboot_info("")
    assert info.version is None
    assert info.commands == ()


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("version 2\n", "unsupported fastboot-info version"),
        ("version one\n", "must be a decimal integer"),
        ("version 1 extra\n", "exactly one number"),
        ("reboot\nreboot fastboot\nupdate-super\nupdate-super\n", "duplicate update-super"),
        ("update-super now\n", "takes no arguments"),
        ("reboot weird\n", "unknown reboot target"),
        ("erase\n", "exactly one partition"),
        ("flash\n", "requires a partition"),
        ("flash boot boot.img extra.img\n", "unexpected extra flash argument"),
        ("flash --apply-vbmeta boot.img\n", "requires a partition"),
        ("flash boot --apply-vbmeta --apply-vbmeta\n", "duplicate --apply-vbmeta"),
        ("flash boot --slot-other --slot-other\n", "duplicate --slot-other"),
        ("flash boot --unknown-flag\n", "unknown flash flag"),
        ("if-wipe\n", "must be followed by a command"),
        ("if-wipe version 1\n", "unknown command"),
        ("fastboot flash boot\n", "unknown command"),
        ("flash boot boot.img # inline\n", "unexpected extra flash argument"),
        ("update-super\nversion 2\n", "unsupported"),
    ],
)
def test_malformed_lines_are_rejected(text: str, message: str) -> None:
    with pytest.raises(FastbootInfoError, match=message):
        parse_fastboot_info(text)


def test_errors_include_the_line_number() -> None:
    with pytest.raises(FastbootInfoError, match="line 3"):
        parse_fastboot_info("flash boot\nreboot\nnonsense\n")
