"""Parser for AOSP ``fastboot-info.txt`` (version 1).

Grammar verified against AOSP ``system/core/fastboot/fastboot_info.cpp`` (pinned
tree ``c66af46cc55138dd6ee70b51cbeb4501b83d23ec``):

    file      = { line }
    line      = comment | "version" N | command
    comment   = "#" ...
    command   = ["if-wipe"] (flash | reboot | update-super | erase)
    flash     = "flash" PARTITION [IMAGE | FLAG]...
    reboot    = "reboot" [bootloader|fastboot|recovery]
    erase     = "erase" PARTITION
    update-super = "update-super"

Deliberate fail-closed deviations from AOSP:

- AOSP treats an unknown ``--flag`` as the image path; we reject it.
- AOSP accepts any reboot target and fails later; we accept only the documented
  targets.
- AOSP allows duplicate ``update-super`` lines; we reject them.

Inline ``#`` comments are not supported, matching AOSP tokenization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from cairn.core.errors import ConfigurationError

MAX_SUPPORTED_VERSION: Final = 1
REBOOT_TARGETS: Final[frozenset[str]] = frozenset({"bootloader", "fastboot", "recovery"})
FLASH_FLAGS: Final[frozenset[str]] = frozenset({"--apply-vbmeta", "--slot-other"})


class FastbootInfoError(ConfigurationError):
    code = "FASTBOOT_INFO_ERROR"


@dataclass(frozen=True, slots=True)
class FlashCommand:
    partition: str
    image: str | None
    apply_vbmeta: bool
    slot_other: bool
    if_wipe: bool
    line: int

    @property
    def image_name(self) -> str:
        """The image AOSP would flash: explicit path or ``<partition>.img``."""
        return self.image if self.image is not None else f"{self.partition}.img"


@dataclass(frozen=True, slots=True)
class RebootCommand:
    target: str | None
    if_wipe: bool
    line: int

    @property
    def target_name(self) -> str:
        return self.target if self.target is not None else "system"


@dataclass(frozen=True, slots=True)
class UpdateSuperCommand:
    if_wipe: bool
    line: int


@dataclass(frozen=True, slots=True)
class EraseCommand:
    partition: str
    if_wipe: bool
    line: int


type FastbootCommand = FlashCommand | RebootCommand | UpdateSuperCommand | EraseCommand


@dataclass(frozen=True, slots=True)
class FastbootInfo:
    version: int | None
    commands: tuple[FastbootCommand, ...]


def parse_fastboot_info(text: str) -> FastbootInfo:
    """Parse ``fastboot-info.txt`` text. Unknown or malformed lines raise."""
    version: int | None = None
    commands: list[FastbootCommand] = []
    seen_update_super = False

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        tokens = [token for token in raw_line.split(" ") if token]
        if not tokens or tokens[0].startswith("#"):
            continue

        if tokens[0] == "version":
            if len(tokens) != 2:
                raise _error(line_number, "version takes exactly one number")
            parsed = _parse_int(tokens[1], line_number, "version")
            if parsed > MAX_SUPPORTED_VERSION:
                raise _error(
                    line_number,
                    f"unsupported fastboot-info version {parsed}; "
                    f"maximum is {MAX_SUPPORTED_VERSION}",
                )
            if parsed < 1:
                raise _error(line_number, f"invalid fastboot-info version {parsed}")
            if version is None:
                version = parsed
            continue

        if_wipe = False
        if tokens[0] == "if-wipe":
            if_wipe = True
            tokens = tokens[1:]
            if not tokens:
                raise _error(line_number, "if-wipe must be followed by a command")

        command = tokens[0]
        if command == "flash":
            commands.append(_parse_flash(tokens[1:], if_wipe, line_number))
        elif command == "erase":
            if len(tokens) != 2:
                raise _error(line_number, "erase takes exactly one partition")
            commands.append(EraseCommand(partition=tokens[1], if_wipe=if_wipe, line=line_number))
        elif command == "reboot":
            if len(tokens) > 2:
                raise _error(line_number, "reboot takes at most one target")
            target = tokens[1] if len(tokens) == 2 else None
            if target is not None and target not in REBOOT_TARGETS:
                raise _error(
                    line_number,
                    f"unknown reboot target {target!r}; expected one of {sorted(REBOOT_TARGETS)}",
                )
            commands.append(RebootCommand(target=target, if_wipe=if_wipe, line=line_number))
        elif command == "update-super":
            if len(tokens) != 1:
                raise _error(line_number, "update-super takes no arguments")
            if seen_update_super:
                raise _error(line_number, "duplicate update-super is not supported")
            seen_update_super = True
            commands.append(UpdateSuperCommand(if_wipe=if_wipe, line=line_number))
        else:
            raise _error(line_number, f"unknown command {command!r}")

    return FastbootInfo(version=version, commands=tuple(commands))


def _parse_flash(tokens: list[str], if_wipe: bool, line_number: int) -> FlashCommand:
    if not tokens:
        raise _error(line_number, "flash requires a partition")
    partition = tokens[0]
    if partition.startswith("--"):
        raise _error(line_number, f"flash requires a partition, got flag {partition!r}")

    image: str | None = None
    apply_vbmeta = False
    slot_other = False
    for argument in tokens[1:]:
        if argument == "--apply-vbmeta":
            if apply_vbmeta:
                raise _error(line_number, "duplicate --apply-vbmeta")
            apply_vbmeta = True
        elif argument == "--slot-other":
            if slot_other:
                raise _error(line_number, "duplicate --slot-other")
            slot_other = True
        elif argument.startswith("--"):
            raise _error(line_number, f"unknown flash flag {argument!r}")
        elif image is None:
            image = argument
        else:
            raise _error(line_number, f"unexpected extra flash argument {argument!r}")

    return FlashCommand(
        partition=partition,
        image=image,
        apply_vbmeta=apply_vbmeta,
        slot_other=slot_other,
        if_wipe=if_wipe,
        line=line_number,
    )


def _parse_int(text: str, line_number: int, field: str) -> int:
    try:
        return int(text, 10)
    except ValueError as exc:
        raise _error(line_number, f"{field} must be a decimal integer, got {text!r}") from exc


def _error(line_number: int, message: str) -> FastbootInfoError:
    return FastbootInfoError(f"fastboot-info line {line_number}: {message}")
