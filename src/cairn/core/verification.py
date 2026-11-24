"""Verification levels. The word "verified" is never used without one."""

from __future__ import annotations

from enum import IntEnum


class VerificationLevel(IntEnum):
    """How far a write was actually confirmed.

    V0: the transport acknowledged the write.
    V1: the host-side source hash matched the manifest and the device acknowledged.
    V2: the device read-back hash matched the source.
    V3: post-boot identity was confirmed.
    """

    V0 = 0
    V1 = 1
    V2 = 2
    V3 = 3

    @property
    def label(self) -> str:
        return {
            VerificationLevel.V0: "transport acknowledged",
            VerificationLevel.V1: "host hash plus device acknowledgement",
            VerificationLevel.V2: "device read-back hash",
            VerificationLevel.V3: "post-boot identity confirmed",
        }[self]

    def at_least(self, other: VerificationLevel) -> bool:
        return self >= other
