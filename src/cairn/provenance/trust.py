"""Lock-state-contextual key checks for AVB images.

AOSP AVB treats verification errors as fatal in the LOCKED state and non-fatal in
the UNLOCKED state. This module applies that distinction to a valid VBMeta
signature and a caller-provided trusted key. Neither input is device evidence:
obtaining the lock state and the device's actual root of trust is a separate,
unimplemented capability (KU-029).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from cairn.core.tristate import Tri
from cairn.provenance.avb import AvbError, AvbSignature

MAX_TRUSTED_KEY_BYTES: Final = 8192


class LockState(StrEnum):
    """A lock-state value supplied to the contextual key check."""

    LOCKED = "locked"
    UNLOCKED = "unlocked"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class LockKeyCheck:
    """A contextual key result; it is not device-bound trust evidence."""

    state: Tri
    lock_state: LockState
    key_matches: bool | None
    signature_valid: bool | None
    reason: str
    image_key_sha256: str | None = None
    trusted_key_sha256: str | None = None
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("lock-key reason must not be empty")
        if self.image_key_sha256 is not None and len(self.image_key_sha256) != 64:
            raise ValueError("image key sha256 must be 64 hex characters")
        if self.trusted_key_sha256 is not None and len(self.trusted_key_sha256) != 64:
            raise ValueError("trusted key sha256 must be 64 hex characters")

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.name,
            "lock_state": self.lock_state.value,
            "key_matches": self.key_matches,
            "signature_valid": self.signature_valid,
            "reason": self.reason,
            "image_key_sha256": self.image_key_sha256,
            "trusted_key_sha256": self.trusted_key_sha256,
            "warnings": list(self.warnings),
        }


def evaluate_lock_key(
    signature: AvbSignature,
    *,
    lock_state: LockState,
    trusted_key: bytes | None,
) -> LockKeyCheck:
    """Evaluate an image key against a supplied lock-state context.

    A ``TRUE`` result means the signature is valid and the image key matches the
    caller-supplied trusted key under the supplied lock-state context. It never
    means either value was read from the device, and callers must not use it as
    evidence for SR-013. An invalid signature is ``FALSE``; an unsigned image,
    a missing trusted key, or an unknown lock state is ``UNKNOWN``. On an
    unlocked device a mismatch is ``UNKNOWN`` with a warning, because the
    bootloader would not enforce the key.
    """
    if trusted_key is not None:
        _validate_trusted_key(trusted_key)

    image_key_sha256 = signature.key_sha256 if signature.signed else None
    trusted_key_sha256 = None if trusted_key is None else hashlib.sha256(trusted_key).hexdigest()
    key_matches = (
        None if trusted_key is None else hmac.compare_digest(signature.key_blob, trusted_key)
    )

    def result(
        state: Tri,
        reason: str,
        *,
        warnings: tuple[str, ...] = (),
    ) -> LockKeyCheck:
        return LockKeyCheck(
            state=state,
            lock_state=lock_state,
            key_matches=key_matches,
            signature_valid=signature.valid,
            reason=reason,
            image_key_sha256=image_key_sha256,
            trusted_key_sha256=trusted_key_sha256,
            warnings=warnings,
        )

    if signature.valid is False:
        return result(
            Tri.FALSE,
            "VBMeta signature is invalid; key trust cannot be established",
        )
    if signature.valid is None:
        return result(Tri.UNKNOWN, "unsigned VBMeta has no key to compare")
    if trusted_key is None:
        return result(
            Tri.UNKNOWN,
            "no trusted key was supplied; lock state alone cannot establish key trust",
        )
    if lock_state is LockState.UNKNOWN:
        return result(
            Tri.UNKNOWN,
            "device lock state is unknown; key trust cannot be interpreted",
        )

    if key_matches:
        warnings = (
            ("device is unlocked; key matching is not enforced by lock state",)
            if lock_state is LockState.UNLOCKED
            else ()
        )
        return result(
            Tri.TRUE,
            (
                "unlocked device and image key matches the trusted key"
                if lock_state is LockState.UNLOCKED
                else "locked device and image key matches the trusted key"
            ),
            warnings=warnings,
        )

    if lock_state is LockState.LOCKED:
        return result(
            Tri.FALSE,
            "locked device and image key does not match the trusted key",
        )
    return result(
        Tri.UNKNOWN,
        "unlocked device and image key does not match the trusted key",
        warnings=(
            "an unlocked device does not enforce the trusted key; this is not a trust result",
        ),
    )


def _validate_trusted_key(trusted_key: bytes) -> None:
    if not trusted_key:
        raise AvbError("trusted AVB public key must not be empty")
    if len(trusted_key) > MAX_TRUSTED_KEY_BYTES:
        raise AvbError(f"trusted AVB public key is above the {MAX_TRUSTED_KEY_BYTES}-byte limit")
