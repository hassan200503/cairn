"""Recovery asset verification.

SR-008: before a bootchain write on a device without a safe A/B path, known-good
recovery assets must be hash-verified on the host and a last-resort path must be
stated. Assets arrive from the catalog or the caller as ``partition -> (path,
expected sha256)`` pairs; verification is tri-state and fail-closed: a hash
mismatch is FALSE, an unreadable or missing asset is UNKNOWN, and only an exact
match is TRUE. Expected hashes are mandatory — an asset without a recorded hash is
UNKNOWN, never TRUE.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

from cairn.core.errors import RecoveryError
from cairn.core.tristate import Tri
from cairn.safety.engine import CheckState

MAX_ASSET_BYTES: Final = 2 * 1024 * 1024 * 1024
_CHUNK: Final = 1024 * 1024


class AssetError(RecoveryError):
    code = "RECOVERY_ASSET_ERROR"


@dataclass(frozen=True, slots=True)
class AssetVerdict:
    partition: str
    path: str
    state: Tri
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "partition": self.partition,
            "path": self.path,
            "state": self.state.name,
            "detail": self.detail,
        }


def verify_assets(
    assets: Mapping[str, tuple[Path, str]],
) -> tuple[AssetVerdict, ...]:
    """Verify recovery assets against expected SHA-256 hashes."""
    verdicts: list[AssetVerdict] = []
    for partition in sorted(assets):
        path, expected = assets[partition]
        expected = expected.lower()
        if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            verdicts.append(
                AssetVerdict(
                    partition=partition,
                    path=str(path),
                    state=Tri.UNKNOWN,
                    detail=f"expected hash for {partition!r} is not a sha256 hex digest",
                )
            )
            continue
        try:
            size = path.stat().st_size
            if size > MAX_ASSET_BYTES:
                raise AssetError(f"asset {path} is {size} bytes, above the limit")
            hasher = hashlib.sha256()
            with path.open("rb") as handle:
                while chunk := handle.read(_CHUNK):
                    hasher.update(chunk)
            actual = hasher.hexdigest()
        except AssetError as exc:
            verdicts.append(
                AssetVerdict(
                    partition=partition,
                    path=str(path),
                    state=Tri.UNKNOWN,
                    detail=str(exc),
                )
            )
            continue
        except OSError as exc:
            verdicts.append(
                AssetVerdict(
                    partition=partition,
                    path=str(path),
                    state=Tri.UNKNOWN,
                    detail=f"cannot read recovery asset {path}: {exc}",
                )
            )
            continue
        if actual != expected:
            verdicts.append(
                AssetVerdict(
                    partition=partition,
                    path=str(path),
                    state=Tri.FALSE,
                    detail=f"recovery asset hash mismatch: {actual} != {expected}",
                )
            )
            continue
        verdicts.append(
            AssetVerdict(
                partition=partition,
                path=str(path),
                state=Tri.TRUE,
                detail="recovery asset matches its recorded hash",
            )
        )
    return tuple(verdicts)


def readiness_check(
    verdicts: tuple[AssetVerdict, ...],
    *,
    last_resort_stated: bool,
    observed_at: datetime,
) -> CheckState:
    """Aggregate asset verdicts into the SR-008 readiness check.

    FALSE (any asset hash mismatch, or no last-resort path stated) and UNKNOWN
    (any unreadable asset, or no assets at all) both block and are not
    overridable for a bootchain write.
    """
    if observed_at.tzinfo is None:
        raise AssetError("readiness check time must be timezone-aware")
    if not last_resort_stated:
        return CheckState(
            state=Tri.UNKNOWN,
            detail="no last-resort recovery path was stated; readiness is unknown",
        )
    if not verdicts:
        return CheckState(
            state=Tri.UNKNOWN,
            detail="no recovery assets were supplied; readiness is unknown",
        )
    states = [verdict.state for verdict in verdicts]
    if Tri.FALSE in states:
        state = Tri.FALSE
    elif Tri.UNKNOWN in states:
        state = Tri.UNKNOWN
    else:
        state = Tri.TRUE
    detail = "; ".join(f"{v.partition}: {v.detail}" for v in verdicts)
    return CheckState(state=state, detail=detail)
