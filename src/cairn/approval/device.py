"""Build a device binding from fresh, read-only probe facts.

Fastboot has no challenge-response nonce. Cairn therefore uses a host-generated
session nonce and binds it to a fingerprint of the fresh identity facts reported by
one read-only ``getvar all``. A caller-supplied fingerprint is recorded as
``CALLER`` and is not device evidence.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Final

from cairn.adapters.fastboot import ProbeResult
from cairn.approval.binding import (
    ApprovalError,
    DeviceBinding,
    DeviceBindingSource,
)
from cairn.core.tristate import Tri

REQUIRED_DEVICE_FACTS: Final[tuple[str, ...]] = (
    "serialno",
    "product",
    "hw-revision",
    "version-bootloader",
)
OPTIONAL_DEVICE_FACTS: Final[tuple[str, ...]] = (
    "variant",
    "system-fingerprint",
    "vendor-fingerprint",
)
_FINGERPRINT_KIND: Final = "cairn.device-fingerprint"
_FINGERPRINT_SCHEMA_VERSION: Final = 1


def new_nonce() -> str:
    """Return a fresh 256-bit session nonce as lowercase hex."""
    return secrets.token_hex(32)


def build_device_binding(
    result: ProbeResult,
    nonce: str,
    *,
    now: datetime | None = None,
) -> DeviceBinding:
    """Bind a nonce to a fresh, fully usable probe result."""
    observed_at = now if now is not None else datetime.now(UTC)
    if observed_at.tzinfo is None:
        raise ApprovalError("now must be timezone-aware")
    return DeviceBinding(
        nonce=nonce,
        fingerprint_sha256=device_fingerprint(result, now=observed_at),
        source=DeviceBindingSource.PROBED,
    )


def caller_device_binding(nonce: str, fingerprint_sha256: str) -> DeviceBinding:
    """Record a caller-supplied fingerprint without claiming a probe."""
    return DeviceBinding(
        nonce=nonce,
        fingerprint_sha256=fingerprint_sha256,
        source=DeviceBindingSource.CALLER,
    )


def device_fingerprint(result: ProbeResult, *, now: datetime) -> str:
    """Hash the required and present optional identity facts from one probe."""
    if now.tzinfo is None:
        raise ApprovalError("now must be timezone-aware")
    if not result.tool_ok:
        raise ApprovalError(f"device probe failed: {result.detail}")

    serial_match = result.fact("serial-match")
    if serial_match is not None and serial_match.evidence.state is not Tri.TRUE:
        raise ApprovalError("device serial does not match the requested serial")

    facts: dict[str, str] = {}
    for name in REQUIRED_DEVICE_FACTS:
        fact = result.fact(name)
        if fact is None:
            raise ApprovalError(f"device probe did not report {name}")
        if fact.evidence.state is not Tri.TRUE:
            raise ApprovalError(f"device fact {name} is {fact.evidence.state.name}")
        if not fact.evidence.is_usable(now):
            raise ApprovalError(f"device fact {name} is stale or inferred")
        value = fact.evidence.value
        if value is None or not value.strip():
            raise ApprovalError(f"device fact {name} has no value")
        facts[name] = value.strip()

    for name in OPTIONAL_DEVICE_FACTS:
        fact = result.fact(name)
        if fact is None or fact.evidence.state is not Tri.TRUE:
            continue
        if not fact.evidence.is_usable(now):
            continue
        value = fact.evidence.value
        if value is None or not value.strip():
            continue
        facts[name] = value.strip()

    return fingerprint_facts(facts)


def fingerprint_facts(facts: Mapping[str, str]) -> str:
    """Return the canonical SHA-256 of an identity-fact mapping."""
    encoded = json.dumps(
        {
            "kind": _FINGERPRINT_KIND,
            "schema_version": _FINGERPRINT_SCHEMA_VERSION,
            "facts": dict(facts),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
