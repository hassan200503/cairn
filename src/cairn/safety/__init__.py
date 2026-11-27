"""Safety rules and the report engine."""

from __future__ import annotations

from collections.abc import Sequence

from cairn.safety.engine import (
    DEFAULT_RULES,
    PRE_APPROVAL_RULES,
    CheckState,
    DeviceIdentity,
    OverrideRecord,
    OverrideRequest,
    PackageIdentity,
    RuleResult,
    RuleSpec,
    SafetyContext,
    SafetyEngine,
    SafetyError,
    SafetyReport,
)

__all__: Sequence[str] = (
    "DEFAULT_RULES",
    "PRE_APPROVAL_RULES",
    "CheckState",
    "DeviceIdentity",
    "OverrideRecord",
    "OverrideRequest",
    "PackageIdentity",
    "RuleResult",
    "RuleSpec",
    "SafetyContext",
    "SafetyEngine",
    "SafetyError",
    "SafetyReport",
)
