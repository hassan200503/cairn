"""Rollback checks: can this package lower a counter on this device?"""

from cairn.rollback.oracle import (
    MAX_ROLLBACK_INDEX,
    CounterKind,
    OtaDowngradeSignal,
    RollbackCounter,
    RollbackError,
    RollbackFinding,
    RollbackInputs,
    RollbackReport,
    avb_rollback_inputs,
    evaluate_avb_rollback,
    evaluate_rollback,
)

__all__ = [
    "MAX_ROLLBACK_INDEX",
    "CounterKind",
    "OtaDowngradeSignal",
    "RollbackCounter",
    "RollbackError",
    "RollbackFinding",
    "RollbackInputs",
    "RollbackReport",
    "avb_rollback_inputs",
    "evaluate_avb_rollback",
    "evaluate_rollback",
]
