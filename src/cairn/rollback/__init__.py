"""Rollback checks: can this package lower a counter on this device?"""

from cairn.rollback.device import (
    DeviceRollbackRead,
    OemAntiRollbackSignal,
    StoredRollbackIndex,
    parse_stored_rollback_indexes,
    read_stored_rollback_indexes,
)
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
    "DeviceRollbackRead",
    "OemAntiRollbackSignal",
    "OtaDowngradeSignal",
    "RollbackCounter",
    "RollbackError",
    "RollbackFinding",
    "RollbackInputs",
    "RollbackReport",
    "StoredRollbackIndex",
    "avb_rollback_inputs",
    "evaluate_avb_rollback",
    "evaluate_rollback",
    "parse_stored_rollback_indexes",
    "read_stored_rollback_indexes",
]
