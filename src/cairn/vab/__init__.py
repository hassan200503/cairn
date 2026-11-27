"""Virtual A/B state machines: merge-state and dynamic-partition gates."""

from cairn.vab.dynpart import (
    DynPartError,
    DynPartRead,
    classify_dynpart_mode,
    read_dynpart,
)
from cairn.vab.merge_state import (
    MergeStateError,
    MergeStateRead,
    classify_snapshot_status,
    read_merge_state,
)

__all__ = [
    "DynPartError",
    "DynPartRead",
    "MergeStateError",
    "MergeStateRead",
    "classify_dynpart_mode",
    "classify_snapshot_status",
    "read_dynpart",
    "read_merge_state",
]
