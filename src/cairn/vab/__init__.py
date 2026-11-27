"""Virtual A/B state machines: merge-state reading and evaluation."""

from cairn.vab.merge_state import (
    MergeStateError,
    MergeStateRead,
    classify_snapshot_status,
    read_merge_state,
)

__all__ = [
    "MergeStateError",
    "MergeStateRead",
    "classify_snapshot_status",
    "read_merge_state",
]
