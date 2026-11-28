"""Virtual A/B state machines: merge-state, dynamic-partition, snapshot flows."""

from cairn.vab.dynpart import (
    DynPartError,
    DynPartRead,
    classify_dynpart_mode,
    read_dynpart,
)
from cairn.vab.flows import (
    FlowRefused,
    FlowReport,
    SnapshotFlowInputs,
    expected_acknowledgment,
    run_snapshot_flow,
)
from cairn.vab.merge_state import (
    MergeStateError,
    MergeStateRead,
    classify_snapshot_status,
    read_merge_state,
)
from cairn.vab.super_meta import (
    SuperImage,
    SuperMetadataError,
    parse_super_image,
)

__all__ = [
    "DynPartError",
    "DynPartRead",
    "FlowRefused",
    "FlowReport",
    "MergeStateError",
    "MergeStateRead",
    "SnapshotFlowInputs",
    "SuperImage",
    "SuperMetadataError",
    "classify_dynpart_mode",
    "classify_snapshot_status",
    "expected_acknowledgment",
    "parse_super_image",
    "read_dynpart",
    "read_merge_state",
    "run_snapshot_flow",
]
