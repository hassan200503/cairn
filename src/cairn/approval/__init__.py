"""Approval binding: canonical inputs, device binding, and signed tokens."""

from __future__ import annotations

from collections.abc import Sequence

from cairn.approval.binding import (
    APPROVAL_KIND,
    APPROVAL_SCHEMA_VERSION,
    ApprovalError,
    ApprovalInputs,
    DeviceBinding,
    DeviceBindingSource,
    ToolBinding,
)
from cairn.approval.device import (
    OPTIONAL_DEVICE_FACTS,
    REQUIRED_DEVICE_FACTS,
    build_device_binding,
    caller_device_binding,
    device_fingerprint,
    fingerprint_facts,
    new_nonce,
)
from cairn.approval.token import (
    DOCUMENT_KIND,
    KEY_BYTES,
    MAX_TEXT_CHARS,
    MAX_TOKEN_BYTES,
    MIN_REASON_CHARS,
    TOKEN_SCHEMA_VERSION,
    ApprovalToken,
    ApprovalVerdict,
    encode_approval_key,
    generate_approval_key,
    issue_approval,
    key_id,
    load_approval_key,
    parse_approval_token,
    verify_approval,
    write_approval_key,
)

__all__: Sequence[str] = (
    "APPROVAL_KIND",
    "APPROVAL_SCHEMA_VERSION",
    "DOCUMENT_KIND",
    "KEY_BYTES",
    "MAX_TEXT_CHARS",
    "MAX_TOKEN_BYTES",
    "MIN_REASON_CHARS",
    "OPTIONAL_DEVICE_FACTS",
    "REQUIRED_DEVICE_FACTS",
    "TOKEN_SCHEMA_VERSION",
    "ApprovalError",
    "ApprovalInputs",
    "ApprovalToken",
    "ApprovalVerdict",
    "DeviceBinding",
    "DeviceBindingSource",
    "ToolBinding",
    "build_device_binding",
    "caller_device_binding",
    "device_fingerprint",
    "encode_approval_key",
    "fingerprint_facts",
    "generate_approval_key",
    "issue_approval",
    "key_id",
    "load_approval_key",
    "new_nonce",
    "parse_approval_token",
    "verify_approval",
    "write_approval_key",
)
