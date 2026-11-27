"""HMAC-signed approval tokens.

The token is canonical JSON with an HMAC-SHA256 signature. The key is a per-session
consistency key, not an authorization secret. Strict parsing rejects duplicate keys,
unknown fields, wrong types, and any binding mismatch.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from cairn.approval.binding import (
    APPROVAL_KIND,
    APPROVAL_SCHEMA_VERSION,
    ApprovalError,
    ApprovalInputs,
    DeviceBinding,
    DeviceBindingSource,
    ToolBinding,
)
from cairn.core.tristate import Tri
from cairn.safety.engine import CheckState

TOKEN_SCHEMA_VERSION: Final = 1
DOCUMENT_KIND: Final = "cairn.approval-token"
KEY_BYTES: Final = 32
MAX_TOKEN_BYTES: Final = 2 * 1024 * 1024
MAX_TEXT_CHARS: Final = 4096
MIN_REASON_CHARS: Final = 10
_KEY_FILE_LIMIT: Final = 1024

_HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE: Final = re.compile(r"^[0-9a-f]{16}$")


@dataclass(frozen=True, slots=True)
class ApprovalToken:
    """A signed statement that a specific set of inputs was approved."""

    schema_version: int
    key_id: str
    issued_at: datetime
    operator: str
    reason: str
    inputs: ApprovalInputs
    binding_sha256: str
    signature: str

    def __post_init__(self) -> None:
        if self.schema_version != TOKEN_SCHEMA_VERSION:
            raise ApprovalError(f"unsupported approval token schema {self.schema_version}")
        if _KEY_ID_RE.fullmatch(self.key_id) is None:
            raise ApprovalError("approval key id must be 16 lowercase hex characters")
        if self.issued_at.tzinfo is None:
            raise ApprovalError("approval issued_at must be timezone-aware")
        _validate_text(self.operator, "approval operator")
        _validate_text(self.reason, "approval reason")
        if len(self.reason.strip()) < MIN_REASON_CHARS:
            raise ApprovalError(f"approval reason must be at least {MIN_REASON_CHARS} characters")
        _require_hex64(self.binding_sha256, "approval binding_sha256")
        _require_hex64(self.signature, "approval signature")
        if self.binding_sha256 != self.inputs.binding_sha256:
            raise ApprovalError("approval binding hash does not match the bound inputs")

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "kind": DOCUMENT_KIND,
            "key_id": self.key_id,
            "issued_at": _canonical_timestamp(self.issued_at),
            "operator": self.operator,
            "reason": self.reason,
            "binding": self.inputs.binding_payload(),
            "binding_sha256": self.binding_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        return self.payload() | {"signature": self.signature}

    def to_json(self) -> str:
        return (
            json.dumps(
                self.to_dict(),
                indent=2,
                sort_keys=True,
                ensure_ascii=True,
            )
            + "\n"
        )


@dataclass(frozen=True, slots=True)
class ApprovalVerdict:
    """The result of comparing a signed token with current inputs."""

    state: Tri
    reasons: tuple[str, ...]
    mismatches: tuple[str, ...] = ()
    token_sha256: str | None = None
    binding_sha256: str | None = None
    key_id: str | None = None
    issued_at: str | None = None
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.reasons:
            raise ApprovalError("approval verdict must carry a reason")
        for reason in self.reasons:
            if not reason.strip():
                raise ApprovalError("approval verdict reasons must not be empty")
        for warning in self.warnings:
            if not warning.strip():
                raise ApprovalError("approval verdict warnings must not be empty")
        if self.state is Tri.TRUE and self.mismatches:
            raise ApprovalError("a TRUE approval verdict cannot carry mismatches")
        if self.state is Tri.TRUE and self.token_sha256 is None:
            raise ApprovalError("a TRUE approval verdict must cite the token hash")
        if self.state is Tri.FALSE and not self.mismatches:
            raise ApprovalError("a FALSE approval verdict must name a mismatch")
        if self.token_sha256 is not None:
            _require_hex64(self.token_sha256, "approval token_sha256")
        if self.binding_sha256 is not None:
            _require_hex64(self.binding_sha256, "approval binding_sha256")
        if self.key_id is not None and _KEY_ID_RE.fullmatch(self.key_id) is None:
            raise ApprovalError("approval key id must be 16 lowercase hex characters")

    def to_check_state(self) -> CheckState:
        evidence_ids = (self.token_sha256,) if self.token_sha256 is not None else ()
        return CheckState(
            state=self.state,
            detail="; ".join(self.reasons),
            evidence_ids=evidence_ids,
            warnings=self.warnings,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.name,
            "reasons": list(self.reasons),
            "mismatches": list(self.mismatches),
            "warnings": list(self.warnings),
            "token_sha256": self.token_sha256,
            "binding_sha256": self.binding_sha256,
            "key_id": self.key_id,
            "issued_at": self.issued_at,
        }


def generate_approval_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def key_id(key: bytes) -> str:
    _validate_key(key)
    return hashlib.sha256(key).hexdigest()[:16]


def encode_approval_key(key: bytes) -> str:
    _validate_key(key)
    return key.hex()


def load_approval_key(path: Path) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ApprovalError(f"cannot stat approval key {path}: {exc}") from exc
    if size > _KEY_FILE_LIMIT:
        raise ApprovalError(f"approval key file at {path} is too large")
    try:
        text = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise ApprovalError(f"cannot read approval key {path}: {exc}") from exc
    if _HEX64_RE.fullmatch(text) is None:
        raise ApprovalError("approval key file must contain exactly 64 lowercase hex characters")
    return bytes.fromhex(text)


def write_approval_key(path: Path, key: bytes, *, overwrite: bool = False) -> None:
    _validate_key(key)
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if overwrite else os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise ApprovalError(
            f"approval key already exists at {path}; pass --force to overwrite"
        ) from exc
    except OSError as exc:
        raise ApprovalError(f"cannot create approval key {path}: {exc}") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            handle.write(key.hex() + "\n")
    except OSError as exc:
        raise ApprovalError(f"cannot write approval key {path}: {exc}") from exc


def issue_approval(
    inputs: ApprovalInputs,
    key: bytes,
    *,
    operator: str,
    reason: str,
    issued_at: datetime | None = None,
) -> ApprovalToken:
    _validate_key(key)
    operator = operator.strip()
    reason = reason.strip()
    _validate_text(operator, "approval operator")
    _validate_text(reason, "approval reason")
    if len(reason) < MIN_REASON_CHARS:
        raise ApprovalError(f"approval reason must be at least {MIN_REASON_CHARS} characters")
    timestamp = issued_at if issued_at is not None else datetime.now(UTC)
    token = ApprovalToken(
        schema_version=TOKEN_SCHEMA_VERSION,
        key_id=key_id(key),
        issued_at=timestamp,
        operator=operator,
        reason=reason,
        inputs=inputs,
        binding_sha256=inputs.binding_sha256,
        signature="0" * 64,
    )
    return replace(token, signature=_sign(key, _payload_bytes(token)))


def parse_approval_token(text: str, key: bytes) -> ApprovalToken:
    _validate_key(key)
    if len(text) > MAX_TOKEN_BYTES:
        raise ApprovalError(f"approval token is above the {MAX_TOKEN_BYTES}-character limit")
    try:
        raw: object = json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ApprovalError(f"approval token is not valid JSON: {exc}") from exc
    except RecursionError as exc:
        raise ApprovalError("approval token is nested too deeply") from exc
    if not isinstance(raw, dict):
        raise ApprovalError("approval token must be a JSON object")
    document: dict[str, Any] = raw
    _require_exact_keys(
        document,
        {
            "schema_version",
            "kind",
            "key_id",
            "issued_at",
            "operator",
            "reason",
            "binding",
            "binding_sha256",
            "signature",
        },
        "approval token",
    )
    if document["kind"] != DOCUMENT_KIND:
        raise ApprovalError("approval token kind is not cairn.approval-token")
    schema_version = _expect_int(document["schema_version"], "token schema_version")
    if schema_version != TOKEN_SCHEMA_VERSION:
        raise ApprovalError(f"unsupported approval token schema {schema_version}")

    recorded_key_id = _expect_str(document["key_id"], "token key_id")
    if _KEY_ID_RE.fullmatch(recorded_key_id) is None:
        raise ApprovalError("approval key id must be 16 lowercase hex characters")
    if recorded_key_id != key_id(key):
        raise ApprovalError("approval token was signed by a different key")

    issued_at = _parse_timestamp(_expect_str(document["issued_at"], "token issued_at"))
    operator = _expect_text(document["operator"], "token operator")
    reason = _expect_text(document["reason"], "token reason")
    if len(reason.strip()) < MIN_REASON_CHARS:
        raise ApprovalError(f"approval reason must be at least {MIN_REASON_CHARS} characters")

    binding_raw = document["binding"]
    if not isinstance(binding_raw, dict):
        raise ApprovalError("approval binding must be a JSON object")
    inputs = _parse_inputs(binding_raw)
    recorded_binding = _expect_hex64(document["binding_sha256"], "token binding_sha256")
    if recorded_binding != inputs.binding_sha256:
        raise ApprovalError("approval binding hash does not match the bound inputs")
    signature = _expect_hex64(document["signature"], "token signature")

    token = ApprovalToken(
        schema_version=schema_version,
        key_id=recorded_key_id,
        issued_at=issued_at,
        operator=operator,
        reason=reason,
        inputs=inputs,
        binding_sha256=recorded_binding,
        signature=signature,
    )
    expected = _sign(key, _payload_bytes(token))
    if not hmac.compare_digest(signature, expected):
        raise ApprovalError("approval signature is invalid")
    return token


def verify_approval(
    token_text: str,
    key: bytes,
    current: ApprovalInputs,
) -> ApprovalVerdict:
    """Compare a signed token with the current bound inputs."""
    _validate_key(key)
    token_sha = _text_sha256(token_text)
    try:
        token = parse_approval_token(token_text, key)
    except ApprovalError as exc:
        return ApprovalVerdict(
            state=Tri.FALSE,
            reasons=(str(exc),),
            mismatches=("token",),
            token_sha256=token_sha,
        )

    mismatches: list[str] = []
    reasons: list[str] = []
    _compare(
        "plan_sha256",
        token.inputs.plan_sha256,
        current.plan_sha256,
        mismatches,
        reasons,
    )
    _compare(
        "evidence_snapshot_sha256",
        token.inputs.evidence_snapshot_sha256,
        current.evidence_snapshot_sha256,
        mismatches,
        reasons,
    )
    _compare(
        "archive_sha256",
        token.inputs.archive_sha256,
        current.archive_sha256,
        mismatches,
        reasons,
    )
    _compare_device(token.inputs.device, current.device, mismatches, reasons)
    _compare_package_hashes(
        token.inputs.package_hashes,
        current.package_hashes,
        mismatches,
        reasons,
    )
    _compare_tools(token.inputs.tools, current.tools, mismatches, reasons)

    issued_at = _canonical_timestamp(token.issued_at)
    if mismatches:
        return ApprovalVerdict(
            state=Tri.FALSE,
            reasons=tuple(reasons),
            mismatches=tuple(mismatches),
            token_sha256=token_sha,
            binding_sha256=token.binding_sha256,
            key_id=token.key_id,
            issued_at=issued_at,
        )

    warnings: tuple[str, ...] = ()
    if token.inputs.device.source is DeviceBindingSource.CALLER:
        warnings = ("device binding was caller-supplied, not probed; it is not device evidence",)
    return ApprovalVerdict(
        state=Tri.TRUE,
        reasons=(
            "approval binding matches the current plan, evidence snapshot, "
            "package, device, and tools",
        ),
        token_sha256=token_sha,
        binding_sha256=token.binding_sha256,
        key_id=token.key_id,
        issued_at=issued_at,
        warnings=warnings,
    )


def _parse_inputs(raw: Mapping[str, Any]) -> ApprovalInputs:
    _require_exact_keys(
        raw,
        {
            "kind",
            "schema_version",
            "plan_sha256",
            "evidence_snapshot_sha256",
            "archive_sha256",
            "package_hashes",
            "device",
            "tools",
        },
        "approval binding",
    )
    if raw["kind"] != APPROVAL_KIND:
        raise ApprovalError("approval binding kind is not cairn.approval")
    schema_version = _expect_int(raw["schema_version"], "binding schema_version")
    if schema_version != APPROVAL_SCHEMA_VERSION:
        raise ApprovalError(f"unsupported approval binding schema {schema_version}")

    package_raw = raw["package_hashes"]
    if not isinstance(package_raw, dict):
        raise ApprovalError("approval package_hashes must be a JSON object")
    package_hashes: list[tuple[str, str]] = []
    for name, digest_raw in package_raw.items():
        if not isinstance(name, str):
            raise ApprovalError("approval package entry name must be a string")
        _validate_entry_name(name)
        package_hashes.append((name, _expect_hex64(digest_raw, f"package hash for {name!r}")))
    package_hashes.sort()

    device_raw = raw["device"]
    if not isinstance(device_raw, dict):
        raise ApprovalError("approval device must be a JSON object")
    device = _parse_device(device_raw)

    tools_raw = raw["tools"]
    if not isinstance(tools_raw, list):
        raise ApprovalError("approval tools must be a JSON array")
    tools: list[ToolBinding] = []
    for item in tools_raw:
        if not isinstance(item, dict):
            raise ApprovalError("each approval tool must be a JSON object")
        _require_exact_keys(item, {"name", "version", "sha256"}, "tool binding")
        tools.append(
            ToolBinding(
                name=_expect_str(item["name"], "tool name"),
                version=_optional_str(item["version"], "tool version"),
                sha256=_optional_str(item["sha256"], "tool sha256"),
            )
        )
    tools.sort(key=lambda tool: tool.name)

    return ApprovalInputs(
        plan_sha256=_expect_hex64(raw["plan_sha256"], "plan_sha256"),
        evidence_snapshot_sha256=_expect_hex64(
            raw["evidence_snapshot_sha256"], "evidence_snapshot_sha256"
        ),
        archive_sha256=_expect_hex64(raw["archive_sha256"], "archive_sha256"),
        package_hashes=tuple(package_hashes),
        device=device,
        tools=tuple(tools),
    )


def _parse_device(raw: Mapping[str, Any]) -> DeviceBinding:
    _require_exact_keys(
        raw,
        {"nonce", "fingerprint_sha256", "source"},
        "device binding",
    )
    source_text = _expect_str(raw["source"], "device source")
    try:
        source = DeviceBindingSource(source_text)
    except ValueError as exc:
        raise ApprovalError(f"unknown device binding source {source_text!r}") from exc
    return DeviceBinding(
        nonce=_expect_str(raw["nonce"], "device nonce"),
        fingerprint_sha256=_expect_hex64(raw["fingerprint_sha256"], "device fingerprint_sha256"),
        source=source,
    )


def _compare(
    label: str,
    expected: str,
    actual: str,
    mismatches: list[str],
    reasons: list[str],
) -> None:
    if expected != actual:
        mismatches.append(label)
        reasons.append(f"{label} differs: approval {expected!r} != current {actual!r}")


def _compare_device(
    expected: DeviceBinding,
    actual: DeviceBinding,
    mismatches: list[str],
    reasons: list[str],
) -> None:
    _compare("device.nonce", expected.nonce, actual.nonce, mismatches, reasons)
    _compare(
        "device.fingerprint_sha256",
        expected.fingerprint_sha256,
        actual.fingerprint_sha256,
        mismatches,
        reasons,
    )
    _compare(
        "device.source",
        expected.source.value,
        actual.source.value,
        mismatches,
        reasons,
    )


def _compare_package_hashes(
    expected: tuple[tuple[str, str], ...],
    actual: tuple[tuple[str, str], ...],
    mismatches: list[str],
    reasons: list[str],
) -> None:
    expected_map = dict(expected)
    actual_map = dict(actual)
    changed = sorted(
        name
        for name in expected_map.keys() & actual_map.keys()
        if expected_map[name] != actual_map[name]
    )
    removed = sorted(expected_map.keys() - actual_map.keys())
    added = sorted(actual_map.keys() - expected_map.keys())
    if changed:
        mismatches.append("package_hashes")
        reasons.append("package entry hashes changed: " + _summarize(changed))
    if removed:
        mismatches.append("package_hashes")
        reasons.append("package entries missing from the current package: " + _summarize(removed))
    if added:
        mismatches.append("package_hashes")
        reasons.append("package entries added since approval: " + _summarize(added))


def _compare_tools(
    expected: tuple[ToolBinding, ...],
    actual: tuple[ToolBinding, ...],
    mismatches: list[str],
    reasons: list[str],
) -> None:
    expected_map = {tool.name: tool for tool in expected}
    actual_map = {tool.name: tool for tool in actual}
    changed = sorted(
        name
        for name in expected_map.keys() & actual_map.keys()
        if expected_map[name] != actual_map[name]
    )
    removed = sorted(expected_map.keys() - actual_map.keys())
    added = sorted(actual_map.keys() - expected_map.keys())
    if changed or removed or added:
        mismatches.append("tools")
        if changed:
            reasons.append("tool identities changed: " + _summarize(changed))
        if removed:
            reasons.append("tools missing from the current set: " + _summarize(removed))
        if added:
            reasons.append("tools added since approval: " + _summarize(added))


def _summarize(names: list[str]) -> str:
    if len(names) <= 10:
        return ", ".join(names)
    return ", ".join(names[:10]) + f", ... ({len(names)} total)"


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ApprovalError(f"duplicate JSON key {key!r} in approval token")
        result[key] = value
    return result


def _require_exact_keys(
    raw: Mapping[str, Any],
    expected: set[str],
    what: str,
) -> None:
    keys = set(raw)
    missing = expected - keys
    extra = keys - expected
    if missing:
        raise ApprovalError(f"{what} is missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ApprovalError(f"{what} has unknown keys: {', '.join(sorted(extra))}")


def _expect_int(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApprovalError(f"{what} must be an integer")
    return value


def _expect_str(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise ApprovalError(f"{what} must be a string")
    return value


def _optional_str(value: object, what: str) -> str | None:
    if value is None:
        return None
    return _expect_str(value, what)


def _expect_hex64(value: object, what: str) -> str:
    text = _expect_str(value, what)
    _require_hex64(text, what)
    return text


def _expect_text(value: object, what: str) -> str:
    text = _expect_str(value, what)
    _validate_text(text, what)
    return text


def _validate_text(value: str, what: str) -> None:
    if not value.strip():
        raise ApprovalError(f"{what} must not be empty")
    if len(value) > MAX_TEXT_CHARS:
        raise ApprovalError(f"{what} is above the {MAX_TEXT_CHARS}-character limit")


def _validate_entry_name(name: str) -> None:
    if not name:
        raise ApprovalError("package entry name must not be empty")
    if len(name) > 1024:
        raise ApprovalError("package entry name is above the 1024-character limit")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise ApprovalError(f"package entry name {name!r} contains control characters")


def _require_hex64(value: str, what: str) -> None:
    if _HEX64_RE.fullmatch(value) is None:
        raise ApprovalError(f"{what} must be 64 lowercase hex characters")


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes):
        raise ApprovalError("approval key must be bytes")
    if len(key) != KEY_BYTES:
        raise ApprovalError(f"approval key must be exactly {KEY_BYTES} bytes")


def _canonical_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ApprovalError("approval timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat()


def _parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ApprovalError(f"invalid approval timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        raise ApprovalError("approval timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _payload_bytes(token: ApprovalToken) -> bytes:
    return json.dumps(
        token.payload(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _sign(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
