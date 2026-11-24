"""Cairn error hierarchy.

Every error carries a stable code and an optional operator hint. Errors are
classified so the executor and reporter can distinguish a retryable transport
fault from a safety veto or a hardware failure.
"""

from __future__ import annotations


class CairnError(Exception):
    code = "CAIRN_ERROR"
    recoverable = False

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:
        if self.hint:
            return f"{self.message} (hint: {self.hint})"
        return self.message


class ConfigurationError(CairnError):
    code = "CONFIGURATION_ERROR"


class SafetyViolation(CairnError):
    code = "SAFETY_VIOLATION"


class EvidenceError(CairnError):
    code = "EVIDENCE_ERROR"


class ProtocolError(CairnError):
    code = "PROTOCOL_ERROR"


class TransportError(CairnError):
    code = "TRANSPORT_ERROR"
    recoverable = True


class VerificationError(CairnError):
    code = "VERIFICATION_ERROR"


class JournalError(CairnError):
    code = "JOURNAL_ERROR"


class RecoveryError(CairnError):
    code = "RECOVERY_ERROR"


class ToolError(CairnError):
    code = "TOOL_ERROR"


class UnsupportedDeviceError(CairnError):
    code = "UNSUPPORTED_DEVICE"


class HardwareError(CairnError):
    code = "FATAL_HARDWARE"
