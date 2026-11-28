"""Write-ahead journal for the Cairn executor.

The journal is an append-only JSONL file with a per-record SHA-256 hash chain and
an fsync on every append. Each record answers exactly one question a resumed run
needs: was this step started, and did it finish?

Crash consistency: a crash can leave a torn final line (bytes written without the
trailing newline or a truncated record). Loading reports the torn tail instead of
failing, because the last *complete* record is still trustworthy; corruption
anywhere else refuses the journal entirely. The journal is a crash-consistency
record, not a security boundary: a compromised host can rewrite it and recompute
the chain, exactly like the wizard session state hash (ADR-014).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from cairn.core.errors import JournalError

JOURNAL_KIND: Final = "cairn.executor-journal"
JOURNAL_SCHEMA_VERSION: Final = 1
MAX_JOURNAL_BYTES: Final = 32 * 1024 * 1024
MAX_RECORD_BYTES: Final = 64 * 1024
GENESIS_SHA256: Final = "0" * 64
# Growth policy: a journal that reaches this share of the byte limit is rotated
# to a continuation file at resume time instead of growing without bound. The
# predecessor file is never deleted — it is crash evidence.
ROTATE_THRESHOLD_BYTES: Final = 24 * 1024 * 1024
MAX_CHAIN_DEPTH: Final = 8

_HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")

_RECORD_KEYS: Final[frozenset[str]] = frozenset(
    {"seq", "kind", "at", "payload", "prev_sha256", "record_sha256"}
)


class JournalWriteError(JournalError):
    code = "JOURNAL_WRITE_ERROR"


class JournalCorruptError(JournalError):
    code = "JOURNAL_CORRUPT_ERROR"


class JournalKind(StrEnum):
    SESSION = "session"
    STEP_STARTED = "step_started"
    STEP_DONE = "step_done"
    STEP_FAILED = "step_failed"
    STEP_SKIPPED = "step_skipped"
    ABORTED = "aborted"
    COMPLETED = "completed"
    RECONCILED = "reconciled"


@dataclass(frozen=True, slots=True)
class JournalRecord:
    seq: int
    kind: JournalKind
    at: datetime
    payload: dict[str, object]
    prev_sha256: str
    record_sha256: str

    def __post_init__(self) -> None:
        if self.seq < 0:
            raise JournalCorruptError("journal record seq must not be negative")
        if self.at.tzinfo is None:
            raise JournalCorruptError("journal record timestamp must be timezone-aware")
        if _HEX64_RE.fullmatch(self.prev_sha256) is None:
            raise JournalCorruptError("journal prev_sha256 must be 64 lowercase hex characters")
        if _HEX64_RE.fullmatch(self.record_sha256) is None:
            raise JournalCorruptError("journal record_sha256 must be 64 lowercase hex characters")

    @staticmethod
    def compute_sha256(
        seq: int,
        kind: JournalKind,
        at: datetime,
        payload: Mapping[str, object],
    ) -> str:
        encoded = json.dumps(
            {
                "seq": seq,
                "kind": kind.value,
                "at": at.astimezone(UTC).isoformat(),
                "payload": dict(payload),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "seq": self.seq,
            "kind": self.kind.value,
            "at": self.at.astimezone(UTC).isoformat(),
            "payload": dict(self.payload),
            "prev_sha256": self.prev_sha256,
            "record_sha256": self.record_sha256,
        }

    @classmethod
    def from_dict(cls, raw: object) -> JournalRecord:
        mapping = _mapping(raw)
        _exact_keys(mapping)
        seq_raw = mapping["seq"]
        if isinstance(seq_raw, bool) or not isinstance(seq_raw, int):
            raise JournalCorruptError("journal seq must be an integer")
        kind_raw = mapping["kind"]
        if not isinstance(kind_raw, str):
            raise JournalCorruptError("journal kind must be a string")
        try:
            kind = JournalKind(kind_raw)
        except ValueError as exc:
            raise JournalCorruptError(f"unknown journal record kind {kind_raw!r}") from exc
        at_raw = mapping["at"]
        if not isinstance(at_raw, str):
            raise JournalCorruptError("journal timestamp must be a string")
        try:
            at = datetime.fromisoformat(at_raw)
        except ValueError as exc:
            raise JournalCorruptError(f"invalid journal timestamp {at_raw!r}") from exc
        if at.tzinfo is None:
            raise JournalCorruptError("journal timestamp must include a timezone")
        payload = mapping["payload"]
        if not isinstance(payload, dict):
            raise JournalCorruptError("journal payload must be a JSON object")
        return cls(
            seq=seq_raw,
            kind=kind,
            at=at,
            payload=payload,
            prev_sha256=_string(mapping["prev_sha256"], "prev_sha256"),
            record_sha256=_string(mapping["record_sha256"], "record_sha256"),
        )


@dataclass(frozen=True, slots=True)
class JournalLoad:
    records: tuple[JournalRecord, ...]
    torn_tail: bool
    valid_bytes: int
    """Byte offset just past the last complete record; a torn tail starts here."""

    @property
    def last(self) -> JournalRecord | None:
        return self.records[-1] if self.records else None


class Journal:
    """Append-only hash-chained record log."""

    def __init__(self, path: Path, records: Sequence[JournalRecord]) -> None:
        self._path = path
        self._records = list(records)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def records(self) -> tuple[JournalRecord, ...]:
        return tuple(self._records)

    @property
    def last(self) -> JournalRecord | None:
        return self._records[-1] if self._records else None

    @classmethod
    def create(cls, path: Path, session_payload: dict[str, object]) -> Journal:
        if path.exists():
            raise JournalWriteError(f"journal already exists at {path}")
        journal = cls(path, ())
        session_payload = _checked_payload(session_payload)
        parent = path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise JournalWriteError(f"cannot create journal directory {parent}: {exc}") from exc
        journal.append(JournalKind.SESSION, session_payload)
        return journal

    @classmethod
    def load(cls, path: Path, *, max_bytes: int = MAX_JOURNAL_BYTES) -> JournalLoad:
        if max_bytes <= 0:
            raise JournalError("journal byte limit must be positive")
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise JournalError(f"cannot stat journal {path}: {exc}") from exc
        if size > max_bytes:
            raise JournalError(f"journal is {size} bytes, above the {max_bytes}-byte limit")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise JournalError(f"cannot read journal {path}: {exc}") from exc
        if not raw:
            return JournalLoad(records=(), torn_tail=False, valid_bytes=0)

        lines = raw.split(b"\n")
        torn_tail = lines[-1] != b""
        complete = lines[:-1]
        records: list[JournalRecord] = []
        previous = GENESIS_SHA256
        offset = 0
        for index, line in enumerate(complete):
            if not line:
                raise JournalCorruptError(f"journal {path} has a blank record at line {index}")
            if len(line) > MAX_RECORD_BYTES:
                raise JournalCorruptError(f"journal record at line {index} is above the byte limit")
            record = _decode_record(line, path, index)
            if record.seq != index:
                raise JournalCorruptError(
                    f"journal {path} record {index} has seq {record.seq}; sequence is broken"
                )
            if record.prev_sha256 != previous:
                raise JournalCorruptError(
                    f"journal {path} record {record.seq} does not chain to its predecessor"
                )
            previous = record.record_sha256
            records.append(record)
            offset += len(line) + 1
        return JournalLoad(records=tuple(records), torn_tail=torn_tail, valid_bytes=offset)

    @classmethod
    def resume(cls, path: Path, *, max_bytes: int = MAX_JOURNAL_BYTES) -> Journal:
        loaded = cls.load(path, max_bytes=max_bytes)
        if loaded.torn_tail:
            # Cut the torn bytes off so the next append starts on a record boundary.
            with open(path, "r+b") as handle:
                handle.truncate(loaded.valid_bytes)
                handle.flush()
                os.fsync(handle.fileno())
        return cls(path, loaded.records)

    def append(self, kind: JournalKind, payload: dict[str, object]) -> JournalRecord:
        payload = _checked_payload(payload)
        last = self.last
        seq = 0 if last is None else last.seq + 1
        prev = GENESIS_SHA256 if last is None else last.record_sha256
        at = datetime.now(UTC)
        record = JournalRecord(
            seq=seq,
            kind=kind,
            at=at,
            payload=payload,
            prev_sha256=prev,
            record_sha256=JournalRecord.compute_sha256(seq, kind, at, payload),
        )
        line = (json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        if len(line) > MAX_RECORD_BYTES:
            raise JournalWriteError("journal record is above the byte limit")
        try:
            current_size = self._path.stat().st_size
        except FileNotFoundError:
            # An in-memory journal whose file was not created yet; the append
            # below creates it.
            current_size = 0
        except OSError as exc:
            raise JournalWriteError(f"cannot stat journal {self._path}: {exc}") from exc
        if current_size + len(line) > MAX_JOURNAL_BYTES:
            raise JournalWriteError(
                f"journal {self._path} is at its {MAX_JOURNAL_BYTES}-byte limit; "
                "resume the execution to rotate it to a continuation journal"
            )
        try:
            with open(self._path, "ab") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise JournalWriteError(f"cannot append to journal {self._path}: {exc}") from exc
        self._records.append(record)
        return record

    def size_bytes(self) -> int:
        try:
            return self._path.stat().st_size
        except OSError as exc:
            raise JournalError(f"cannot stat journal {self._path}: {exc}") from exc

    def rotate(self, successor_path: Path) -> Journal:
        """Continue this journal in a new file, chaining back to this one.

        The successor's session record names this journal's path and head hash;
        ``load_chain`` verifies that link on resume. The predecessor file is kept
        as evidence and is never deleted or rewritten.
        """
        last = self.last
        if last is None:
            raise JournalWriteError("cannot rotate an empty journal")
        continuation: dict[str, object] = {
            "journal_kind": JOURNAL_KIND,
            "schema_version": JOURNAL_SCHEMA_VERSION,
            "continues_from": {
                "path": str(self._path),
                "head_sha256": last.record_sha256,
                "records": len(self._records),
            },
            "reason": "journal growth policy rotation",
        }
        successor = Journal.create(successor_path, continuation)
        # The in-memory journal keeps the full chain so step-state reconciliation
        # and subsequent appends see the predecessor records too.
        return Journal(successor_path, (*self._records, *successor.records))

    @classmethod
    def load_chain(cls, path: Path, *, max_bytes: int = MAX_JOURNAL_BYTES) -> JournalLoad:
        """Load a journal and, if it continues an earlier one, its predecessors.

        The continuation link is verified against the predecessor's actual head
        hash; a missing, unreadable, or mismatched predecessor is corruption, not
        a soft warning, because the step states live in the chain.
        """
        return cls._load_chain(path, max_bytes=max_bytes, depth=0)

    @classmethod
    def _load_chain(cls, path: Path, *, max_bytes: int, depth: int) -> JournalLoad:
        if depth > MAX_CHAIN_DEPTH:
            raise JournalCorruptError(
                f"journal continuation chain starting at {path} is deeper than {MAX_CHAIN_DEPTH}"
            )
        tip = cls.load(path, max_bytes=max_bytes)
        if not tip.records or tip.records[0].kind is not JournalKind.SESSION:
            return tip
        continues = tip.records[0].payload.get("continues_from")
        if not isinstance(continues, dict):
            return tip
        predecessor_path_raw = continues.get("path")
        head = continues.get("head_sha256")
        if not isinstance(predecessor_path_raw, str) or not isinstance(head, str):
            raise JournalCorruptError(
                f"journal {path} has a continuation record without path/head_sha256"
            )
        if not _HEX64_RE.fullmatch(head):
            raise JournalCorruptError(f"journal {path} continuation head hash is not hex64")
        predecessor = cls._load_chain(
            Path(predecessor_path_raw), max_bytes=max_bytes, depth=depth + 1
        )
        if predecessor.last is None:
            raise JournalCorruptError(
                f"journal {path} continues from {predecessor_path_raw}, which has no records"
            )
        if predecessor.last.record_sha256 != head:
            raise JournalCorruptError(
                f"journal {path} continues from head {head[:12]}…, but "
                f"{predecessor_path_raw} ends at {predecessor.last.record_sha256[:12]}…"
            )
        return JournalLoad(
            records=predecessor.records + tip.records,
            torn_tail=tip.torn_tail,
            valid_bytes=tip.valid_bytes,
        )

    @classmethod
    def resume_chain(cls, path: Path, *, max_bytes: int = MAX_JOURNAL_BYTES) -> Journal:
        """Resume a possibly-continued journal; appends land in the tip file."""
        loaded = cls._load_chain(path, max_bytes=max_bytes, depth=0)
        if loaded.torn_tail:
            with open(path, "r+b") as handle:
                handle.truncate(loaded.valid_bytes)
                handle.flush()
                os.fsync(handle.fileno())
        return cls(path, loaded.records)


def _decode_record(line: bytes, path: Path, index: int) -> JournalRecord:
    try:
        document: object = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JournalCorruptError(
            f"journal {path} record {index} is not valid JSON: {exc}"
        ) from exc
    record = JournalRecord.from_dict(document)
    expected = JournalRecord.compute_sha256(record.seq, record.kind, record.at, record.payload)
    if expected != record.record_sha256:
        raise JournalCorruptError(
            f"journal {path} record {record.seq} hash does not cover its contents"
        )
    return record


def _checked_payload(payload: dict[str, object]) -> dict[str, object]:
    for key, value in payload.items():
        if not isinstance(key, str):
            raise JournalWriteError("journal payload keys must be strings")
        if value is not None and not isinstance(value, (str, int, float, bool, list, dict)):
            raise JournalWriteError(f"journal payload value for {key!r} is not JSON-serializable")
    return payload


def _mapping(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise JournalCorruptError("journal record must be a JSON object")
    return raw


def _exact_keys(mapping: dict[str, Any]) -> None:
    keys = set(mapping)
    missing = _RECORD_KEYS - keys
    extra = keys - _RECORD_KEYS
    if missing:
        raise JournalCorruptError(f"journal record is missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise JournalCorruptError(f"journal record has unknown keys: {', '.join(sorted(extra))}")


def _string(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise JournalCorruptError(f"journal {what} must be a string")
    return value
