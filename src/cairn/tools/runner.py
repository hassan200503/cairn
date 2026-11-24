"""Bounded, cancellable subprocess execution for external flash tools.

Official tools are untrusted infrastructure: they may hang, flood stdout, or be
replaced by a different binary. Every invocation is explicit argv, no shell, a
scrubbed environment, a wall-clock budget, and bounded output buffers.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from cairn.core.errors import ToolError

DEFAULT_TIMEOUT_S = 30.0
DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024
_READ_CHUNK_BYTES = 65536
_KILL_GRACE_S = 2.0
_THREAD_JOIN_S = 5.0

_ENV_ALLOWLIST: tuple[str, ...] = (
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "LANG",
    "LC_ALL",
)


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Outcome of one bounded tool invocation."""

    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False
    cancelled: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.cancelled

    @property
    def combined_output(self) -> str:
        return f"{self.stdout}\n{self.stderr}"


class _BoundedBuffer:
    """Keep the first ``limit`` bytes and keep draining without storing more."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._data = bytearray()
        self.truncated = False

    def append(self, chunk: bytes) -> None:
        room = self._limit - len(self._data)
        if room > 0:
            self._data.extend(chunk[:room])
        if len(chunk) > max(room, 0):
            self.truncated = True

    def text(self) -> str:
        return self._data.decode("utf-8", errors="replace")


def _drain(stream: IO[bytes], buffer: _BoundedBuffer) -> None:
    try:
        while True:
            chunk = stream.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            buffer.append(chunk)
    except (OSError, ValueError):
        return
    finally:
        with contextlib.suppress(OSError):
            stream.close()


def _write_stdin(stream: IO[bytes], data: bytes) -> None:
    try:
        stream.write(data)
        stream.close()
    except (OSError, ValueError):
        return


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=_KILL_GRACE_S)
        return
    except subprocess.TimeoutExpired:
        pass
    process.kill()
    try:
        process.wait(timeout=_KILL_GRACE_S)
    except subprocess.TimeoutExpired:
        return


class ToolRunner:
    """Run a tool without a shell and return a classified, bounded result."""

    def __init__(
        self,
        *,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        env_allowlist: Sequence[str] = _ENV_ALLOWLIST,
    ) -> None:
        if max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        self._max_output_bytes = max_output_bytes
        self._env_allowlist = tuple(env_allowlist)

    def scrub_env(self) -> dict[str, str]:
        """Return a minimal environment; no tokens, keys, or user profiles."""
        env = {key: os.environ[key] for key in self._env_allowlist if key in os.environ}
        env["PYTHONIOENCODING"] = "utf-8"
        if os.name == "nt":
            system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
            env["PATH"] = f"{system_root}\\System32;{system_root}"
        else:
            env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
        return env

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        cancel: threading.Event | None = None,
        extra_env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        stdin_bytes: bytes | None = None,
    ) -> ToolResult:
        if not argv:
            raise ValueError("argv must not be empty")
        if timeout_s < 0:
            raise ValueError("timeout_s must not be negative")

        env = self.scrub_env()
        if extra_env is not None:
            env.update(extra_env)

        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        started = time.monotonic()
        try:
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=None if cwd is None else str(cwd),
                shell=False,
                creationflags=creationflags,
            )
        except OSError as exc:
            raise ToolError(f"could not start tool {argv[0]!r}: {exc}") from exc

        if process.stdout is None or process.stderr is None:
            _stop(process)
            raise ToolError("tool process did not expose stdout/stderr pipes")

        stdout_buffer = _BoundedBuffer(self._max_output_bytes)
        stderr_buffer = _BoundedBuffer(self._max_output_bytes)
        stdout_thread = threading.Thread(
            target=_drain, args=(process.stdout, stdout_buffer), daemon=True
        )
        stderr_thread = threading.Thread(
            target=_drain, args=(process.stderr, stderr_buffer), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()

        if stdin_bytes is not None and process.stdin is not None:
            stdin_thread = threading.Thread(
                target=_write_stdin, args=(process.stdin, stdin_bytes), daemon=True
            )
            stdin_thread.start()

        deadline = None if timeout_s == 0 else started + timeout_s
        timed_out = False
        cancelled = False
        while True:
            try:
                process.wait(timeout=0.05)
                break
            except subprocess.TimeoutExpired:
                pass
            if cancel is not None and cancel.is_set():
                cancelled = True
                _stop(process)
                break
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                _stop(process)
                break

        stdout_thread.join(timeout=_THREAD_JOIN_S)
        stderr_thread.join(timeout=_THREAD_JOIN_S)

        duration = time.monotonic() - started
        return ToolResult(
            argv=tuple(argv),
            exit_code=process.returncode if process.returncode is not None else -1,
            stdout=stdout_buffer.text(),
            stderr=stderr_buffer.text(),
            duration_s=duration,
            stdout_truncated=stdout_buffer.truncated,
            stderr_truncated=stderr_buffer.truncated,
            timed_out=timed_out,
            cancelled=cancelled,
        )
