from __future__ import annotations

import sys
import threading
import time

import pytest

from cairn.core.errors import ToolError
from cairn.tools.runner import ToolRunner


def test_captures_stdout_stderr_and_exit_code() -> None:
    result = ToolRunner().run(
        (sys.executable, "-c", "import sys; print('out'); sys.stderr.write('err\\n')")
    )
    assert result.ok
    assert result.exit_code == 0
    assert result.stdout.strip() == "out"
    assert result.stderr.strip() == "err"
    assert not result.timed_out
    assert not result.cancelled


def test_nonzero_exit_is_not_ok() -> None:
    result = ToolRunner().run((sys.executable, "-c", "import sys; sys.exit(3)"))
    assert result.exit_code == 3
    assert not result.ok


def test_timeout_kills_the_process() -> None:
    started = time.monotonic()
    result = ToolRunner().run(
        (sys.executable, "-c", "import time; time.sleep(30)"),
        timeout_s=0.3,
    )
    elapsed = time.monotonic() - started
    assert result.timed_out
    assert not result.ok
    assert elapsed < 15


def test_cancel_event_stops_the_process() -> None:
    cancel = threading.Event()
    cancel.set()
    result = ToolRunner().run(
        (sys.executable, "-c", "import time; time.sleep(30)"),
        timeout_s=10,
        cancel=cancel,
    )
    assert result.cancelled
    assert not result.ok


def test_output_is_bounded() -> None:
    result = ToolRunner(max_output_bytes=10).run((sys.executable, "-c", "print('x' * 1000)"))
    assert result.stdout == "x" * 10
    assert result.stdout_truncated
    assert result.stderr == ""


def test_environment_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAIRN_TEST_SECRET", "do-not-leak")
    result = ToolRunner().run(
        (
            sys.executable,
            "-c",
            "import os; print(os.environ.get('CAIRN_TEST_SECRET', 'missing'))",
        )
    )
    assert result.stdout.strip() == "missing"


def test_stdin_bytes_are_delivered() -> None:
    result = ToolRunner().run(
        (sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"),
        stdin_bytes=b"hello",
    )
    assert result.ok
    assert result.stdout == "hello"


def test_missing_executable_raises_tool_error(tmp_path) -> None:
    with pytest.raises(ToolError, match="could not start"):
        ToolRunner().run((str(tmp_path / "does-not-exist.exe"),), timeout_s=1)


def test_empty_argv_is_rejected() -> None:
    with pytest.raises(ValueError, match="argv"):
        ToolRunner().run(())
