"""Transcript-driven stand-in for the official fastboot CLI.

Invoked as ``python -m cairn.sim.fastboot_sim <args...>`` with
``CAIRN_SIM_TRANSCRIPT`` pointing at a transcript. It matches argv exactly and
replays recorded output, exit codes, delays, and faults. Test-only.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from cairn.sim.transcript import TRANSCRIPT_ENV, TranscriptError, load_transcript


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    raw_path = os.environ.get(TRANSCRIPT_ENV)
    if not raw_path:
        sys.stderr.write(f"fastboot-sim: {TRANSCRIPT_ENV} is not set\n")
        return 2

    try:
        transcript = load_transcript(Path(raw_path))
    except TranscriptError as exc:
        sys.stderr.write(f"fastboot-sim: {exc}\n")
        return 2

    step = transcript.find(args)
    if step is None:
        sys.stderr.write(f"fastboot-sim: no recorded step for argv {args!r}\n")
        return 2

    if step.delay_s > 0:
        time.sleep(step.delay_s)

    if step.fault == "timeout":
        while True:
            time.sleep(3600)

    if step.fault == "garbage":
        sys.stdout.write("\x00\xffsimulated-garbage\n")
        sys.stdout.flush()
        return 0

    if step.fault == "truncated":
        sys.stdout.write(step.stdout[: len(step.stdout) // 2])
        sys.stdout.flush()
        return step.exit_code

    sys.stdout.write(step.stdout)
    sys.stdout.flush()

    if step.fault == "disconnect":
        sys.stderr.write(step.stderr or "fastboot: error: no devices/emulators found\n")
        return 255

    if step.fault == "fail":
        sys.stderr.write(step.stderr or "FAILED (remote: 'simulated failure')\n")
        return step.exit_code if step.exit_code != 0 else 1

    sys.stderr.write(step.stderr)
    sys.stderr.flush()
    return step.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
