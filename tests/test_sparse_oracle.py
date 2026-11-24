"""Differential oracle tests against AOSP libsparse (simg2img/img2simg).

These tests skip with a reason when the host libsparse utilities are not
installed. CI runs them in a dedicated Ubuntu job with
``android-sdk-libsparse-utils``.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from cairn.sparse.format import validate_sparse_image

IMG2SIMG = shutil.which("img2simg")
SIMG2IMG = shutil.which("simg2img")
BLOCK = 4096

pytestmark = pytest.mark.skipif(
    IMG2SIMG is None or SIMG2IMG is None,
    reason="AOSP libsparse tools img2simg/simg2img are not installed",
)


def build_raw_image(blocks: int = 64) -> bytes:
    data = bytearray()
    for block in range(blocks):
        if block < 16:
            data.extend(b"\x00" * BLOCK)
        elif block < 24:
            data.extend(b"\xff" * BLOCK)
        else:
            data.extend(bytes((block * 37 + offset * 11) % 256 for offset in range(BLOCK)))
    return bytes(data)


def run_tool(argv: list[str]) -> None:
    completed = subprocess.run(argv, capture_output=True, check=False)
    assert completed.returncode == 0, (
        f"{argv[0]} failed with {completed.returncode}: "
        f"{completed.stderr.decode('utf-8', errors='replace')}"
    )


def test_sparse_roundtrip_matches_libsparse(tmp_path: Path) -> None:
    raw = build_raw_image()
    raw_path = tmp_path / "raw.img"
    sparse_path = tmp_path / "sparse.img"
    out_path = tmp_path / "out.img"
    raw_path.write_bytes(raw)

    run_tool([str(IMG2SIMG), str(raw_path), str(sparse_path), str(BLOCK)])

    image = validate_sparse_image(sparse_path.read_bytes())
    assert image.header.block_size == BLOCK
    assert image.header.total_blocks == len(raw) // BLOCK
    assert image.total_data_blocks == len(raw) // BLOCK

    run_tool([str(SIMG2IMG), str(sparse_path), str(out_path)])
    assert out_path.read_bytes() == raw
