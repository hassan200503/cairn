#!/usr/bin/env bash
# Cairn installer for Linux/macOS. Installs the cairn-flash CLI as an isolated
# uv tool. Everything Cairn does is read-only until the M6 gate; this script
# only builds and installs the CLI and never touches a device.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "git is required. Install git and re-run." >&2
  exit 1
fi
if ! command -v uv >/dev/null 2>&1; then
  if command -v pip >/dev/null 2>&1; then
    pip install uv
  else
    echo "uv is not installed and pip was not found. Install Python 3.12+ and re-run." >&2
    exit 1
  fi
fi

repo="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" && pwd)"
(
  cd "$repo"
  uv sync
  uv tool install --from . cairn-flash --force
)

cairn version
echo
echo "Cairn installed. Try: cairn levels ; cairn --help"
echo "Read-only commands are safe on real devices. Writes exist only in the transcript simulator (ADR-027)."
