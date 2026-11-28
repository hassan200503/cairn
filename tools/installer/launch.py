"""PyInstaller entry point: the same console script pyproject defines."""

from cairn.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
