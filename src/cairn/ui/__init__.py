"""Cairn local workbench UI.

The UI is a thin, local orchestration layer over the same audited core the CLI
exposes (ADR-031). It adds no safety logic: every verdict rendered by the
dashboard comes from the safety engine, the wizard stages, or the recovery
drill, and every write verb reaches the transcript simulator only (ADR-027).
"""

from cairn.ui.app import dispatch
from cairn.ui.server import serve

__all__ = ["dispatch", "serve"]
