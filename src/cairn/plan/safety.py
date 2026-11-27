"""Bind a read-only plan candidate to a safety-engine report.

Plan construction and safety evaluation are deliberately separate: a plan can be
structurally complete while the evidence needed to execute it is unavailable. This
wrapper makes that distinction explicit at the CLI and future executor boundary.
"""

from __future__ import annotations

from dataclasses import dataclass

from cairn.plan.planner import Plan
from cairn.safety.engine import SafetyReport


@dataclass(frozen=True, slots=True)
class PlanAssessment:
    """A candidate plan together with its independent safety decision."""

    plan: Plan
    safety: SafetyReport

    @property
    def executable(self) -> bool:
        """Whether both structural and safety gates permit execution."""
        return self.plan.executable and self.safety.can_proceed

    def to_dict(self) -> dict[str, object]:
        """Emit both decisions without hiding the structural-plan result."""
        return self.plan.to_dict() | {
            "structurally_executable": self.plan.executable,
            "safety": self.safety.to_dict(),
            "executable": self.executable,
        }


def assess_plan(plan: Plan, safety: SafetyReport) -> PlanAssessment:
    """Attach a completed safety report to a candidate plan."""
    return PlanAssessment(plan=plan, safety=safety)
