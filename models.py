from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, model_validator


class Risk(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class Ratings(BaseModel):
    ratings: list[Risk] = Field(
        description="Exactly one risk/review-priority enum per input item, in input order."
    )


class DependencyRiskRating(BaseModel):
    current_risk: Risk
    future_risk: Risk
    future_confidence: float = Field(ge=0.0, le=1.0)
    surface_signals: list["SurfaceSignal"] = Field(default_factory=list, max_length=12)


class SurfaceSignal(BaseModel):
    domain: Literal["capability", "exposure", "resilience", "trajectory"]
    strength: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    polarity: Literal["support", "mitigate", "contradict"] = "support"


class DependencyRiskMap(BaseModel):
    ratings: list[DependencyRiskRating] = Field(
        description="Exactly one current/future risk object per dependency, in input order."
    )


class DependencyDeepReview(BaseModel):
    package: str
    severity: Literal["medium", "high"]
    applicable: bool
    confirmed_risk: Risk
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_summary: str
    affected_reasoning: str
    recommended_action: str
    fixed_or_safer_version: str | None = None
    verification_note: str

    @model_validator(mode="after")
    def validate_applicability_conclusion(self):
        if not self.applicable and self.confirmed_risk != Risk.low:
            raise ValueError("a non-applicable advisory must produce confirmed_risk=low")
        if self.applicable and self.confirmed_risk == Risk.low:
            raise ValueError("an applicable advisory cannot produce confirmed_risk=low")
        return self


class DependencyFutureReview(BaseModel):
    package: str
    horizon_months: Literal[1, 6, 12, 36]
    risk: Literal["medium", "high"]
    confidence: float = Field(ge=0.0, le=1.0)
    forecast_summary: str
    risk_drivers: list[str] = Field(default_factory=list)
    uncertainty: str
    preventive_actions: list[str] = Field(default_factory=list)
    monitoring_triggers: list[str] = Field(default_factory=list)
    disclaimer: str = "Forecast only; not evidence of an undisclosed vulnerability."


class FutureRiskTimepoint(BaseModel):
    month: Literal[1, 6, 12, 36]
    risk: Literal["low", "medium", "high"]
    confidence: float = Field(ge=0.0, le=1.0)
    change_driver: str


class FutureRiskScenario(BaseModel):
    name: Literal["base_case", "patch_lag", "ecosystem_shock"]
    risk: Literal["low", "medium", "high"]
    preconditions: list[str] = Field(default_factory=list)
    leading_signal: str
    mitigation: str


class LeadingIndicator(BaseModel):
    metric: str
    trigger: str
    response: str


class AdvancedDependencyFutureReview(DependencyFutureReview):
    # Idea 1: a curve prevents one selected horizon from hiding risk migration.
    risk_timeline: list[FutureRiskTimepoint] = Field(min_length=4, max_length=4)
    # Idea 2: separates package hazard from the deployment's compensating controls.
    inherent_risk: Literal["low", "medium", "high"]
    residual_risk: Literal["low", "medium", "high"]
    control_assumptions: list[str] = Field(default_factory=list)
    highest_leverage_control: str
    # Idea 3: an epistemic ledger makes unsupported inference visible.
    observed_facts: list[str] = Field(default_factory=list)
    bounded_inferences: list[str] = Field(default_factory=list)
    critical_unknowns: list[str] = Field(default_factory=list)
    # Idea 4: fixed scenarios expose sensitivity to operational shocks.
    scenarios: list[FutureRiskScenario] = Field(min_length=3, max_length=3)
    # Idea 5: measurable triggers convert a static forecast into a watch system.
    leading_indicators: list[LeadingIndicator] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def validate_forecast_invariants(self):
        months = [point.month for point in self.risk_timeline]
        if sorted(months) != [1, 6, 12, 36]:
            raise ValueError("risk_timeline must contain each required month exactly once")
        names = [scenario.name for scenario in self.scenarios]
        if sorted(names) != ["base_case", "ecosystem_shock", "patch_lag"]:
            raise ValueError("scenarios must contain each required scenario exactly once")
        headline = next(point.risk for point in self.risk_timeline if point.month == self.horizon_months)
        if headline != self.risk:
            raise ValueError("headline risk must match the selected timeline horizon")
        order = {"low": 0, "medium": 1, "high": 2}
        if order[self.residual_risk] > order[self.inherent_risk]:
            raise ValueError("control-adjusted residual risk cannot exceed inherent risk")
        return self


class SourceFinding(BaseModel):
    severity: Literal["medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    title: str
    category: str
    evidence: str
    exploit_preconditions: str
    security_impact: str
    remediation_goal: str


class SourceReview(BaseModel):
    findings: list[SourceFinding] = Field(default_factory=list)
    no_findings_reason: str | None = None


class PatchProposal(BaseModel):
    finding_index: int = Field(ge=0)
    target_path: str
    unified_diff: str
    rationale: str
    security_properties_preserved: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)


class PatchVerification(BaseModel):
    approved: bool
    issues: list[str] = Field(default_factory=list)
    residual_risk: str
    verification_summary: str
