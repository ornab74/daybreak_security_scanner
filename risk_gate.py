"""Deterministic entropy-bounded gate for prospective dependency risk.

This is a calibration mechanism, not a vulnerability probability model.  It limits
correlated evidence, rewards independent evidence domains, and never charges unknowns.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable

from entropy_surface import DOMAINS, analyze_surface


DOMAIN_WEIGHT = {"capability": 1.0, "exposure": 1.0, "resilience": .8, "trajectory": .65}
MEDIUM_GATE = {1: .72, 6: .66, 12: .61, 36: .56}
HIGH_GATE = {1: .92, 6: .89, 12: .86, 36: .82}


@dataclass(frozen=True)
class GateDecision:
    requested: str
    calibrated: str
    charge: float
    entropy: float
    locality_count: int
    supercharged: bool
    lattice_charge: float
    repulsion_loss: float
    contradiction_charge: float
    reason: str


def _value(signal) -> tuple[str, float]:
    domain = getattr(signal, "domain", None) or signal.get("domain")
    strength = getattr(signal, "strength", None)
    confidence = getattr(signal, "confidence", None)
    if strength is None:
        strength = signal.get("strength", 0)
    if confidence is None:
        confidence = signal.get("confidence", 0)
    return str(domain), max(0.0, min(1.0, float(strength))) * max(0.0, min(1.0, float(confidence)))


def tune_future_risk(requested: str, current: str, horizon_months: int,
                     signals: Iterable, future_confidence: float) -> GateDecision:
    """Calibrate a model rating with bounded, locality-diverse evidence charge."""
    signals = list(signals)
    surface = analyze_surface(signals, DOMAIN_WEIGHT)
    domain_charge = dict(zip(DOMAINS, surface.domain_charge.tolist()))
    active = [value for value in domain_charge.values() if value >= .18]
    locality_count = len(active)

    total = sum(active)
    if total and locality_count > 1:
        probabilities = [value / total for value in active]
        entropy = -sum(p * math.log(p) for p in probabilities) / math.log(len(DOMAINS))
    else:
        entropy = 0.0

    base = total / sum(DOMAIN_WEIGHT.values())
    diversity_multiplier = .72 + .28 * entropy
    confidence_multiplier = .65 + .35 * max(0.0, min(1.0, future_confidence))
    charge = base * diversity_multiplier * confidence_multiplier
    charge += min(.10, surface.lattice_charge * .35)
    charge -= min(.18, surface.contradiction_charge * .20)
    charge = max(0.0, min(1.0, charge))

    # A supercharge represents propagation, not mere package complexity. It requires
    # independently charged capability and exposure plus a third locality.
    bridge = domain_charge["capability"] >= .45 and domain_charge["exposure"] >= .45
    supercharged = bridge and locality_count >= 3 and entropy >= .55
    if supercharged:
        charge = min(1.0, charge * 1.18 + .08)

    medium_gate = MEDIUM_GATE[horizon_months]
    high_gate = HIGH_GATE[horizon_months]
    calibrated = "low"
    if charge >= medium_gate and locality_count >= 2 and bridge:
        calibrated = "medium"
    if charge >= high_gate and locality_count >= 3 and supercharged:
        calibrated = "high"

    # Short-term escalation from a LOW current outlook needs unusually strong present
    # evidence; elapsed time alone cannot supply charge.
    if current == "low" and horizon_months == 1 and charge < .82:
        calibrated = "low"
    requested_order = {"low": 0, "medium": 1, "high": 2}
    if requested_order[calibrated] > requested_order[requested]:
        calibrated = requested
    reason = (
        f"charge={charge:.2f}; gate={medium_gate:.2f}/{high_gate:.2f}; "
        f"localities={locality_count}; entropy={entropy:.2f}; bridge={'yes' if bridge else 'no'}; "
        f"lattice={surface.lattice_charge:.2f}; repelled={surface.repulsion_loss:.2f}; "
        f"capacitor={surface.contradiction_charge:.2f}"
    )
    return GateDecision(requested, calibrated, charge, entropy, locality_count, supercharged,
                        surface.lattice_charge, surface.repulsion_loss,
                        surface.contradiction_charge, reason)
