from __future__ import annotations

import unittest

from pydantic import ValidationError

from models import AdvancedDependencyFutureReview


def valid_payload():
    return {
        "package": "parser>=1",
        "horizon_months": 12,
        "risk": "medium",
        "confidence": .78,
        "forecast_summary": "Parser exposure warrants bounded monitoring.",
        "risk_drivers": ["untrusted input parser"],
        "uncertainty": "Deployment reachability is unknown.",
        "preventive_actions": ["bound parser inputs"],
        "monitoring_triggers": ["security release"],
        "risk_timeline": [
            {"month": 1, "risk": "low", "confidence": .8, "change_driver": "current controls"},
            {"month": 6, "risk": "medium", "confidence": .75, "change_driver": "patch latency"},
            {"month": 12, "risk": "medium", "confidence": .7, "change_driver": "constraint aging"},
            {"month": 36, "risk": "high", "confidence": .55, "change_driver": "unbounded staleness"},
        ],
        "inherent_risk": "high",
        "residual_risk": "medium",
        "control_assumptions": ["input size cap"],
        "highest_leverage_control": "isolate parsing",
        "observed_facts": ["package parses untrusted format"],
        "bounded_inferences": ["exposure depends on reachability"],
        "critical_unknowns": ["runtime call paths"],
        "scenarios": [
            {"name": "base_case", "risk": "medium", "preconditions": ["normal patching"], "leading_signal": "routine release", "mitigation": "upgrade"},
            {"name": "patch_lag", "risk": "high", "preconditions": ["SLA missed"], "leading_signal": "age > SLA", "mitigation": "block release"},
            {"name": "ecosystem_shock", "risk": "high", "preconditions": ["upstream compromise"], "leading_signal": "provenance alert", "mitigation": "freeze artifact"},
        ],
        "leading_indicators": [
            {"metric": "release age", "trigger": ">90 days behind", "response": "open upgrade incident"}
        ],
    }


class ForecastInvariantTests(unittest.TestCase):
    def test_valid_advanced_forecast(self):
        result = AdvancedDependencyFutureReview.model_validate(valid_payload())
        self.assertEqual(len(result.risk_timeline), 4)

    def test_duplicate_timepoint_rejected(self):
        payload = valid_payload()
        payload["risk_timeline"][0]["month"] = 6
        with self.assertRaises(ValidationError):
            AdvancedDependencyFutureReview.model_validate(payload)

    def test_missing_scenario_rejected(self):
        payload = valid_payload()
        payload["scenarios"][0]["name"] = "patch_lag"
        with self.assertRaises(ValidationError):
            AdvancedDependencyFutureReview.model_validate(payload)

    def test_headline_timeline_disagreement_rejected(self):
        payload = valid_payload()
        payload["risk"] = "high"
        with self.assertRaises(ValidationError):
            AdvancedDependencyFutureReview.model_validate(payload)

    def test_controls_cannot_increase_risk(self):
        payload = valid_payload()
        payload["inherent_risk"] = "low"
        with self.assertRaises(ValidationError):
            AdvancedDependencyFutureReview.model_validate(payload)


if __name__ == "__main__":
    unittest.main()
