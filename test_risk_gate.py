from __future__ import annotations

import unittest

from risk_gate import tune_future_risk


def signal(domain, strength=.9, confidence=.9):
    return {"domain": domain, "strength": strength, "confidence": confidence}


class EntropyGateTests(unittest.TestCase):
    def test_time_alone_cannot_raise_low(self):
        decision = tune_future_risk("medium", "low", 1, [], .9)
        self.assertEqual(decision.calibrated, "low")

    def test_correlated_capability_signals_do_not_cross_gate(self):
        signals = [signal("capability") for _ in range(10)]
        decision = tune_future_risk("medium", "low", 36, signals, .95)
        self.assertEqual(decision.calibrated, "low")
        self.assertEqual(decision.locality_count, 1)

    def test_missing_exposure_bridge_blocks_escalation(self):
        signals = [signal("capability"), signal("resilience"), signal("trajectory")]
        decision = tune_future_risk("high", "medium", 36, signals, .95)
        self.assertEqual(decision.calibrated, "low")

    def test_independent_strong_surfaces_can_charge(self):
        signals = [signal(domain, 1, 1) for domain in ("capability", "exposure", "resilience", "trajectory")]
        decision = tune_future_risk("medium", "low", 12, signals, 1)
        self.assertEqual(decision.calibrated, "medium")
        self.assertTrue(decision.supercharged)

    def test_gate_never_upgrades_model_rating(self):
        signals = [signal(domain, 1, 1) for domain in ("capability", "exposure", "resilience", "trajectory")]
        decision = tune_future_risk("low", "low", 36, signals, 1)
        self.assertEqual(decision.calibrated, "low")


if __name__ == "__main__":
    unittest.main()
