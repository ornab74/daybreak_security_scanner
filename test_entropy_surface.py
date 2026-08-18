from __future__ import annotations

import unittest

from entropy_surface import analyze_surface


WEIGHTS = {"capability": 1.0, "exposure": 1.0, "resilience": .8, "trajectory": .65}


def item(domain, evidence, polarity="support"):
    return {"domain": domain, "strength": .9, "confidence": .9,
            "evidence": evidence, "polarity": polarity}


class NumPySurfaceTests(unittest.TestCase):
    def test_locality_repulsion_reduces_duplicates(self):
        state = analyze_surface([
            item("capability", "native parser accepts untrusted bytes"),
            item("capability", "native parser accepts untrusted bytes"),
        ], WEIGHTS)
        self.assertGreater(state.repulsion_loss, .5)
        self.assertLessEqual(state.domain_charge[0], 1.0)

    def test_contradiction_capacitor_stores_opposition(self):
        state = analyze_surface([
            item("exposure", "public endpoint reaches parser"),
            item("exposure", "public endpoint reaches parser", "contradict"),
        ], WEIGHTS)
        self.assertGreater(state.contradiction_charge, .75)
        self.assertAlmostEqual(float(state.domain_charge[1]), 0.0)

    def test_lattice_does_not_create_missing_locality_charge(self):
        one = analyze_surface([item("capability", "native memory parser")], WEIGHTS)
        bridged = analyze_surface([
            item("capability", "native memory parser"),
            item("exposure", "internet input reaches parser"),
        ], WEIGHTS)
        self.assertEqual(one.lattice_charge, 0.0)
        self.assertGreater(bridged.lattice_charge, 0.0)


if __name__ == "__main__":
    unittest.main()
