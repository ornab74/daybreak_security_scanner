from __future__ import annotations

import unittest
from pydantic import ValidationError

from models import DependencyDeepReview


def payload():
    return {
        "package":"pypi:zipp==4.1.0", "severity":"high", "applicable":False,
        "confirmed_risk":"low", "confidence":.99,
        "evidence_summary":"CVE affected versions before 3.19.1.",
        "affected_reasoning":"4.1.0 is outside the affected range.",
        "recommended_action":"Retain the secure pin.", "fixed_or_safer_version":"3.19.1",
        "verification_note":"Exact pin compared with affected range.",
    }


class DependencyEvidenceTests(unittest.TestCase):
    def test_disproved_exact_pin_becomes_low(self):
        review=DependencyDeepReview.model_validate(payload())
        self.assertFalse(review.applicable)
        self.assertEqual(review.confirmed_risk.value,"low")

    def test_non_applicable_cannot_remain_high(self):
        value=payload(); value["confirmed_risk"]="high"
        with self.assertRaises(ValidationError): DependencyDeepReview.model_validate(value)

    def test_applicable_cannot_be_low(self):
        value=payload(); value["applicable"]=True
        with self.assertRaises(ValidationError): DependencyDeepReview.model_validate(value)


if __name__ == "__main__": unittest.main()
