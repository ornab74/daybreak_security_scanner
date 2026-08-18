from __future__ import annotations

import unittest

from prompts import dependency_prompt


class DependencyModePromptTests(unittest.TestCase):
    def test_current_mode_is_explicitly_neutral_for_future(self):
        prompt = dependency_prompt(["pypi:httpx==0.28.1"], "", 12, "current")
        self.assertIn("[scan_mode]current[/scan_mode]", prompt)
        self.assertIn("future_risk=low", prompt)

    def test_future_mode_is_explicit(self):
        prompt = dependency_prompt(["cargo:serde==1.0.0"], "", 1, "future")
        self.assertIn("[scan_mode]future[/scan_mode]", prompt)

    def test_both_is_default(self):
        prompt = dependency_prompt([], "", 36)
        self.assertIn("[scan_mode]both[/scan_mode]", prompt)


if __name__ == "__main__":
    unittest.main()
