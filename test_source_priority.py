from __future__ import annotations

import unittest

from source_review import source_review_priority


class SourcePriorityTests(unittest.TestCase):
    def test_application_code_precedes_workflows_and_tests(self):
        app={"path":"src/auth.py","extension":".py","kind":"file"}
        test={"path":"tests/test_auth.py","extension":".py","kind":"file"}
        workflow={"path":".github/workflows/build.yml","extension":".yml","kind":"file"}
        self.assertLess(source_review_priority(app),source_review_priority(test))
        self.assertLess(source_review_priority(test),source_review_priority(workflow))

    def test_configuration_follows_implementation(self):
        app={"path":"main.py","extension":".py","kind":"file"}
        config={"path":"config/settings.yaml","extension":".yaml","kind":"file"}
        self.assertLess(source_review_priority(app),source_review_priority(config))


if __name__ == "__main__":
    unittest.main()
