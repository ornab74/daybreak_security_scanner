from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lockfiles import parse_dependency_file


class LockfileParserTests(unittest.TestCase):
    def parse(self, name: str, content: str):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, name)
            path.write_text(content, encoding="utf-8")
            return parse_dependency_file(path)[0]

    def test_requirements_preserves_range_semantics(self):
        records = self.parse("requirements.txt", "httpx>=0.27,<1\ncryptography==46.0.7\n")
        self.assertFalse(records[0].exact)
        self.assertTrue(records[1].exact)
        self.assertEqual(records[1].display(), "pypi:cryptography==46.0.7")

    def test_npm_package_lock(self):
        data = {"packages": {"node_modules/react": {"version": "19.1.0"}}}
        records = self.parse("package-lock.json", json.dumps(data))
        self.assertEqual(records[0].display(), "npm:react==19.1.0")

    def test_cargo_lock(self):
        records = self.parse("Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.219"\n')
        self.assertEqual(records[0].display(), "cargo:serde==1.0.219")

    def test_go_sum_deduplicates_module_and_go_mod(self):
        records = self.parse("go.sum", "example.com/mod v1.2.3 h1:a\nexample.com/mod v1.2.3/go.mod h1:b\n")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].display(), "go:example.com/mod==v1.2.3")

    def test_pubspec_lock(self):
        records = self.parse("pubspec.lock", 'packages:\n  http:\n    dependency: direct main\n    version: "1.4.0"\n')
        self.assertEqual(records[0].display(), "pub:http==1.4.0")

    def test_maven_property_version(self):
        records = self.parse("pom.xml", """<project><properties><jackson.version>2.19.2</jackson.version></properties><dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency></dependencies></project>""")
        self.assertEqual(records[0].display(), "maven:com.fasterxml.jackson.core:jackson-databind==2.19.2")


if __name__ == "__main__":
    unittest.main()
