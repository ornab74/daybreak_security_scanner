import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from provider_store import PROVIDER_PRESETS, ProviderProfile, ProviderStore, validate_endpoint


class ProviderStoreTests(unittest.TestCase):
    def test_endpoint_rejects_insecure_and_local_targets(self):
        invalid = (
            "http://api.example.com/v1", "https://localhost/v1",
            "https://127.0.0.1/v1", "https://10.0.0.2/v1",
            "https://user:pass@example.com/v1", "https://example.com/v1?token=x",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_endpoint(value, resolve_dns=False)

    def test_documented_presets_are_not_speculative(self):
        self.assertEqual(PROVIDER_PRESETS["DigitalOcean Gradient · Kimi K2.5"][1], "kimi-k2.5")
        self.assertIn("Muse Spark 1.1", " ".join(PROVIDER_PRESETS))
        self.assertNotIn("kimi-k3", repr(PROVIDER_PRESETS).lower())

    def test_sqlite_contains_only_authenticated_ciphertext(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "providers.sqlite3"
            store = ProviderStore(path)
            profile = ProviderProfile("secret-label", "Custom OpenAI-compatible", "https://api.example.com/v1", "private-model", "super-secret-key", "chat_completions")
            key = b"K" * 32
            with patch("secure_store._get_or_create_master_key", return_value=key):
                store.save(profile, resolve_dns=False)
                loaded = store.load(resolve_dns=False)
            self.assertEqual(loaded, profile)
            raw = path.read_bytes()
            for secret in (b"secret-label", b"api.example.com", b"private-model", b"super-secret-key", b"Custom OpenAI-compatible"):
                self.assertNotIn(secret, raw)
            with sqlite3.connect(path) as db:
                columns = [row[1] for row in db.execute("PRAGMA table_info(profiles)")]
            self.assertEqual(columns, ["id", "nonce", "ciphertext", "updated_at"])


if __name__ == "__main__":
    unittest.main()
