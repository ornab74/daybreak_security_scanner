import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from provider_store import PROVIDER_PRESETS, ProviderProfile, ProviderStore, validate_endpoint, validate_profile


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

    def test_local_ollama_endpoint_is_explicit_and_loopback_only(self):
        self.assertEqual(
            validate_endpoint("http://127.0.0.1:11434/v1", resolve_dns=False, allow_local=True),
            "http://127.0.0.1:11434/v1",
        )
        self.assertEqual(
            validate_endpoint("http://localhost:11434/v1/", resolve_dns=False, allow_local=True),
            "http://localhost:11434/v1",
        )
        for endpoint in ("http://192.168.1.5:11434/v1", "http://example.com:11434/v1",
                         "http://127.0.0.1:1234/v1", "http://127.0.0.1:11434/api",
                         "http://127.0.0.1:11434/v1?secret=x"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                validate_endpoint(endpoint, resolve_dns=False, allow_local=True)

    def test_local_ollama_profile_without_key(self):
        profile = ProviderProfile("Local", "Ollama (local)", "http://127.0.0.1:11434/v1",
                                  "qwen2.5-coder:7b", "", "chat_completions")
        self.assertEqual(validate_profile(profile, resolve_dns=False), profile)
        with self.assertRaises(ValueError):
            validate_profile(ProviderProfile("Remote", "Custom OpenAI-compatible",
                             "http://127.0.0.1:11434/v1", "model", "", "chat_completions"),
                             resolve_dns=False)

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
