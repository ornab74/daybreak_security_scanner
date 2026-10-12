from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from platformdirs import user_data_dir

from secure_store import SecureStoreError, decrypt_secret, encrypt_secret

APP_NAME = "DaybreakSecurityScanner"
APP_AUTHOR = "Local"
DEFAULT_DB = Path(user_data_dir(APP_NAME, APP_AUTHOR)) / "providers.sqlite3"
PROFILE_AAD_PREFIX = b"DaybreakSecurityScanner|provider-profile|v1|"
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")

PROVIDER_PRESETS = {
    "OpenAI": ("https://api.openai.com/v1", "gpt-5.6-terra", "responses"),
    "Ollama (local)": ("http://127.0.0.1:11434/v1", "qwen2.5-coder:7b", "chat_completions"),
    "DigitalOcean Gradient · Kimi K2.5": (
        "https://inference.do-ai.run/v1", "kimi-k2.5", "chat_completions"
    ),
    # Meta has announced Muse Spark 1.1, but endpoint/model identifiers are supplied
    # by its console during public preview. Never guess credentials-routing values.
    "Meta Model API · Muse Spark 1.1": ("", "", "chat_completions"),
    "Custom OpenAI-compatible": ("", "", "chat_completions"),
}


@dataclass(frozen=True)
class ProviderProfile:
    label: str
    provider: str
    base_url: str
    model: str
    api_key: str
    protocol: str = "chat_completions"


def _is_public_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return not any((address.is_private, address.is_loopback, address.is_link_local,
                    address.is_multicast, address.is_reserved, address.is_unspecified))


def validate_endpoint(value: str, *, resolve_dns: bool = True, allow_local: bool = False) -> str:
    value = value.strip()
    if len(value) > 2048:
        raise ValueError("API endpoint is too long.")
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme != "https" and not (allow_local and scheme == "http"):
        raise ValueError("API endpoint must use HTTPS (except loopback-only local Ollama).")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("API endpoint must have a host and must not contain credentials.")
    if parsed.query or parsed.fragment:
        raise ValueError("API endpoint must not contain a query string or fragment.")
    host = parsed.hostname.rstrip(".").lower()
    if allow_local:
        # Never allow LAN, public, or DNS-based targets in this exception.
        if host not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Local Ollama endpoint must use localhost or a loopback IP.")
        if parsed.port != 11434:
            raise ValueError("Local Ollama endpoint must use port 11434.")
        if parsed.path.rstrip("/") != "/v1":
            raise ValueError("Local Ollama endpoint must end with /v1.")
        authority = "[::1]" if host == "::1" else host
        return urlunsplit((scheme, f"{authority}:11434", "/v1", "", ""))
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Local API endpoints are blocked to prevent SSRF.")
    try:
        if not _is_public_ip(host):
            raise ValueError("Private, local, and reserved API addresses are blocked.")
    except ValueError as exc:
        if "does not appear" not in str(exc):
            raise
    if resolve_dns:
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)}
        except socket.gaierror as exc:
            raise ValueError("API endpoint hostname could not be resolved.") from exc
        if not addresses or any(not _is_public_ip(address) for address in addresses):
            raise ValueError("API endpoint resolves to a non-public address; connection blocked.")
    netloc = host if parsed.port in (None, 443) else f"{host}:{parsed.port}"
    return urlunsplit(("https", netloc, parsed.path.rstrip("/"), "", ""))


def validate_profile(profile: ProviderProfile, *, resolve_dns: bool = True) -> ProviderProfile:
    label = profile.label.strip()
    provider = profile.provider.strip()
    model = profile.model.strip()
    key = profile.api_key.strip()
    if not label or len(label) > 100 or not provider or len(provider) > 100:
        raise ValueError("Profile label/provider is missing or too long.")
    if not MODEL_RE.fullmatch(model):
        raise ValueError("Model ID contains unsupported characters or is too long.")
    if profile.protocol not in {"responses", "chat_completions"}:
        raise ValueError("Unsupported API protocol.")
    if (not key and provider != "Ollama (local)") or len(key) > 4096 or "\x00" in key:
        raise ValueError("API key is empty or invalid.")
    if provider == "Ollama (local)" and profile.protocol != "chat_completions":
        raise ValueError("Local Ollama requires chat_completions.")
    endpoint = validate_endpoint(profile.base_url, resolve_dns=resolve_dns, allow_local=provider == "Ollama (local)")
    return ProviderProfile(label, provider, endpoint, model, key, profile.protocol)


class ProviderStore:
    def __init__(self, path: Path = DEFAULT_DB):
        self.path = Path(path)

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("CREATE TABLE IF NOT EXISTS profiles (id INTEGER PRIMARY KEY CHECK(id=1), nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return connection

    def save(self, profile: ProviderProfile, *, resolve_dns: bool = True) -> None:
        clean = validate_profile(profile, resolve_dns=resolve_dns)
        payload = json.dumps(asdict(clean), separators=(",", ":")).encode()
        nonce, ciphertext = encrypt_secret(payload, aad=PROFILE_AAD_PREFIX + b"1")
        with self._connect() as db:
            db.execute("INSERT INTO profiles(id,nonce,ciphertext) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET nonce=excluded.nonce,ciphertext=excluded.ciphertext,updated_at=CURRENT_TIMESTAMP", (nonce, ciphertext))

    def load(self, *, resolve_dns: bool = True) -> ProviderProfile | None:
        if not self.path.exists():
            return None
        with self._connect() as db:
            row = db.execute("SELECT nonce,ciphertext FROM profiles WHERE id=1").fetchone()
        if not row:
            return None
        try:
            data = json.loads(decrypt_secret(row[0], row[1], aad=PROFILE_AAD_PREFIX + b"1"))
            return validate_profile(ProviderProfile(**data), resolve_dns=resolve_dns)
        except (TypeError, KeyError, json.JSONDecodeError) as exc:
            raise SecureStoreError("Encrypted provider profile is corrupted.") from exc

    def forget(self) -> None:
        if not self.path.exists():
            return
        with self._connect() as db:
            db.execute("DELETE FROM profiles")

    def exists(self) -> bool:
        if not self.path.exists():
            return False
        with self._connect() as db:
            return db.execute("SELECT 1 FROM profiles WHERE id=1").fetchone() is not None
