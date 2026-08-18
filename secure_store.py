from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import keyring
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from platformdirs import user_data_dir

APP_NAME = "DaybreakSecurityScanner"
APP_AUTHOR = "Local"
KEYRING_SERVICE = "DaybreakSecurityScanner.AESGCM.v1"
KEYRING_ACCOUNT = "master-key"
AAD = b"DaybreakSecurityScanner|openai-api-key|v1"

_DATA_DIR = Path(user_data_dir(APP_NAME, APP_AUTHOR))
_SECRET_FILE = _DATA_DIR / "openai_key.aesgcm.json"


class SecureStoreError(RuntimeError):
    pass


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Windows ACLs are handled by the user profile + credential vault.
        pass


def _get_or_create_master_key() -> bytes:
    try:
        encoded = keyring.get_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
    except Exception as exc:
        raise SecureStoreError(
            "OS credential vault is unavailable; refusing insecure fallback."
        ) from exc

    if encoded:
        try:
            key = base64.urlsafe_b64decode(encoded.encode("ascii"))
        except Exception as exc:
            raise SecureStoreError("Stored master key is corrupted.") from exc
        if len(key) != 32:
            raise SecureStoreError("Stored master key has an invalid length.")
        return key

    key = AESGCM.generate_key(bit_length=256)
    try:
        keyring.set_password(
            KEYRING_SERVICE,
            KEYRING_ACCOUNT,
            base64.urlsafe_b64encode(key).decode("ascii"),
        )
    except Exception as exc:
        raise SecureStoreError(
            "Could not save master key to the OS credential vault."
        ) from exc
    return key


def encrypt_secret(plaintext: bytes, *, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt an application secret with the OS-vault-backed master key."""
    if not plaintext or not aad:
        raise SecureStoreError("Secret plaintext and authenticated context are required.")
    nonce = os.urandom(12)
    return nonce, AESGCM(_get_or_create_master_key()).encrypt(nonce, plaintext, aad)


def decrypt_secret(nonce: bytes, ciphertext: bytes, *, aad: bytes) -> bytes:
    """Decrypt an application secret, rejecting tampering or context substitution."""
    if len(nonce) != 12 or not ciphertext or not aad:
        raise SecureStoreError("Encrypted secret has an invalid format.")
    try:
        return AESGCM(_get_or_create_master_key()).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise SecureStoreError("Secret decryption or authentication failed.") from exc


def save_api_key(api_key: str) -> None:
    api_key = api_key.strip()
    if not api_key:
        raise SecureStoreError("API key is empty.")
    if len(api_key) > 4096 or "\x00" in api_key:
        raise SecureStoreError("API key has an invalid format.")

    master = _get_or_create_master_key()
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM.
    ciphertext = AESGCM(master).encrypt(nonce, api_key.encode("utf-8"), AAD)

    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _SECRET_FILE.with_suffix(".tmp")
    payload = {
        "version": 1,
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
    }
    tmp.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    _chmod_private(tmp)
    os.replace(tmp, _SECRET_FILE)
    _chmod_private(_SECRET_FILE)


def load_api_key() -> str | None:
    if not _SECRET_FILE.exists():
        return None

    try:
        payload = json.loads(_SECRET_FILE.read_text(encoding="utf-8"))
        if payload.get("version") != 1:
            raise SecureStoreError("Unsupported encrypted-key format.")
        nonce = base64.urlsafe_b64decode(payload["nonce"])
        ciphertext = base64.urlsafe_b64decode(payload["ciphertext"])
    except SecureStoreError:
        raise
    except Exception as exc:
        raise SecureStoreError("Encrypted API-key file is corrupted.") from exc

    if len(nonce) != 12:
        raise SecureStoreError("Encrypted API-key nonce is invalid.")

    master = _get_or_create_master_key()
    try:
        plaintext = AESGCM(master).decrypt(nonce, ciphertext, AAD)
        value = plaintext.decode("utf-8")
    except Exception as exc:
        raise SecureStoreError(
            "API-key decryption failed. The ciphertext or vault key may have changed."
        ) from exc

    return value


def forget_api_key() -> None:
    try:
        if _SECRET_FILE.exists():
            _SECRET_FILE.unlink()
    finally:
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
        except keyring.errors.PasswordDeleteError:
            pass
        except Exception as exc:
            raise SecureStoreError(
                "Encrypted file was removed, but the OS-vault master key could not be deleted."
            ) from exc


def has_saved_key() -> bool:
    return _SECRET_FILE.exists()
