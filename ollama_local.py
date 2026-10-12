"""Safe helpers for local Ollama lifecycle and model inventory."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.error
import urllib.request

OLLAMA_URL = "http://127.0.0.1:11434"
MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")


class OllamaError(RuntimeError):
    pass


def ollama_installed() -> bool:
    return shutil.which("ollama") is not None


def available_models() -> list[str]:
    """Fetch installed model names from the fixed, local-only API address."""
    try:
        with urllib.request.urlopen(OLLAMA_URL + "/api/tags", timeout=2) as response:
            payload = json.load(response)
        if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
            raise OllamaError("Invalid response from local Ollama.")
        return sorted(
            item["name"] for item in payload["models"]
            if isinstance(item, dict) and isinstance(item.get("name"), str)
            and MODEL_NAME.fullmatch(item["name"])
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise OllamaError("Ollama is not running on localhost:11434.") from exc
    except (ValueError, TypeError) as exc:
        raise OllamaError("Invalid Ollama model list.") from exc


def start_server() -> None:
    if not ollama_installed():
        raise OllamaError("Install Ollama from https://ollama.com/download first.")
    try:
        available_models()
        return
    except OllamaError:
        pass
    try:
        subprocess.Popen(["ollama", "serve"], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
    except OSError as exc:
        raise OllamaError("Could not start local Ollama.") from exc


def pull_model(model: str) -> None:
    if not MODEL_NAME.fullmatch(model):
        raise OllamaError("Invalid Ollama model name.")
    if not ollama_installed():
        raise OllamaError("Install Ollama from https://ollama.com/download first.")
    try:
        result = subprocess.run(["ollama", "pull", model], stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=3600, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OllamaError("Model download failed or timed out.") from exc
    if result.returncode:
        raise OllamaError("Ollama download failed. Check network access and free disk space.")
