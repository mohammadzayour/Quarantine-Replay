"""Runtime configuration. Secrets are read from the environment only."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"

DEFAULT_LIVE_MODEL = "claude-opus-5-5"


def load_dotenv(path: Path = BASE_DIR / ".env") -> None:
    """Load KEY=VALUE lines from a local .env file without overriding real env vars."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and value:
            os.environ.setdefault(key, value)


def data_dir() -> Path:
    return Path(os.environ.get("QR_DATA_DIR") or BASE_DIR / "data")


def live_model() -> str:
    return os.environ.get("QR_LIVE_MODEL") or DEFAULT_LIVE_MODEL


def live_provider() -> str:
    """'ollama' (default, local, free) or 'anthropic' (explicit opt-in only)."""
    value = os.environ.get("QR_LIVE_PROVIDER", "ollama").strip().lower()
    return value if value in ("ollama", "anthropic") else "ollama"


def ollama_host() -> str:
    return (os.environ.get("QR_OLLAMA_HOST") or "http://127.0.0.1:11434").rstrip("/")


def ollama_model() -> str:
    return os.environ.get("QR_OLLAMA_MODEL") or "qwen3:4b"


def allowed_hosts() -> list[str]:
    extra = [h.strip() for h in os.environ.get("QR_ALLOWED_HOSTS", "").split(",") if h.strip()]
    return ["127.0.0.1", "localhost", "testserver", *extra]
