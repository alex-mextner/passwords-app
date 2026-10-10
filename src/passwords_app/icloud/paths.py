"""Filesystem locations. Everything lives under $XDG_CONFIG_HOME/icp."""

import os
from pathlib import Path


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    d = Path(base) / "passwords-app"
    d.mkdir(parents=True, exist_ok=True)
    # Tokens and identity are sensitive; keep the directory private.
    os.chmod(d, 0o700)
    return d


def device_file() -> Path:
    return config_dir() / "device.json"


def session_file() -> Path:
    return config_dir() / "session.enc"


def fallback_key_file() -> Path:
    return config_dir() / "master.key"


def vault_file() -> Path:
    return config_dir() / "vault.enc"


def aliases_file() -> Path:
    return config_dir() / "aliases.enc"


def sync_lock_file() -> Path:
    return config_dir() / "sync.lock"


def sync_attempt_file() -> Path:
    return config_dir() / "sync.attempt"
