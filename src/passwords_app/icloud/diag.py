"""Diagnostic logging for the token flow. `login --debug` writes a redacted transcript to
~/.config/icp/debug-<ts>.log - secret values are replaced with their length, safe to share."""

import json
import logging
import time
from pathlib import Path

from . import paths

# Keys whose string values must never be written verbatim.
_SECRET_HINTS = (
    "token", "pet", "sk", "spd", "m1", "m2", "secret", "password", "pwd",
    "cookie", "auth", "prk", "et", "key", "salt", "challenge",
)


def redact(value, key: str = ""):
    if isinstance(value, (bytes, bytearray)):
        return f"<bytes:{len(value)}>"
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, key) for v in value]
    if isinstance(value, str):
        low = key.lower()
        if any(h in low for h in _SECRET_HINTS) and len(value) > 8:
            return f"<redacted:{len(value)}>"
        if len(value) > 80:
            return f"<str:{len(value)}>"
        return value
    return value


def start() -> Path:
    """Attach a DEBUG file handler; return the log path."""
    path = paths.config_dir() / f"debug-{int(time.time())}.log"
    handler = logging.FileHandler(path)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger = logging.getLogger("icp")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    path.chmod(0o600)
    return path


def dump(logger: logging.Logger, label: str, obj) -> None:
    logger.debug("%s (redacted):\n%s", label, json.dumps(redact(obj), indent=2, default=str))


def dump_token_dict(logger: logging.Logger, spd: dict) -> None:
    """Log the available app tokens by name + expiry - the most useful single artifact."""
    t = spd.get("t") or {}
    logger.debug("spd contains %d app token(s):", len(t))
    for name, entry in t.items():
        if isinstance(entry, dict):
            logger.debug("  token %r -> fields=%s expiry=%s",
                         name, list(entry.keys()), entry.get("expiry"))
        else:
            logger.debug("  token %r -> %s", name, type(entry).__name__)
    logger.debug("spd top-level keys: %s", list(spd.keys()))
    logger.debug("ids present: adsid=%s DsPrsId=%s GsIdmsToken=%s",
                 bool(spd.get("adsid")), bool(spd.get("DsPrsId")), bool(spd.get("GsIdmsToken")))
