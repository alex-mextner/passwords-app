# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Persist a signed-in, joined session the way `passwords-app signin` leaves it.

Runs as a child of the test with the stack's environment, so the session's master key lands
in the throwaway keyring (Secret Service) and `session.enc` / `device.json` in the throwaway
`$XDG_CONFIG_HOME/passwords-app`, the files the daemon reads at start.
Usage: `python tests/e2e/seed_session.py <session.json>`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from passwords_app.icloud.auth.device import Device
from passwords_app.icloud.auth.session import SessionStore
from passwords_app.icloud.paths import ConfigPaths


def main(argv: list[str]) -> int:
    payload = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    paths = ConfigPaths.default()
    paths.ensure()
    Device(**payload["device"]).save(paths.device)
    store = SessionStore(paths)
    store.save(payload["session"])
    assert store.load() == payload["session"]
    # The key must live in the throwaway keyring, as on a desktop, not in the fallback file.
    assert not paths.fallback_key.exists()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
