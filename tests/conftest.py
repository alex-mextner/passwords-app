# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Suite-wide safety net: no test can reach the owner's real session.

Before any test module is imported, HOME, the XDG directories and the session bus address are
pointed into a throwaway directory, and the bus address names a socket that does not exist.
Code that falls back to "the default session bus", "~/.config/passwords-app" or the login
keyring therefore fails loudly instead of touching real data. Tests that need a bus get one
only from the private harnesses (``tests/harness/dbus_session.py``,
``tests/harness/gnome_shell.py``), which set their own addresses on top of this.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import MutableMapping

ISOLATED_DIRS = {
    "HOME": "home",
    "XDG_CONFIG_HOME": "config",
    "XDG_DATA_HOME": "data",
    "XDG_CACHE_HOME": "cache",
    "XDG_STATE_HOME": "state",
    "XDG_RUNTIME_DIR": "runtime",
}
# Variables that lead to the real desktop session or its agents; they are removed outright.
REMOVED_VARS = (
    "DBUS_STARTER_ADDRESS",
    "DBUS_STARTER_BUS_TYPE",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "GNOME_KEYRING_CONTROL",
    "AT_SPI_BUS_ADDRESS",
    "SESSION_MANAGER",
)
# Browser drivers keep their downloads under the real HOME; keep finding them there.
_REAL_HOME = Path(os.environ.get("HOME") or Path("~").expanduser())
_TOOL_CACHES = {
    "PLAYWRIGHT_BROWSERS_PATH": _REAL_HOME / ".cache" / "ms-playwright",
    "SE_CACHE_PATH": _REAL_HOME / ".cache" / "selenium",
}


def isolate(environ: MutableMapping[str, str], root: Path) -> None:
    """Point every per-user location in ``environ`` into ``root``; idempotent."""
    for name, value in _TOOL_CACHES.items():
        environ.setdefault(name, str(value))
    for var, sub in ISOLATED_DIRS.items():
        directory = root / sub
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        environ[var] = str(directory)
    environ["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={root / 'no-session-bus'}"
    for var in REMOVED_VARS:
        environ.pop(var, None)


# At import time, not in a fixture: test modules (and the code they import) may read these
# variables at import, before any fixture runs. Each xdist worker gets its own root.
ISOLATED_ROOT = Path(tempfile.mkdtemp(prefix="passwords-app-tests-"))
isolate(os.environ, ISOLATED_ROOT)


@pytest.fixture(scope="session", autouse=True)
def isolated_user_environment() -> Path:
    """Re-assert the isolation for the session (a plugin may have touched the environment)."""
    isolate(os.environ, ISOLATED_ROOT)
    return ISOLATED_ROOT


def pytest_unconfigure() -> None:
    # A hook, not fixture teardown: zero-test runs and the xdist controller never set up
    # the session fixture but still created a root at import.
    shutil.rmtree(ISOLATED_ROOT, ignore_errors=True)
