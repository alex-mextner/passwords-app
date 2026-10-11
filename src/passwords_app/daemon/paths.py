# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Where the daemon keeps its data; resolved on every call so tests can redirect HOME/XDG."""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    """`$XDG_DATA_HOME/passwords-app` (default `~/.local/share/passwords-app`)."""
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "passwords-app"


def state_path() -> Path:
    return data_dir() / "state.db"
