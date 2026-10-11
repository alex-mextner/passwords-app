# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Where the iCloud client keeps its state: `$XDG_CONFIG_HOME/passwords-app` by default.

Path lookups are pure; only `ensure()` touches the filesystem, so reading a session never
creates or re-permissions anything.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

APP_DIR = "passwords-app"


def default_config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP_DIR


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigPaths:
    root: Path

    @classmethod
    def default(cls) -> ConfigPaths:
        return cls(default_config_dir())

    def ensure(self) -> Path:
        """Create the directory private to the user (tokens and keys live here)."""
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        return self.root

    @property
    def device(self) -> Path:
        return self.root / "device.json"

    @property
    def session(self) -> Path:
        return self.root / "session.enc"

    @property
    def fallback_key(self) -> Path:
        return self.root / "master.key"

    @property
    def zone_cache(self) -> Path:
        return self.root / "icloud-zones.json"
