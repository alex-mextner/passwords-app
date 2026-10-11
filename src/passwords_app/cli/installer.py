# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`passwords-app install` / `uninstall`: run the shell installers.

The scripts are the single source of truth for the installed layout (they also work
without Python). They are found in the source checkout this package runs from, else via the
checkout path install.sh records, and uninstall.sh additionally from the copy install.sh
leaves in the data directory, so uninstalling works after the checkout is gone.
"""

from __future__ import annotations

import contextlib

# Only runs our own install scripts, with a fixed interpreter and no shell.
import subprocess  # nosec B404
from pathlib import Path
from typing import TYPE_CHECKING

from passwords_app.daemon.paths import data_dir

if TYPE_CHECKING:
    from collections.abc import Sequence

BASH = "/bin/bash"
SOURCE_RECORD = "source-dir"


class ScriptNotFoundError(FileNotFoundError):
    """No checkout (or installed copy) provides the requested script."""


def _checkout() -> Path:
    return Path(__file__).resolve().parents[3]


def candidates(name: str) -> list[Path]:
    found = [_checkout() / "scripts" / name]
    record = data_dir() / SOURCE_RECORD
    with contextlib.suppress(OSError):  # no record (never installed) or unreadable
        found.append(Path(record.read_text(encoding="utf-8").strip()) / "scripts" / name)
    if name == "uninstall.sh":
        found.append(data_dir() / name)
    return found


def find_script(name: str) -> Path:
    for path in candidates(name):
        if path.is_file():
            return path
    msg = (
        f"{name} not found. Run it from a passwords-app checkout: "
        f"git clone https://github.com/alex-mextner/passwords-app && "
        f"passwords-app/scripts/{name}"
    )
    raise ScriptNotFoundError(msg)


def run_script(name: str, args: Sequence[str]) -> int:
    script = find_script(name)
    return subprocess.run(  # noqa: S603  # nosec B603
        [BASH, str(script), *args], check=False
    ).returncode
