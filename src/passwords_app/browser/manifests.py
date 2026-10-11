# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Native messaging host manifests: how Firefox and Chrome find `passwords-app-native-host`.

The `.json.in` templates under `data/native-messaging/` are what packagers install system wide;
`render` produces the same documents for a per-user install, and a test keeps the two equal.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Final, Literal

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

type Browser = Literal["firefox", "chrome", "chromium"]
BROWSERS: Final[tuple[Browser, ...]] = ("firefox", "chrome", "chromium")

HOST_NAME: Final = "io.github.alex_mextner.passwords"
DESCRIPTION: Final = "Passwords for Linux: iCloud Keychain autofill"
FIREFOX_EXTENSION_ID: Final = "passwords-app@alex-mextner.github.io"
CHROME_ORIGIN: Final = "chrome-extension://djaiceficanbdafmmlcmgbfjefiapjaf/"
HOST_PATH_PLACEHOLDER: Final = "@HOST_PATH@"
FILE_NAME: Final = f"{HOST_NAME}.json"

_DIRS: Final[dict[Browser, tuple[str, ...]]] = {
    "firefox": (".mozilla", "native-messaging-hosts"),
    "chrome": (".config", "google-chrome", "NativeMessagingHosts"),
    "chromium": (".config", "chromium", "NativeMessagingHosts"),
}
_FILE_MODE: Final = 0o644


def render(browser: Browser, host_path: Path | str) -> dict[str, object]:
    """Build the manifest for `browser`; browsers reject a relative `host_path`."""
    manifest: dict[str, object] = {
        "name": HOST_NAME,
        "description": DESCRIPTION,
        "path": str(host_path),
        "type": "stdio",
    }
    if browser == "firefox":
        manifest["allowed_extensions"] = [FIREFOX_EXTENSION_ID]
    else:
        manifest["allowed_origins"] = [CHROME_ORIGIN]
    return manifest


def dumps(manifest: dict[str, object]) -> str:
    """Canonical file contents: stable key order, so reinstalling rewrites identical bytes."""
    return json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"


def manifest_dir(browser: Browser, home: Path) -> Path:
    return home.joinpath(*_DIRS[browser])


def manifest_path(browser: Browser, home: Path) -> Path:
    return manifest_dir(browser, home) / FILE_NAME


def install(home: Path, host_path: Path, browsers: Iterable[Browser] = BROWSERS) -> list[Path]:
    """Write the manifests (0644) for `browsers` under `home`; returns the files written."""
    if not host_path.is_absolute():
        msg = f"the host path must be absolute: {host_path}"
        raise ValueError(msg)
    written: list[Path] = []
    for browser in browsers:
        path = manifest_path(browser, home)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Write-then-rename: a browser starting meanwhile never reads half a manifest.
        tmp = path.with_name(f".{FILE_NAME}.tmp")
        tmp.write_text(dumps(render(browser, host_path)), encoding="utf-8")
        tmp.chmod(_FILE_MODE)
        tmp.replace(path)
        written.append(path)
    return written


def uninstall(home: Path) -> list[Path]:
    """Remove every manifest this module may have installed; returns the files removed."""
    removed: list[Path] = []
    for browser in BROWSERS:
        path = manifest_path(browser, home)
        if path.is_file():
            path.unlink()
            removed.append(path)
    return removed
