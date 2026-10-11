# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from passwords_app.browser.manifests import (
    BROWSERS,
    CHROME_ORIGIN,
    DESCRIPTION,
    FIREFOX_EXTENSION_ID,
    HOST_NAME,
    HOST_PATH_PLACEHOLDER,
    Browser,
    dumps,
    install,
    manifest_dir,
    manifest_path,
    render,
    uninstall,
)

TEMPLATES = Path(__file__).resolve().parents[3] / "data" / "native-messaging"
HOST = Path("/home/alex/.local/bin/passwords-app-native-host")


def test_firefox_manifest() -> None:
    assert render("firefox", HOST) == {
        "name": HOST_NAME,
        "description": DESCRIPTION,
        "path": str(HOST),
        "type": "stdio",
        "allowed_extensions": ["passwords-app@alex-mextner.github.io"],
    }


@pytest.mark.parametrize("browser", ["chrome", "chromium"])
def test_chrome_manifests(browser: Browser) -> None:
    manifest = render(browser, HOST)
    assert manifest["allowed_origins"] == ["chrome-extension://djaiceficanbdafmmlcmgbfjefiapjaf/"]
    assert "allowed_extensions" not in manifest
    assert manifest["path"] == str(HOST)
    assert manifest["type"] == "stdio"


def test_identifiers() -> None:
    assert HOST_NAME == "io.github.alex_mextner.passwords"
    assert FIREFOX_EXTENSION_ID == "passwords-app@alex-mextner.github.io"
    # Chrome requires the trailing slash on an origin.
    assert CHROME_ORIGIN.endswith("/")


@pytest.mark.parametrize("browser", BROWSERS)
def test_host_name_is_valid_for_browsers(browser: Browser) -> None:
    # Both browsers allow only lowercase alphanumerics, `_` and `.` in a host name.
    name = render(browser, HOST)["name"]
    assert isinstance(name, str)
    assert all(c.islower() or c.isdigit() or c in "._" for c in name)


@pytest.mark.parametrize(
    ("browser", "template"),
    [("firefox", "firefox.json.in"), ("chrome", "chrome.json.in"), ("chromium", "chrome.json.in")],
)
def test_templates_equal_rendered_manifests(browser: Browser, template: str) -> None:
    text = (TEMPLATES / template).read_text(encoding="utf-8")
    assert text == dumps(render(browser, HOST_PATH_PLACEHOLDER))


@pytest.mark.parametrize("template", ["firefox.json.in", "chrome.json.in"])
def test_template_substitution_yields_installed_file(template: str) -> None:
    text = (TEMPLATES / template).read_text(encoding="utf-8")
    browser: Browser = "firefox" if template.startswith("firefox") else "chrome"
    assert json.loads(text.replace(HOST_PATH_PLACEHOLDER, str(HOST))) == render(browser, HOST)


@pytest.mark.parametrize(
    ("browser", "relative"),
    [
        ("firefox", ".mozilla/native-messaging-hosts"),
        ("chrome", ".config/google-chrome/NativeMessagingHosts"),
        ("chromium", ".config/chromium/NativeMessagingHosts"),
    ],
)
def test_manifest_dirs(browser: Browser, relative: str, tmp_path: Path) -> None:
    assert manifest_dir(browser, tmp_path) == tmp_path / relative
    assert manifest_path(browser, tmp_path) == tmp_path / relative / f"{HOST_NAME}.json"


def test_install_all_browsers(tmp_path: Path) -> None:
    written = install(tmp_path, HOST)
    assert written == [manifest_path(b, tmp_path) for b in BROWSERS]
    for browser, path in zip(BROWSERS, written, strict=True):
        assert json.loads(path.read_text(encoding="utf-8")) == render(browser, HOST)
        assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_install_selected_browsers_only(tmp_path: Path) -> None:
    assert install(tmp_path, HOST, ["firefox"]) == [manifest_path("firefox", tmp_path)]
    assert not manifest_dir("chrome", tmp_path).exists()
    assert not manifest_dir("chromium", tmp_path).exists()


def test_install_is_idempotent(tmp_path: Path) -> None:
    first = install(tmp_path, HOST)
    contents = [p.read_bytes() for p in first]
    second = install(tmp_path, HOST)
    assert second == first
    assert [p.read_bytes() for p in second] == contents
    # No temporary files are left next to the manifests.
    for path in second:
        assert sorted(p.name for p in path.parent.iterdir()) == [path.name]


def test_install_replaces_a_stale_manifest(tmp_path: Path) -> None:
    path = manifest_path("firefox", tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text('{"path": "/old/host"}', encoding="utf-8")
    path.chmod(0o600)
    install(tmp_path, HOST, ["firefox"])
    assert json.loads(path.read_text(encoding="utf-8"))["path"] == str(HOST)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_install_keeps_other_hosts(tmp_path: Path) -> None:
    other = manifest_dir("firefox", tmp_path) / "org.example.other.json"
    other.parent.mkdir(parents=True)
    other.write_text("{}", encoding="utf-8")
    install(tmp_path, HOST)
    uninstall(tmp_path)
    assert other.read_text(encoding="utf-8") == "{}"


def test_install_rejects_relative_host_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute"):
        install(tmp_path, Path("bin/passwords-app-native-host"))
    assert not (tmp_path / ".mozilla").exists()


def test_uninstall_removes_installed_manifests(tmp_path: Path) -> None:
    written = install(tmp_path, HOST)
    assert uninstall(tmp_path) == written
    assert not any(p.exists() for p in written)


def test_uninstall_is_idempotent(tmp_path: Path) -> None:
    install(tmp_path, HOST, ["chromium"])
    assert uninstall(tmp_path) == [manifest_path("chromium", tmp_path)]
    assert uninstall(tmp_path) == []


def test_uninstall_on_empty_home(tmp_path: Path) -> None:
    assert uninstall(tmp_path) == []
