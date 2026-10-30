# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""scripts/install.sh and scripts/uninstall.sh against a temp HOME (shell stand-ins log calls)."""

from __future__ import annotations

import gettext
import os
import re
import shutil
import socket
import stat
import subprocess
from typing import TYPE_CHECKING

import pytest
from tests.integration.cli.install_env import REPO, InstallEnv, make_env

from passwords_app.icloud.const import DEFAULT_ANISETTE_URL

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

pytestmark = [pytest.mark.integration, pytest.mark.timeout(120)]

UNIT = "passwords-appd.service"
DBUS_SERVICE = "io.github.alex_mextner.Passwords.service"


@pytest.fixture
def env(tmp_path: Path) -> InstallEnv:
    return make_env(tmp_path)


def installed(env: InstallEnv) -> InstallEnv:
    result = env.run("install.sh")
    assert result.returncode == 0, result.stderr
    return env


def unit_file(env: InstallEnv) -> Path:
    return env.config / "systemd" / "user" / UNIT


# ---------------------------------------------------------------- fresh install


def test_creates_a_system_site_packages_venv_and_installs_the_checkout(env: InstallEnv) -> None:
    installed(env)
    venv, pip = env.calls("uv")
    assert venv == f"venv -q --python /usr/bin/python3 --system-site-packages {env.app_data}/venv"
    assert pip.startswith(f"pip install -q --python {env.venv_bin}/python")
    assert pip.endswith(str(env.checkout))


def test_unit_points_at_the_venv_and_has_no_placeholders(env: InstallEnv) -> None:
    installed(env)
    text = unit_file(env).read_text()
    assert f"ExecStart={env.venv_bin}/passwords-appd" in text
    assert f"ReadWritePaths=-{env.app_data} -{env.app_config}" in text
    assert re.search(r"@[A-Z]+@", text) is None


def test_unit_hardening(env: InstallEnv) -> None:
    installed(env)
    lines = set(unit_file(env).read_text().splitlines())
    for setting in (
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
        "ProtectSystem=strict",
        "MemoryDenyWriteExecute=yes",
        "Type=dbus",
        "BusName=io.github.alex_mextner.Passwords",
        "UMask=0077",
    ):
        assert setting in lines


def test_dbus_activation_file(env: InstallEnv) -> None:
    installed(env)
    text = (env.data / "dbus-1" / "services" / DBUS_SERVICE).read_text()
    assert "Name=io.github.alex_mextner.Passwords" in text
    assert f"Exec={env.venv_bin}/passwords-appd" in text
    assert f"SystemdService={UNIT}" in text
    xml = env.data / "dbus-1" / "interfaces" / "io.github.alex_mextner.Passwords1.xml"
    assert xml.read_bytes() == (REPO / "data" / "dbus" / xml.name).read_bytes()


def test_cli_on_path_and_uninstaller_kept(env: InstallEnv) -> None:
    installed(env)
    link = env.home / ".local" / "bin" / "passwords-app"
    assert link.readlink() == env.venv_bin / "passwords-app"
    assert os.access(env.app_data / "uninstall.sh", os.X_OK)
    assert (env.app_data / "source-dir").read_text().strip() == str(env.checkout)


def test_app_directories_are_private(env: InstallEnv) -> None:
    installed(env)
    for path in (env.app_data, env.app_config):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_service_is_enabled_and_restarted(env: InstallEnv) -> None:
    installed(env)
    assert env.calls("systemctl") == [
        "--user daemon-reload",
        f"--user enable {UNIT}",
        f"--user restart {UNIT}",
    ]


def test_anisette_image_is_built_from_the_checkout_and_run_on_loopback_with_a_named_volume(
    env: InstallEnv,
) -> None:
    installed(env)
    docker = env.calls("docker")
    assert docker[0] == "container inspect passwords-app-anisette-windows"
    assert docker[1].startswith("image inspect --format ")
    build = docker[2]
    assert build.startswith("build --label io.github.alex_mextner.passwords.anisette-source=")
    assert build.endswith(f"-t passwords-app-anisette-windows:local {env.checkout}/docker/anisette")
    run = next(c for c in docker if c.startswith("run "))
    assert run.startswith("run -d --name passwords-app-anisette-windows --restart unless-stopped")
    assert f"-p 127.0.0.1:{env.anisette_port}:6969" in run
    assert "-v passwords-app-anisette-windows:/state" in run
    assert "--cap-drop ALL" in run
    assert run.endswith("passwords-app-anisette-windows:local")


def test_the_installers_default_port_is_the_clients_default_anisette_port() -> None:
    script = (REPO / "scripts" / "install.sh").read_text()
    port = re.search(r"^ANISETTE_PORT=\$\{ANISETTE_PORT:-(\d+)\}", script, re.MULTILINE)
    assert port is not None
    assert f"http://localhost:{port.group(1)}" == DEFAULT_ANISETTE_URL


def test_a_failed_image_build_is_a_warning_and_creates_no_container(env: InstallEnv) -> None:
    (env.fakebin / "docker").write_text("#!/bin/bash\nexit 1\n")
    result = env.run("install.sh")
    assert result.returncode == 0
    assert "could not build passwords-app-anisette-windows:local" in result.stderr
    assert "docker-container" not in (env.app_data / "installed-files").read_text()


def test_the_android_container_on_6969_is_never_reused_or_touched(env: InstallEnv) -> None:
    (env.docker_state / "passwords-app-anisette").touch()
    installed(env)
    docker = env.calls("docker")
    assert not any(
        "passwords-app-anisette " in c or c.endswith("passwords-app-anisette") for c in docker
    )


def test_manifest_lists_every_installed_path(env: InstallEnv) -> None:
    installed(env)
    lines = (env.app_data / "installed-files").read_text().splitlines()
    assert str(unit_file(env)) in lines
    assert str(env.data / "dbus-1" / "services" / DBUS_SERVICE) in lines
    assert str(env.home / ".local" / "bin" / "passwords-app") in lines
    assert "docker-container:passwords-app-anisette-windows" in lines
    assert len(lines) == len(set(lines))
    # Polkit actions are recorded but installed by the user through the printed pkexec command.
    files = [p for p in lines if not p.startswith(("docker-container:", "polkit-action:"))]
    assert all(os.path.lexists(p) for p in files)


def test_success_message_points_to_signin(env: InstallEnv) -> None:
    assert "passwords-app signin" in env.run("install.sh").stdout


def test_warns_when_local_bin_is_not_on_path(env: InstallEnv) -> None:
    assert ".local/bin to PATH" in env.run("install.sh").stdout


# ---------------------------------------------------------------- idempotence


def test_second_run_converges_to_the_same_layout(env: InstallEnv) -> None:
    installed(env)
    first = env.tree()
    env.clear_calls()
    installed(env)
    assert env.tree() == first
    assert [c for c in env.calls("uv") if c.startswith("venv")] == []  # venv reused
    docker = env.calls("docker")
    assert "start passwords-app-anisette-windows" in docker
    assert not any(c.startswith(("run", "build")) for c in docker)


def test_update_removes_files_the_new_version_no_longer_ships(env: InstallEnv) -> None:
    desktop = env.checkout / "data" / "applications" / "old.desktop"
    desktop.parent.mkdir(parents=True, exist_ok=True)
    desktop.write_text("[Desktop Entry]\nExec=@BINDIR@/passwords-app\n")
    installed(env)
    target = env.data / "applications" / "old.desktop"
    assert target.exists()
    desktop.unlink()
    installed(env)
    assert not target.exists()


def test_user_data_survives_reinstall(env: InstallEnv) -> None:
    installed(env)
    (env.app_data / "state.db").write_bytes(b"state")
    (env.app_config / "session.enc").write_bytes(b"session")
    installed(env)
    assert (env.app_data / "state.db").read_bytes() == b"state"
    assert (env.app_config / "session.enc").read_bytes() == b"session"


# ---------------------------------------------------------------- optional components


PROVIDER_SERVICE = "io.github.alex_mextner.Passwords.App.service"
POLICY = "io.github.alex_mextner.Passwords.policy"


@pytest.fixture
def with_app_files(env: InstallEnv) -> InstallEnv:
    """The GTK app's data files, laid out as the app branch ships them."""
    data = env.checkout / "data"
    files = {
        "applications/io.github.alex_mextner.Passwords.desktop": "Exec=@BINDIR@/passwords-app\n",
        "metainfo/io.github.alex_mextner.Passwords.metainfo.xml": "<component/>\n",
        "icons/hicolor/scalable/apps/io.github.alex_mextner.Passwords.svg": "<svg/>\n",
        "search-providers/io.github.alex_mextner.Passwords.search-provider.ini": "[x]\n",
        f"search-providers/{PROVIDER_SERVICE}": (
            "[D-BUS Service]\nName=io.github.alex_mextner.Passwords.App\n"
            "Exec=@BINDIR@/passwords-app --search-provider\n"
        ),
        "glib-2.0/schemas/io.github.alex_mextner.Passwords.gschema.xml": "<schemalist/>\n",
        f"polkit/{POLICY}": "<policyconfig/>\n",
        "native-messaging/firefox.json.in": '{"path": "@HOST_PATH@"}\n',
        "native-messaging/chrome.json.in": '{"path": "@HOST_PATH@"}\n',
    }
    for rel, content in files.items():
        (data / rel).parent.mkdir(parents=True, exist_ok=True)
        (data / rel).write_text(content)
    png = data / "icons" / "hicolor" / "256x256" / "apps" / "io.github.alex_mextner.Passwords.png"
    png.parent.mkdir(parents=True)
    png.write_bytes(b"\x89PNG\r\n\x1a\n@BINDIR@\x00\xff")
    po = env.checkout / "po"
    po.mkdir()
    (po / "ru.po").write_text(RU_PO)
    (po / "passwords-app.pot").write_text("# template, not a translation\n")
    return env


RU_PO = """\
msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\\n"

msgid "Passwords"
msgstr "Пароли"
"""


def catalog(env: InstallEnv, lang: str) -> Path:
    return env.app_data / "venv" / "share" / "locale" / lang / "LC_MESSAGES" / "passwords-app.mo"


def test_app_files_are_installed_with_paths_filled_in(with_app_files: InstallEnv) -> None:
    env = installed(with_app_files)
    desktop = env.data / "applications" / "io.github.alex_mextner.Passwords.desktop"
    assert desktop.read_text() == f"Exec={env.venv_bin}/passwords-app\n"
    assert (env.data / "metainfo" / "io.github.alex_mextner.Passwords.metainfo.xml").exists()
    provider = "io.github.alex_mextner.Passwords.search-provider.ini"
    assert (env.data / "gnome-shell" / "search-providers" / provider).exists()
    assert ("glib-compile-schemas", str(env.data / "glib-2.0" / "schemas")) in [
        ("glib-compile-schemas", c) for c in env.calls("glib-compile-schemas")
    ]


def test_search_provider_is_d_bus_activatable(with_app_files: InstallEnv) -> None:
    env = installed(with_app_files)
    service = (env.data / "dbus-1" / "services" / PROVIDER_SERVICE).read_text()
    assert f"Exec={env.venv_bin}/passwords-app --search-provider\n" in service
    assert not (env.data / "gnome-shell" / "search-providers" / PROVIDER_SERVICE).exists()


def test_translations_compile_into_the_app_s_prefix(with_app_files: InstallEnv) -> None:
    env = installed(with_app_files)
    assert catalog(env, "ru").read_text() == "catalog from ru.po\n"
    assert stat.S_IMODE(catalog(env, "ru").stat().st_mode) == 0o644
    (call,) = env.calls("msgfmt")
    assert call.startswith("--check -o ")
    assert call.endswith(f"-- {env.checkout}/po/ru.po")
    assert str(catalog(env, "ru")) in (env.app_data / "installed-files").read_text()


@pytest.mark.skipif(shutil.which("msgfmt") is None, reason="msgfmt (gettext) not installed")
def test_real_msgfmt_builds_a_catalog_gettext_loads(with_app_files: InstallEnv) -> None:
    env = with_app_files
    env.overrides["MSGFMT"] = str(shutil.which("msgfmt"))
    installed(env)
    localedir = catalog(env, "ru").parents[2]
    ru = gettext.translation("passwords-app", localedir=str(localedir), languages=["ru"])
    assert ru.gettext("Passwords") == "Пароли"


def test_a_translation_that_does_not_compile_is_left_out(with_app_files: InstallEnv) -> None:
    env = with_app_files
    (env.checkout / "po" / "de.po").write_text("BROKEN\n")
    result = env.run("install.sh")
    assert result.returncode == 0, result.stderr
    assert "de translation does not compile" in result.stderr
    assert not catalog(env, "de").exists()
    assert list(catalog(env, "de").parent.iterdir()) == []  # no temp file left behind
    assert catalog(env, "ru").exists()


def test_missing_msgfmt_is_a_warning(with_app_files: InstallEnv) -> None:
    env = with_app_files
    env.overrides["MSGFMT"] = "/nonexistent/msgfmt"
    result = env.run("install.sh")
    assert result.returncode == 0, result.stderr
    assert "gettext" in result.stderr
    assert not catalog(env, "ru").exists()


def test_polkit_action_is_explained_not_installed(with_app_files: InstallEnv) -> None:
    env = with_app_files
    result = env.run("install.sh")
    assert result.returncode == 0, result.stderr
    source = env.checkout / "data" / "polkit" / POLICY
    assert f"  pkexec install -m 0644 {source} {env.polkit_actions / POLICY}\n" in result.stdout
    assert env.calls("pkexec") == []
    assert list(env.polkit_actions.iterdir()) == []


def test_installed_polkit_action_is_not_asked_for_again(with_app_files: InstallEnv) -> None:
    env = with_app_files
    shutil.copy(env.checkout / "data" / "polkit" / POLICY, env.polkit_actions / POLICY)
    assert "pkexec" not in env.run("install.sh").stdout


def test_outdated_polkit_action_is_asked_for_again(with_app_files: InstallEnv) -> None:
    env = with_app_files
    (env.polkit_actions / POLICY).write_text("<policyconfig><!-- old --></policyconfig>\n")
    assert "pkexec install" in env.run("install.sh").stdout


def test_desktop_and_icon_caches_are_refreshed(with_app_files: InstallEnv) -> None:
    env = installed(with_app_files)
    assert env.calls("update-desktop-database") == [f"-q {env.data / 'applications'}"]
    assert env.calls("gtk-update-icon-cache") == [f"-q -t -f {env.data / 'icons' / 'hicolor'}"]


def test_second_run_with_app_files_converges(with_app_files: InstallEnv) -> None:
    env = installed(with_app_files)
    first = env.tree()
    installed(env)
    assert env.tree() == first


def test_update_that_drops_the_polkit_action_says_how_to_remove_it(
    with_app_files: InstallEnv,
) -> None:
    env = installed(with_app_files)
    policy = env.checkout / "data" / "polkit" / POLICY
    shutil.copy(policy, env.polkit_actions / POLICY)  # the user ran the printed command
    policy.unlink()
    result = env.run("install.sh")
    assert result.returncode == 0, result.stderr
    assert f"pkexec rm -f {env.polkit_actions / POLICY}" in result.stdout
    assert (env.polkit_actions / POLICY).exists()


def test_binary_icons_are_copied_byte_for_byte(with_app_files: InstallEnv) -> None:
    env = installed(with_app_files)
    rel = "icons/hicolor/256x256/apps/io.github.alex_mextner.Passwords.png"
    assert (env.data / rel).read_bytes() == (env.checkout / "data" / rel).read_bytes()


def test_firefox_manifest_is_always_installed(with_app_files: InstallEnv) -> None:
    env = installed(with_app_files)
    manifest = (
        env.home / ".mozilla" / "native-messaging-hosts" / "io.github.alex_mextner.passwords.json"
    )
    assert str(env.venv_bin / "passwords-app-native-host") in manifest.read_text()


def test_chrome_manifests_only_for_installed_browsers(with_app_files: InstallEnv) -> None:
    env = with_app_files
    (env.config / "google-chrome").mkdir(parents=True)
    installed(env)
    name = "io.github.alex_mextner.passwords.json"
    assert (env.config / "google-chrome" / "NativeMessagingHosts" / name).exists()
    assert not (env.config / "chromium").exists()


def test_without_app_files_nothing_is_created_for_them(env: InstallEnv) -> None:
    result = env.run("install.sh")
    assert result.returncode == 0, result.stderr
    for absent in ("applications", "metainfo", "gnome-shell", "glib-2.0", "icons"):
        assert not (env.data / absent).exists()
    assert not (env.app_data / "venv" / "share" / "locale").exists()
    assert not (env.home / ".mozilla").exists()
    for tool in (
        "glib-compile-schemas",
        "msgfmt",
        "update-desktop-database",
        "gtk-update-icon-cache",
    ):
        assert env.calls(tool) == []
    assert "pkexec" not in result.stdout


# ---------------------------------------------------------------- environments


@pytest.fixture
def anisette_listening(env: InstallEnv) -> Iterator[None]:
    with socket.socket() as server:
        server.bind(("127.0.0.1", env.anisette_port))
        server.listen()
        yield


@pytest.mark.usefixtures("anisette_listening")
def test_running_anisette_is_left_alone(env: InstallEnv) -> None:
    result = env.run("install.sh")
    assert result.returncode == 0
    assert "already answers" in result.stdout
    assert env.calls("docker") == ["container inspect passwords-app-anisette-windows"]
    assert "docker-container" not in (env.app_data / "installed-files").read_text()


def test_missing_docker_is_a_warning(env: InstallEnv) -> None:
    env.overrides["DOCKER"] = "/nonexistent/docker"
    result = env.run("install.sh")
    assert result.returncode == 0
    assert "docker is not installed" in result.stderr


def test_anisette_can_be_skipped(env: InstallEnv) -> None:
    env.overrides["PASSWORDS_APP_SKIP_ANISETTE"] = "1"
    assert env.run("install.sh").returncode == 0
    assert env.calls("docker") == []


def test_no_user_manager_is_a_warning(env: InstallEnv) -> None:
    env.overrides["FAKE_SYSTEMCTL_RC"] = "1"
    result = env.run("install.sh")
    assert result.returncode == 0
    assert "D-Bus activation" in result.stderr
    assert unit_file(env).exists()


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"UV": "/nonexistent/uv"}, "uv not found"),
        ({"PYTHON": "/nonexistent/python3"}, "not found"),
    ],
)
def test_missing_prerequisites_fail_clearly(
    env: InstallEnv, override: dict[str, str], message: str
) -> None:
    env.overrides.update(override)
    result = env.run("install.sh")
    assert result.returncode == 1
    assert message in result.stderr
    assert not (env.app_data / "venv").exists()


# ---------------------------------------------------------------- uninstall


def test_uninstall_removes_the_installation_but_keeps_data(env: InstallEnv) -> None:
    installed(env)
    (env.app_data / "state.db").write_bytes(b"state")
    (env.app_config / "session.enc").write_bytes(b"session")
    env.clear_calls()
    result = env.run("uninstall.sh")
    assert result.returncode == 0, result.stderr
    assert not unit_file(env).exists()
    assert not (env.data / "dbus-1" / "services" / DBUS_SERVICE).exists()
    assert not os.path.lexists(env.home / ".local" / "bin" / "passwords-app")
    assert not (env.app_data / "venv").exists()
    assert not (env.app_data / "installed-files").exists()
    assert (env.app_data / "state.db").read_bytes() == b"state"
    assert (env.app_config / "session.enc").read_bytes() == b"session"
    assert "Kept your data" in result.stdout
    assert f"--user disable --now {UNIT}" in env.calls("systemctl")
    assert env.calls("docker") == ["rm -f passwords-app-anisette-windows"]


def test_uninstall_purge_removes_data_too(env: InstallEnv) -> None:
    installed(env)
    (env.app_data / "state.db").write_bytes(b"state")
    (env.app_config / "session.enc").write_bytes(b"session")
    env.clear_calls()
    result = env.run("uninstall.sh", "--purge")
    assert result.returncode == 0
    assert not env.app_data.exists()
    assert not env.app_config.exists()
    docker = env.calls("docker")
    assert "volume rm passwords-app-anisette-windows" in docker
    assert "image rm passwords-app-anisette-windows:local" in docker
    assert "keyring" in result.stdout


def test_install_then_uninstall_leaves_home_as_it_was(with_app_files: InstallEnv) -> None:
    env = with_app_files
    (env.config / "google-chrome").mkdir(parents=True)
    before = env.tree()
    installed(env)
    assert env.run("uninstall.sh", "--purge").returncode == 0
    assert env.tree() == before


def test_uninstall_says_how_to_remove_an_installed_polkit_action(
    with_app_files: InstallEnv,
) -> None:
    env = installed(with_app_files)
    shutil.copy(env.checkout / "data" / "polkit" / POLICY, env.polkit_actions / POLICY)
    result = env.run("uninstall.sh")
    assert result.returncode == 0, result.stderr
    assert f"pkexec rm -f {env.polkit_actions / POLICY}" in result.stdout
    assert (env.polkit_actions / POLICY).exists()  # root's file: never removed by us
    assert env.calls("pkexec") == []


def test_uninstall_refreshes_desktop_and_icon_caches(with_app_files: InstallEnv) -> None:
    env = installed(with_app_files)
    env.clear_calls()
    assert env.run("uninstall.sh").returncode == 0
    assert env.calls("update-desktop-database") == [f"-q {env.data / 'applications'}"]
    assert env.calls("gtk-update-icon-cache") == [f"-q -t -f {env.data / 'icons' / 'hicolor'}"]


def test_uninstall_without_installation_is_harmless(env: InstallEnv) -> None:
    result = env.run("uninstall.sh")
    assert result.returncode == 0
    assert env.tree() == {}


def test_uninstall_rejects_unknown_options(env: InstallEnv) -> None:
    result = env.run("uninstall.sh", "--everything")
    assert result.returncode == 2
    assert "usage" in result.stderr


def test_uninstall_help(env: InstallEnv) -> None:
    result = env.run("uninstall.sh", "--help")
    assert result.returncode == 0
    assert "--purge" in result.stdout


def test_installed_uninstaller_works_without_the_checkout(env: InstallEnv) -> None:
    installed(env)
    copy = env.root / "uninstall-copy.sh"
    shutil.copy(env.app_data / "uninstall.sh", copy)
    shutil.rmtree(env.checkout)
    result = env.run("uninstall.sh", script_path=env.app_data / "uninstall.sh")
    assert result.returncode == 0, result.stderr
    assert not unit_file(env).exists()


# ---------------------------------------------------------------- static checks


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_scripts_are_shellcheck_clean() -> None:
    scripts = [str(REPO / "scripts" / s) for s in ("install.sh", "uninstall.sh")]
    result = subprocess.run(  # noqa: S603
        ["shellcheck", "--severity=style", *scripts],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze missing")
def test_installed_unit_passes_systemd_analyze_verify(env: InstallEnv) -> None:
    installed(env)
    exe = env.venv_bin / "passwords-appd"
    assert os.access(exe, os.X_OK)
    result = subprocess.run(  # noqa: S603
        ["systemd-analyze", "--user", "verify", str(unit_file(env))],  # noqa: S607
        env={**env.env(), "XDG_RUNTIME_DIR": str(env.root)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    ours = [line for line in result.stderr.splitlines() if UNIT in line]
    assert ours == [], ours


def test_a_changed_checkout_rebuilds_the_image_and_recreates_the_container_keeping_the_volume(
    env: InstallEnv,
) -> None:
    installed(env)
    (env.checkout / "docker" / "anisette" / "server.py").write_text("# a newer helper\n")
    env.clear_calls()
    installed(env)
    docker = env.calls("docker")
    assert any(c.startswith("build --label ") for c in docker)
    assert "rm -f passwords-app-anisette-windows" in docker
    assert any(c.startswith("run -d --name passwords-app-anisette-windows") for c in docker)
    assert not any(c.startswith("volume rm") for c in docker)
    env.clear_calls()
    installed(env)
    docker = env.calls("docker")
    assert not any(c.startswith(("build", "run", "rm")) for c in docker)
    assert "start passwords-app-anisette-windows" in docker
