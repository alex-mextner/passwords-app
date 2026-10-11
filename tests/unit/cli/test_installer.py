# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Finding and running install.sh / uninstall.sh."""

from __future__ import annotations

from pathlib import Path

import pytest

from passwords_app.cli import installer


@pytest.fixture
def data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    return tmp_path / "data" / "passwords-app"


@pytest.fixture
def no_checkout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(installer, "_checkout", lambda: tmp_path / "not-a-checkout")


def script(path: Path, body: str = 'echo "ran $0 $*"') -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/bash\n{body}\n")
    return path


def test_this_checkout_provides_both_scripts(data: Path) -> None:
    repo = Path(__file__).resolve().parents[3]
    assert installer.find_script("install.sh") == repo / "scripts" / "install.sh"
    assert installer.find_script("uninstall.sh") == repo / "scripts" / "uninstall.sh"


@pytest.mark.usefixtures("no_checkout")
def test_recorded_source_dir_is_used(data: Path, tmp_path: Path) -> None:
    source = tmp_path / "src-checkout"
    script(source / "scripts" / "install.sh")
    data.mkdir(parents=True)
    (data / installer.SOURCE_RECORD).write_text(f"{source}\n")
    assert installer.find_script("install.sh") == source / "scripts" / "install.sh"


@pytest.mark.usefixtures("no_checkout")
def test_uninstall_works_from_the_installed_copy(data: Path) -> None:
    copy = script(data / "uninstall.sh")
    assert installer.find_script("uninstall.sh") == copy


@pytest.mark.usefixtures("no_checkout")
def test_install_has_no_installed_copy(data: Path) -> None:
    script(data / "install.sh")
    with pytest.raises(installer.ScriptNotFoundError, match="git clone"):
        installer.find_script("install.sh")


@pytest.mark.usefixtures("no_checkout")
def test_unreadable_record_is_ignored(data: Path) -> None:
    data.mkdir(parents=True)
    (data / installer.SOURCE_RECORD).mkdir()  # a directory, not a file
    with pytest.raises(installer.ScriptNotFoundError):
        installer.find_script("install.sh")


@pytest.mark.usefixtures("no_checkout")
def test_run_script_passes_arguments_and_exit_code(
    data: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    script(data / "uninstall.sh", 'echo "args: $*"; exit 3')
    assert installer.run_script("uninstall.sh", ["--purge"]) == 3
    assert "args: --purge" in capfd.readouterr().out
