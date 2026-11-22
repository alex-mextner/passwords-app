# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from tests.browser.e2e_support import _install_temporary_firefox_extension

if TYPE_CHECKING:
    from pathlib import Path


def test_modern_installation_is_temporary(tmp_path: Path) -> None:
    modern = Mock()
    legacy = Mock(side_effect=AssertionError("deprecated installation must not run"))
    driver = SimpleNamespace(install_web_extension=modern, install_addon=legacy)
    extension_dir = tmp_path / "firefox"

    _install_temporary_firefox_extension(driver, extension_dir)

    modern.assert_called_once_with(str(extension_dir), permanent=False)
    legacy.assert_not_called()


def test_older_supported_selenium_keeps_temporary_addon(tmp_path: Path) -> None:
    legacy = Mock()
    driver = SimpleNamespace(install_addon=legacy)
    extension_dir = tmp_path / "firefox"

    _install_temporary_firefox_extension(driver, extension_dir)

    legacy.assert_called_once_with(str(extension_dir), temporary=True)


def test_modern_installation_failure_does_not_retry_legacy(tmp_path: Path) -> None:
    modern = Mock(side_effect=RuntimeError("temporary extension rejected"))
    legacy = Mock()
    driver = SimpleNamespace(install_web_extension=modern, install_addon=legacy)
    extension_dir = tmp_path / "firefox"

    with pytest.raises(RuntimeError, match="temporary extension rejected"):
        _install_temporary_firefox_extension(driver, extension_dir)

    modern.assert_called_once_with(str(extension_dir), permanent=False)
    legacy.assert_not_called()
