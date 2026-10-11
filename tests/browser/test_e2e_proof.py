# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Proof captures: the dark-mode screenshot set and a short WebM per browser.

The light screenshots come from test_e2e_{firefox,chromium}.py. Here the same scenarios run
with the browser in dark mode (prefixes `firefox-dark-`, `chromium-dark-`), and one session per
browser records fill -> OTP -> save prompt into `docs/proof/browser/<browser>-flow.webm`.
Every run also re-checks the scenarios' assertions, so these are real tests, not just pictures.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from tests.browser import e2e_scenarios as scenarios
from tests.browser.e2e_support import PROOF, ChromiumSession, FirefoxSession, FrameRecorder

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from tests.browser.conftest import Vault
    from tests.browser.e2e_support import Page, SiteServer

pytestmark = [pytest.mark.browser, pytest.mark.timeout(240)]

BROWSERS = ["firefox", "chromium"]

# The scenarios that take a screenshot.
DARK_SCENES: list[Callable[[Page, SiteServer, Vault], None]] = [
    scenarios.fill_first_candidate,
    scenarios.otp_fill,
    scenarios.save_new_login,
    scenarios.update_changed_password,
    scenarios.generator_then_save,
    scenarios.popup_search_and_fill,
    scenarios.no_fill_on_lookalike,
]


class Sessions:
    """Browsers opened by one test, closed together at its end."""

    def __init__(self, home: Path, bus: str, site: SiteServer) -> None:
        self._args = (home, bus, site)
        self._opened: list[FirefoxSession | ChromiumSession] = []

    def open(self, browser: str, *, dark: bool) -> Page:
        session: FirefoxSession | ChromiumSession
        if browser == "firefox":
            session = FirefoxSession(*self._args, dark=dark)
        else:
            session = ChromiumSession(*self._args, dark=dark)
        self._opened.append(session)
        return session

    def close(self) -> None:
        for session in self._opened:
            session.close()


@pytest.fixture
def sessions(
    tmp_path: Path, private_bus: str, site: SiteServer, vault: Vault
) -> Iterator[Sessions]:
    del vault  # seeded before the browser can ask
    opened = Sessions(tmp_path / "home", private_bus, site)
    try:
        yield opened
    finally:
        opened.close()


@pytest.mark.parametrize("scenario", DARK_SCENES, ids=lambda s: s.__name__)
@pytest.mark.parametrize("browser", BROWSERS)
def test_dark_scene(
    browser: str,
    scenario: Callable[[Page, SiteServer, Vault], None],
    sessions: Sessions,
    site: SiteServer,
    vault: Vault,
) -> None:
    page = sessions.open(browser, dark=True)
    assert page.js("return matchMedia('(prefers-color-scheme: dark)').matches") is True
    scenario(page, site, vault)


@pytest.mark.parametrize("browser", BROWSERS)
def test_flow_video(
    browser: str, sessions: Sessions, site: SiteServer, vault: Vault, tmp_path: Path
) -> None:
    recorder = FrameRecorder(sessions.open(browser, dark=False), tmp_path / "frames")
    for scenario in (scenarios.fill_first_candidate, scenarios.otp_fill, scenarios.save_new_login):
        vault.daemon.call(lambda d: d.calls.clear())  # each scenario checks its own calls
        scenario(recorder, site, vault)
        recorder.hold()
    out = PROOF / f"{browser}-flow.webm"
    recorder.encode(out)
    assert out.stat().st_size > 10_000
    assert out.read_bytes()[:4] == b"\x1a\x45\xdf\xa3"  # EBML magic: a Matroska/WebM file
