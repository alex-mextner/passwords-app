# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Autofill, codes, saving and the security refusals in real Firefox (see e2e_scenarios)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from tests.browser import e2e_scenarios as scenarios

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.browser.conftest import Vault
    from tests.browser.e2e_support import Page, SiteServer

pytestmark = [pytest.mark.browser, pytest.mark.timeout(180)]

SCENARIOS: list[Callable[[Page, SiteServer, Vault], None]] = [
    scenarios.fill_first_candidate,
    scenarios.fill_field_focused_while_loading,
    scenarios.keyboard_picks_second,
    scenarios.escape_closes_without_filling,
    scenarios.otp_fill,
    scenarios.save_new_login,
    scenarios.update_changed_password,
    scenarios.unchanged_login_is_not_offered,
    scenarios.generator_then_save,
    scenarios.popup_search_and_fill,
    scenarios.no_fill_on_lookalike,
    scenarios.no_fill_on_http_downgrade,
    scenarios.no_fill_in_third_party_frame,
]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.__name__)
def test_scenario(
    scenario: Callable[[Page, SiteServer, Vault], None],
    firefox: Page,
    site: SiteServer,
    vault: Vault,
) -> None:
    scenario(firefox, site, vault)
