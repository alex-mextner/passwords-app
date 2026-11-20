# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S20: stopping the daemon (logout) or killing it (power loss), with changes made on both
sides meanwhile, never duplicates or loses a password."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from tests.e2e.apple import login
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack


@pytest.mark.parametrize("how", ["stop", "kill"])
def test_s20_restart_never_duplicates(stack: Stack, how: str) -> None:
    before = len(stack.seeded)
    stack.stop_daemon(kill=how == "kill")
    on_phone = stack.apple.create(
        login("https://news.tailspin.example", "reader", "FAKE-while-down")
    )
    stack.keyring.create("ops @ intranet.example", "FAKE-seahorse-down")

    stack.start_daemon()
    wait_until(lambda: stack.keyring_matches(on_phone), what="the iPhone's login on Linux")
    wait_until(
        lambda: stack.apple.find("https://intranet.example", "ops"), what="Seahorse's in iCloud"
    )
    # And once more, with nothing changed in between: a restart alone does nothing.
    stack.stop_daemon(kill=how == "kill")
    stack.start_daemon()
    stack.daemon.sync_now()

    stack.assert_no_duplicates()
    assert len(stack.apple.logins()) == before + 2
    assert len(stack.keyring.items()) == before + 2
    assert len(stack.daemon.items()) == before + 2
    assert stack.daemon.trash() == []
    app = stack.app
    assert len(app.items()) == before + 2
