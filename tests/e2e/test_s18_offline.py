# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S18: while iCloud cannot be reached the status says "offline", changes on both sides wait,
and once it is back the daemon retries by itself and nothing is lost."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.e2e.apple import login
from tests.e2e.stack import stays, wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack

EDITED = "FAKE-edited-while-offline"


def test_s18_offline_then_retry_loses_nothing(stack: Stack) -> None:
    app = stack.app
    seeded = stack.seeded["contoso"]
    for path in ("/record/sync", "/record/save", "/record/delete"):
        stack.cloudkit.fail(path, http_status=503, times=1_000_000)

    item = stack.keyring.by_id(seeded.id)
    assert item is not None
    stack.keyring.set_secret(item.path, EDITED)
    added = stack.apple.create(
        login("https://news.tailspin.example", "reader", "FAKE-added-offline")
    )
    wait_until(lambda: stack.daemon.status()["state"] == "offline", what="status offline")
    wait_until(lambda: app.status_title() == "Offline", what="app shows Offline")
    stays(
        lambda: stack.apple.get(seeded.id).password == seeded.password,  # type: ignore[union-attr]
        seconds=3,
        what="iCloud untouched while unreachable",
    )
    assert stack.keyring.by_id(added.id) is None

    for fault in stack.cloudkit.faults:
        fault.times = 0  # iCloud is reachable again

    wait_until(
        lambda: (c := stack.apple.get(seeded.id)) and c.password == EDITED,
        what="the offline edit in iCloud",
    )
    wait_until(lambda: stack.keyring_matches(added), what="the iPhone's login on Linux")
    wait_until(lambda: stack.daemon.status()["state"] == "idle", what="status idle")
    wait_until(lambda: app.status_title() == "Synced", what="app shows Synced")
    assert len(stack.apple.logins()) == len(stack.seeded) + 1
    stack.assert_no_duplicates()
