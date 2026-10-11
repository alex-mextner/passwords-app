# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S26: a login Apple keeps on several websites of one domain (one record per website, same
account and password) is one item everywhere: one keyring item listing every website, one
row in the app without a reused-password warning, a browser match on each website. Records
that had synced as separate items fold into it without a mass-delete pause or trash entries,
and an edit on Linux rewrites every record without adding one."""

from __future__ import annotations

import dataclasses
from datetime import timedelta
from typing import TYPE_CHECKING

from tests.e2e.apple import login, now
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack

    from passwords_app.core.model import Credential

SITES = ("shop", "account", "help", "pay", "news", "m", "id")


def _record(n: int, password: str) -> Credential:
    stamp = now() - timedelta(days=len(SITES) - n)  # oldest first: the first names the login
    cred = login(f"https://{SITES[n]}.wingtip.example", "lee", password)
    return dataclasses.replace(cred, created=stamp, modified=stamp)


def test_s26_login_on_several_websites_is_one_item(stack: Stack) -> None:
    main = stack.apple.create(_record(0, "FAKE-several-sites"))
    others = [stack.apple.create(_record(n, f"FAKE-old-{n}")) for n in range(1, len(SITES))]
    wait_until(
        lambda: all(stack.keyring.by_id(c.id) for c in (main, *others)),
        what="every record synced as its own item first",
    )

    # On the iPhone the records become one login on several websites: one password for all.
    stack.stop_daemon()
    for other in others:
        stack.apple.edit(other.id, password=main.password)
    records = len(stack.apple.logins())
    stack.start_daemon()

    urls = tuple(o.url for o in others)

    def folded() -> bool:
        item = stack.keyring.by_id(main.id)
        return (
            item is not None
            and item.attributes.get("alt-urls", "").split("\n") == list(urls)
            and not any(stack.keyring.by_id(o.id) for o in others)
        )

    wait_until(folded, what="one keyring item listing every website")
    assert len([i for i in stack.keyring.items() if "wingtip" in i.attributes["url"]]) == 1
    status = stack.daemon.status()
    assert status["state"] != "paused", status
    assert not stack.daemon.trash()
    assert len(stack.apple.logins()) == records
    assert stack.apple.cloudkit.logins(deleted=True) == {}

    # The browser is offered the login on every website.
    for url in (main.url, *urls):
        offered = stack.daemon.call("Match", "s", url)
        assert [c["id"] for c in offered] == [main.id], url

    app = stack.app
    wait_until(
        lambda: app.detail_shows(main.id, url=main.url, alt_urls=urls),
        what="one item with every website in the app",
    )
    assert [i.id for i in app.items() if "wingtip" in i.url] == [main.id]
    assert app.vault.report.of(main.id) == frozenset()

    # Linux → iPhone: a new password reaches every record; no record is added.
    app.edit(main.id, password="FAKE-new-shared")
    wait_until(
        lambda: all(
            (held := stack.apple.get(c.id)) is not None and held.password == "FAKE-new-shared"
            for c in (main, *others)
        ),
        what="the new password on every record",
    )
    assert len(stack.apple.logins()) == records
    assert stack.apple.cloudkit.logins(deleted=True) == {}
