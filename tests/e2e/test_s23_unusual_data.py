# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S23: Unicode, very long values, an empty user name and IP-address / port URLs arrive
byte-for-byte in both directions, and a browser fills a login for an IP address and port."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.e2e.apple import login
from tests.e2e.browsers import fill
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.browser.e2e_support import SiteServer
    from tests.e2e.stack import Stack

    from passwords_app.core.model import Credential

UNICODE_SECRET = "FAKE-Пароль-✓-密码-🔑"
LONG_SECRET = "-".join(("FAKE", "x" * 500))


def _from_iphone(site: SiteServer) -> list[Credential]:
    return [
        login(
            "https://mail.unicode.example",
            "пользователь@пример.example",
            UNICODE_SECRET,
            title="Почта ✉ 日本語",
            notes="Ünïcödé notes — ✓",
        ),
        login("https://long.example", "u" * 200, LONG_SECRET, notes="n" * 4000),
        login("https://router.example", "", "FAKE-no-user"),
        login(f"https://127.0.0.1:{site.port}", "admin", "FAKE-ip-port"),
        login("http://[2001:db8::1]:8080", "root", "FAKE-ipv6"),
    ]


def test_s23_unusual_values_from_iphone_arrive_exactly(stack: Stack, site: SiteServer) -> None:
    creds = [stack.apple.create(c) for c in _from_iphone(site)]
    for cred in creds:
        wait_until(lambda c=cred: stack.keyring_matches(c), what=f"{cred.url} in the keyring")
        got = stack.daemon.get(cred.id)
        assert (got["url"], got["username"], got["password"], got["title"], got["notes"]) == (
            cred.url,
            cred.username,
            cred.password,
            cred.title or "",
            cred.notes or "",
        )
    app = stack.app
    for cred in creds:
        wait_until(
            lambda c=cred: app.detail_shows(c.id, password=c.password, username=c.username),
            what=f"{cred.url} in the app",
        )
    ip_login = creds[3]
    for browser in (stack.firefox, stack.chromium):
        url = f"https://127.0.0.1:{site.port}/login.html"
        assert fill(browser, url) == ("admin", ip_login.password)


def test_s23_unusual_values_from_linux_arrive_exactly(stack: Stack, site: SiteServer) -> None:
    del site
    stack.keyring.create("иван @ intranet.example", UNICODE_SECRET)
    app = stack.app
    app.new_password("https://192.0.2.10:8443", "", LONG_SECRET, title="Switch ⚙")

    unicode_login = wait_until(
        lambda: stack.apple.find("https://intranet.example", "иван"), what="Seahorse's login"
    )
    assert unicode_login.password == UNICODE_SECRET
    ip_login = wait_until(
        lambda: stack.apple.find("https://192.0.2.10:8443", ""), what="the app's login"
    )
    assert (ip_login.password, ip_login.title) == (LONG_SECRET, "Switch ⚙")
    stack.assert_no_duplicates()
