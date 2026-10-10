# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""URL normalization and credential/page matching.

The match table is the security boundary for autofill: every NONE row is a case where offering
the password would leak it to a site that does not own it.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from passwords_app.core.model import Credential
from passwords_app.core.urls import MatchKind, link_host, match, normalize_url, registrable_domain

E = MatchKind.EXACT_HOST
S = MatchKind.SAME_SITE
N = MatchKind.NONE

_T = datetime(2026, 1, 1, tzinfo=UTC)


def _cred(url: str, *alt: str) -> Credential:
    return Credential(
        id="c1",
        url=url,
        username="u",
        password="p",
        created=_T,
        modified=_T,
        alt_urls=alt,
    )


# (page_url, credential url, alt_urls, expected)
MATCH_CASES: list[tuple[str, str, tuple[str, ...], MatchKind]] = [
    # --- identical / trivially equal hosts
    ("https://example.com/login", "https://example.com", (), E),
    ("https://example.com", "https://example.com/", (), E),
    ("https://example.com/a/b?x=1#y", "https://example.com/other", (), E),
    ("https://example.com", "example.com", (), E),
    ("https://example.com/path", "example.com/login", (), E),
    ("https://EXAMPLE.COM/", "https://example.com", (), E),
    ("https://example.com", "HTTPS://Example.Com", (), E),
    ("HTTPS://EXAMPLE.COM/LOGIN", "example.com", (), E),
    # --- www equivalence
    ("https://www.example.com", "https://example.com", (), E),
    ("https://example.com", "https://www.example.com", (), E),
    ("https://www.example.com/login", "www.example.com", (), E),
    ("https://WWW.example.com", "example.com", (), E),
    ("https://www.www.example.com", "https://example.com", (), S),
    ("https://www2.example.com", "https://example.com", (), S),
    ("https://wwwexample.com", "https://example.com", (), N),
    ("https://www.example.com", "https://wwwexample.com", (), N),
    # --- subdomains, both directions
    ("https://login.example.com", "https://example.com", (), S),
    ("https://example.com", "https://login.example.com", (), S),
    ("https://a.b.example.com", "https://example.com", (), S),
    ("https://example.com", "https://a.b.c.example.com", (), S),
    ("https://mail.example.com", "https://accounts.example.com", (), S),
    ("https://deep.sub.example.com", "https://other.sub.example.com", (), S),
    ("https://login.example.com", "https://login.example.com", (), E),
    ("https://login.example.com", "https://www.login.example.com", (), E),
    ("https://www.login.example.com", "https://login.example.com", (), E),
    ("https://accounts.google.com", "https://google.com", (), S),
    ("https://m.facebook.com", "https://www.facebook.com", (), S),
    ("https://signin.aws.amazon.com", "https://console.aws.amazon.com", (), S),
    # --- lookalikes and suffix tricks
    ("https://example.com.evil.com", "https://example.com", (), N),
    ("https://example.com", "https://example.com.evil.com", (), N),
    ("https://evil.com", "https://example.com", (), N),
    ("https://notexample.com", "https://example.com", (), N),
    ("https://example.com", "https://notexample.com", (), N),
    ("https://examp1e.com", "https://example.com", (), N),
    ("https://example.co", "https://example.com", (), N),
    ("https://example.com", "https://example.co", (), N),
    ("https://example.net", "https://example.com", (), N),
    ("https://example.com.au", "https://example.com", (), N),
    ("https://example-com.evil.com", "https://example.com", (), N),
    ("https://exampl.com", "https://example.com", (), N),
    ("https://example.comm", "https://example.com", (), N),
    ("https://xexample.com", "https://example.com", (), N),
    ("https://example.com-login.net", "https://example.com", (), N),
    ("https://login-example.com", "https://login.example.com", (), N),
    ("https://paypal.com.secure-login.ru", "https://paypal.com", (), N),
    ("https://xn--pypal-4ve.com", "https://paypal.com", (), N),
    ("https://раураl.com", "https://paypal.com", (), N),  # noqa: RUF001 - homoglyph attack
    ("https://example.com.", "https://example.com.evil.com", (), N),
    ("https://com", "https://example.com", (), N),
    ("https://example.com", "https://com", (), N),
    # --- userinfo tricks: the real host is after '@'
    ("https://example.com@evil.com", "https://example.com", (), N),
    ("https://example.com:pw@evil.com/", "https://example.com", (), N),
    ("https://user@example.com", "https://example.com", (), E),
    ("https://user:pass@example.com/login", "https://example.com", (), E),
    ("https://evil.com@example.com", "https://example.com", (), E),
    ("https://example.com", "https://example.com@evil.com", (), N),
    ("https://evil.com", "https://example.com@evil.com", (), E),
    ("https://evil.com/@example.com", "https://example.com", (), N),
    ("https://evil.com/?u=https://example.com", "https://example.com", (), N),
    ("https://evil.com/#example.com", "https://example.com", (), N),
    ("https://evil.com/example.com", "https://example.com", (), N),
    # --- scheme downgrade/upgrade
    ("http://example.com", "https://example.com", (), N),
    ("http://login.example.com", "https://example.com", (), N),
    ("http://www.example.com", "https://example.com", (), N),
    ("http://example.com", "example.com", (), N),
    ("https://example.com", "http://example.com", (), E),
    ("https://login.example.com", "http://example.com", (), S),
    ("https://www.example.com", "http://example.com", (), E),
    ("http://example.com", "http://example.com", (), E),
    ("http://login.example.com", "http://example.com", (), S),
    ("http://example.com/login", "HTTP://EXAMPLE.COM", (), E),
    ("http://evil.com", "http://example.com", (), N),
    # --- non-http page schemes
    ("javascript:alert(1)", "https://example.com", (), N),
    ("javascript://example.com/%0aalert(1)", "https://example.com", (), N),
    ("data:text/html,<h1>example.com</h1>", "https://example.com", (), N),
    ("file:///home/user/example.com.html", "https://example.com", (), N),
    ("file://example.com/x", "https://example.com", (), N),
    ("ftp://example.com", "https://example.com", (), N),
    ("ftp://example.com", "ftp://example.com", (), N),
    ("ws://example.com", "https://example.com", (), N),
    ("wss://example.com", "https://example.com", (), N),
    ("chrome://settings", "https://example.com", (), N),
    ("about:blank", "https://example.com", (), N),
    ("blob:https://example.com/uuid", "https://example.com", (), N),
    ("mailto:user@example.com", "https://example.com", (), N),
    ("view-source:https://example.com", "https://example.com", (), N),
    ("moz-extension://abc/page.html", "https://example.com", (), N),
    # --- non-http credential schemes never fill web pages
    ("https://example.com", "ftp://example.com", (), N),
    ("https://example.com", "ssh://example.com", (), N),
    ("https://example.com", "javascript:alert(1)", (), N),
    ("https://example.com", "android://hash@com.example.app/", (), N),
    # --- explicit ports
    ("https://example.com:8443", "https://example.com:8443", (), E),
    ("https://example.com:8443/login", "https://example.com", (), N),
    ("https://example.com", "https://example.com:8443", (), N),
    ("https://example.com:8443", "https://example.com:9443", (), N),
    ("https://example.com:443", "https://example.com", (), E),
    ("https://example.com", "https://example.com:443", (), E),
    ("http://example.com:80", "http://example.com", (), E),
    ("https://example.com", "http://example.com:80", (), E),
    # An explicit port is compared against the other side's effective port (80 == 80 here).
    ("https://example.com:80", "http://example.com", (), E),
    ("https://example.com:80", "https://example.com", (), N),
    ("http://example.com:443", "https://example.com", (), N),
    ("https://login.example.com:8443", "https://example.com:8443", (), S),
    ("https://login.example.com:8443", "https://example.com", (), N),
    ("https://example.com:8080", "example.com:8080", (), E),
    ("http://example.com:8080", "http://example.com:8080", (), E),
    ("https://example.com:8080", "http://example.com:8080", (), E),
    ("http://example.com:8080", "https://example.com:8080", (), N),
    ("https://www.example.com:8443", "https://example.com:8443", (), E),
    ("https://example.com:65535", "https://example.com:65535", (), E),
    ("https://example.com:1", "https://example.com:1", (), E),
    ("https://example.com:8443", "https://example.com:08443", (), E),
    # --- trailing dots and case
    ("https://example.com.", "https://example.com", (), E),
    ("https://example.com", "https://example.com.", (), E),
    ("https://login.example.com.", "https://example.com", (), S),
    ("https://Login.Example.COM.", "https://LOGIN.example.com", (), E),
    ("https://example.com..", "https://example.com", (), N),
    # --- IDN: unicode vs punycode equivalence
    ("https://пример.рф", "https://xn--e1afmkfd.xn--p1ai", (), E),
    ("https://xn--e1afmkfd.xn--p1ai", "https://пример.рф", (), E),
    ("https://ПРИМЕР.РФ", "https://пример.рф", (), E),
    ("https://вход.пример.рф", "https://пример.рф", (), S),
    ("https://пример.рф", "https://xn--d1acufc.xn--e1afmkfd.xn--p1ai", (), S),
    ("https://www.пример.рф", "https://xn--e1afmkfd.xn--p1ai", (), E),
    ("https://другой.рф", "https://пример.рф", (), N),
    ("https://bücher.de", "https://xn--bcher-kva.de", (), E),
    ("https://xn--bcher-kva.de", "https://BÜCHER.de", (), E),
    ("https://shop.bücher.de", "https://bücher.de", (), S),
    ("https://bucher.de", "https://bücher.de", (), N),
    ("https://例え.テスト", "https://xn--r8jz45g.xn--zckzah", (), E),
    ("https://münchen.de", "https://muenchen.de", (), N),
    ("https://xn--mnchen-3ya.de", "https://münchen.de", (), E),
    ("https://пример。рф", "https://пример.рф", (), E),
    # --- IPv4 literals
    ("https://192.168.1.1", "https://192.168.1.1", (), E),
    ("https://192.168.1.1/admin", "192.168.1.1", (), E),
    ("https://192.168.1.2", "https://192.168.1.1", (), N),
    ("https://10.0.0.1", "https://10.0.0.2", (), N),
    ("https://1.1.1.1", "https://1.1.1.2", (), N),
    ("https://192.168.1.1:8443", "https://192.168.1.1:8443", (), E),
    ("https://192.168.1.1:8443", "https://192.168.1.1", (), N),
    ("http://192.168.1.1", "https://192.168.1.1", (), N),
    ("https://192.168.1.1", "http://192.168.1.1", (), E),
    ("https://127.0.0.1", "https://localhost", (), N),
    ("https://192.168.1.1", "https://example.com", (), N),
    ("https://example.com", "https://93.184.216.34", (), N),
    ("https://1.168.192.in-addr.arpa", "https://192.168.1.1", (), N),
    ("https://192.168.1.1.", "https://192.168.1.1", (), E),
    # --- IPv6 literals
    ("https://[::1]", "https://[::1]", (), E),
    ("https://[::1]:8443", "https://[::1]:8443", (), E),
    ("https://[::1]:8443", "https://[::1]", (), N),
    ("https://[2001:db8::1]", "https://[2001:0db8:0000:0000:0000:0000:0000:0001]", (), E),
    ("https://[2001:DB8::1]", "https://[2001:db8::1]", (), E),
    ("https://[2001:db8::1]", "https://[2001:db8::2]", (), N),
    ("https://[::ffff:192.168.1.1]", "https://192.168.1.1", (), N),
    ("https://[::1]", "https://localhost", (), N),
    ("http://[::1]", "https://[::1]", (), N),
    ("https://[2001:db8::1]/login", "[2001:db8::1]", (), E),
    # --- single-label and local hosts
    ("https://localhost", "https://localhost", (), E),
    ("http://localhost:3000", "http://localhost:3000", (), E),
    ("http://localhost:3000", "http://localhost:3001", (), N),
    ("http://localhost:3000", "http://localhost", (), N),
    ("https://a.localhost", "https://b.localhost", (), N),
    ("https://app.localhost", "https://localhost", (), N),
    ("https://router", "https://router", (), E),
    ("https://router", "https://nas", (), N),
    ("https://nas.lan", "https://router.lan", (), N),
    ("https://nas.home.arpa", "https://router.home.arpa", (), N),
    ("https://a.example.local", "https://b.example.local", (), S),
    ("https://a.corp.internal", "https://b.corp.internal", (), S),
    # --- private suffixes: different owners under a shared suffix
    ("https://alice.github.io", "https://bob.github.io", (), N),
    ("https://bob.github.io", "https://alice.github.io", (), N),
    ("https://alice.github.io", "https://alice.github.io", (), E),
    ("https://alice.github.io/repo", "https://alice.github.io/other", (), E),
    ("https://github.io", "https://alice.github.io", (), N),
    ("https://alice.github.io", "https://github.io", (), N),
    ("https://github.io", "https://github.io", (), E),
    ("https://github.com", "https://alice.github.io", (), N),
    ("https://alice.github.io", "https://github.com", (), N),
    ("https://docs.alice.github.io", "https://alice.github.io", (), S),
    ("https://a.gitlab.io", "https://b.gitlab.io", (), N),
    ("https://app1.herokuapp.com", "https://app2.herokuapp.com", (), N),
    ("https://my.vercel.app", "https://your.vercel.app", (), N),
    ("https://a.netlify.app", "https://b.netlify.app", (), N),
    ("https://a.pages.dev", "https://b.pages.dev", (), N),
    ("https://x.blogspot.com", "https://y.blogspot.com", (), N),
    ("https://bucket1.s3.amazonaws.com", "https://bucket2.s3.amazonaws.com", (), N),
    ("https://s3.amazonaws.com", "https://bucket.s3.amazonaws.com", (), N),
    ("https://aws.amazon.com", "https://amazonaws.com", (), N),
    ("https://a.compute-1.amazonaws.com", "https://b.compute-1.amazonaws.com", (), N),
    # --- multi-level public suffixes
    ("https://example.co.uk", "https://example.co.uk", (), E),
    ("https://login.example.co.uk", "https://example.co.uk", (), S),
    ("https://a.b.example.co.uk", "https://c.example.co.uk", (), S),
    ("https://example.co.uk", "https://other.co.uk", (), N),
    ("https://co.uk", "https://example.co.uk", (), N),
    ("https://example.co.uk", "https://co.uk", (), N),
    ("https://co.uk", "https://co.uk", (), E),
    ("https://example.co.uk", "https://example.uk", (), N),
    ("https://example.uk", "https://example.co.uk", (), N),
    ("https://example.co.uk", "https://example.com", (), N),
    ("https://shop.example.com.au", "https://example.com.au", (), S),
    ("https://example.com.au", "https://other.com.au", (), N),
    ("https://com.au", "https://example.com.au", (), N),
    ("https://a.appspot.com", "https://b.appspot.com", (), N),
    ("https://a.appspot.com", "https://appspot.com", (), N),
    ("https://v2.a.appspot.com", "https://a.appspot.com", (), S),
    ("https://ex.co.jp", "https://www.ex.co.jp", (), E),
    ("https://a.ex.co.jp", "https://b.ex.co.jp", (), S),
    ("https://a.gov.uk", "https://b.gov.uk", (), N),
    ("https://www.ox.ac.uk", "https://login.ox.ac.uk", (), S),
    ("https://a.b.c.kawasaki.jp", "https://d.b.c.kawasaki.jp", (), S),
    ("https://a.c.kawasaki.jp", "https://b.c.kawasaki.jp", (), N),
    ("https://a.x.ck", "https://b.x.ck", (), N),
    ("https://x.ck", "https://x.ck", (), E),
    ("https://www.ck", "https://login.www.ck", (), S),
    # --- IDNA as browsers resolve it (UTS #46 non-transitional): ß is not ss
    ("https://fass.de", "https://faß.de", (), N),
    ("https://xn--fa-hia.de", "https://faß.de", (), E),
    ("https://faß.de", "https://fass.de", (), N),
    ("https://straße.de", "https://strasse.de", (), N),
    ("https://xn--strae-oqa.de", "https://STRAẞE.de", (), E),
    # --- backslash is a path separator for http(s), as in the browser
    ("https://example.com", "https://evil.com\\@example.com", (), N),
    ("https://evil.com", "https://evil.com\\@example.com", (), E),
    ("https://example.com", "evil.com\\@example.com", (), N),
    ("https://evil.com\\@example.com", "https://example.com", (), N),
    ("https://example.com", "https:\\\\example.com", (), E),
    ("https://example.com/?next=a\\@evil.com", "https://example.com", (), E),
    # `www.` is only dropped when what remains is an ownable domain, never a bare suffix
    ("https://www.ck", "https://ck", (), N),
    ("https://www.com", "https://com", (), N),
    ("https://www.co.uk", "https://co.uk", (), N),
    ("https://www.github.io", "https://github.io", (), N),
    # --- alt_urls
    ("https://example.org", "https://example.com", ("https://example.org",), E),
    ("https://login.example.org", "https://example.com", ("https://example.org",), S),
    ("https://example.net", "https://example.com", ("https://example.org",), N),
    ("https://example.com", "https://login.example.com", ("https://example.com",), E),
    ("https://example.org", "https://example.com", ("not a url", "example.org"), E),
    ("http://example.org", "https://example.com", ("https://example.org",), N),
    ("http://example.org", "https://example.com", ("http://example.org",), E),
    ("https://evil.com", "https://example.com", ("https://example.com@evil.com",), E),
    ("https://evil.com", "https://example.com", ("https://evil.com.example.com",), N),
    ("https://example.org:8443", "https://example.com", ("https://example.org:8443",), E),
    ("https://example.org", "https://example.com", ("https://example.org:8443",), N),
    ("https://a.example.org", "https://x.example.com", ("https://b.example.org",), S),
    ("https://alice.github.io", "https://example.com", ("https://bob.github.io",), N),
    ("https://example.com", "javascript:alert(1)", ("https://example.com",), E),
    ("https://example.com", "garbage ::: url", ("ftp://example.com", "www.example.com"), E),
    ("https://shop.example.com", "https://example.com", ("https://shop.example.com",), E),
    # --- unparsable input never raises, never matches
    ("not a url", "https://example.com", (), N),
    ("", "https://example.com", (), N),
    ("https://", "https://example.com", (), N),
    ("https:///path", "https://example.com", (), N),
    ("https://exa mple.com", "https://example.com", (), N),
    ("https://example.com:99999", "https://example.com", (), N),
    ("https://example.com:abc", "https://example.com", (), N),
    ("https://[::1", "https://example.com", (), N),
    ("https://example.com", "https://[::1", (), N),
    ("https://example.com", "http://", (), N),
    ("https://example.com", "https://exa mple.com", (), N),
    ("https://example.com", "https://example.com:0", (), N),
    ("https://example.com", "https://-example-.com", (), N),
    ("https://example..com", "https://example.com", (), N),
    ("https://.example.com", "https://example.com", (), N),
    ("https://a_b.example.com", "https://example.com", (), S),
    ("https://" + "a" * 64 + ".com", "https://example.com", (), N),
    ("https://xn--zz.com", "https://xn--zz.com", (), N),
    ("https://256.256.256.256", "https://256.256.256.256", (), N),
    ("https://0x7f.0.0.1", "https://127.0.0.1", (), N),
    ("\x00https://example.com", "https://example.com", (), N),
    ("https://example.com\n.evil.com", "https://example.com", (), N),
]


@pytest.mark.parametrize(
    ("page", "url", "alt", "expected"),
    MATCH_CASES,
    ids=[f"{i:03d}" for i in range(len(MATCH_CASES))],
)
def test_match(page: str, url: str, alt: tuple[str, ...], expected: MatchKind) -> None:
    assert match(page, _cred(url, *alt)) is expected


def test_match_table_is_large_and_distinct() -> None:
    rows = [(p, u, a) for p, u, a, _ in MATCH_CASES]
    assert len(set(rows)) == len(rows)
    assert len(rows) >= 200


NORMALIZE_CASES: list[tuple[str, str]] = [
    ("example.com", "https://example.com"),
    ("https://example.com", "https://example.com"),
    ("https://example.com/", "https://example.com"),
    ("https://example.com/login", "https://example.com/login"),
    ("https://example.com/login/", "https://example.com/login/"),
    ("HTTPS://EXAMPLE.COM/Path", "https://example.com/Path"),
    ("Http://Example.com", "http://example.com"),
    ("https://example.com:443/x", "https://example.com/x"),
    ("http://example.com:80/x", "http://example.com/x"),
    ("https://example.com:80/x", "https://example.com:80/x"),
    ("http://example.com:443", "http://example.com:443"),
    ("https://example.com:8443", "https://example.com:8443"),
    ("https://example.com:08443", "https://example.com:8443"),
    ("example.com:8080/x", "https://example.com:8080/x"),
    ("https://user:pw@example.com/", "https://example.com"),
    ("https://example.com@evil.com", "https://evil.com"),
    ("https://example.com/p?q=1#frag", "https://example.com/p"),
    ("https://example.com?q=1", "https://example.com"),
    ("https://example.com#frag", "https://example.com"),
    ("https://example.com.", "https://example.com"),
    ("https://example.com./x", "https://example.com/x"),
    ("https://пример.рф", "https://xn--e1afmkfd.xn--p1ai"),
    ("пример.рф/вход", "https://xn--e1afmkfd.xn--p1ai/вход"),
    ("https://BÜCHER.de", "https://xn--bcher-kva.de"),
    ("https://XN--BCHER-KVA.DE", "https://xn--bcher-kva.de"),
    ("https://пример。рф", "https://xn--e1afmkfd.xn--p1ai"),
    ("https://[::1]", "https://[::1]"),
    ("https://[::1]:8443/x", "https://[::1]:8443/x"),
    ("https://[2001:0DB8:0:0:0:0:0:1]", "https://[2001:db8::1]"),
    ("[2001:db8::1]", "https://[2001:db8::1]"),
    ("https://192.168.1.1", "https://192.168.1.1"),
    ("https://192.168.1.1/admin/", "https://192.168.1.1/admin/"),
    ("192.168.1.1:8080", "https://192.168.1.1:8080"),
    ("localhost", "https://localhost"),
    ("localhost:3000", "https://localhost:3000"),
    ("ftp://Example.com/file", "ftp://example.com/file"),
    ("http://example.com:", "http://example.com"),
    ("  https://example.com  ", "https://example.com"),
    ("https://a_b.example.com", "https://a_b.example.com"),
]


@pytest.mark.parametrize(("raw", "expected"), NORMALIZE_CASES)
def test_normalize_url(raw: str, expected: str) -> None:
    assert normalize_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "https://",
        "https:///path",
        "//",
        "not a url",
        "https://exa mple.com",
        "https://example.com:99999",
        "https://example.com:0",
        "https://example.com:-1",
        "https://example.com:abc",
        "https://[::1",
        "https://[not-ipv6]",
        "https://example..com",
        "https://.example.com",
        "https://example.com..",
        "https://-bad.com",
        "https://bad-.com",
        "https://" + "a" * 64 + ".com",
        "https://xn--zz.com",
        "https://256.256.256.256",
        "https://1.2.3.4.5",
        "https://0x7f.0.0.1",
        "https://127.1",
        "javascript:alert(1)",
        "data:text/html,hi",
        "mailto:user@example.com",
        "file:///etc/passwd",
        "about:blank",
        "https://exa\x00mple.com",
        "https://example.com\n.evil.com",
        "https://ex<ample.com",
        "https://ex%41mple.com",
    ],
)
def test_normalize_url_rejects(raw: str) -> None:
    with pytest.raises(ValueError, match=r"."):
        normalize_url(raw)


REGISTRABLE_CASES: list[tuple[str, str]] = [
    ("example.com", "example.com"),
    ("www.example.com", "example.com"),
    ("a.b.c.example.com", "example.com"),
    ("EXAMPLE.COM", "example.com"),
    ("example.com.", "example.com"),
    ("login.example.co.uk", "example.co.uk"),
    ("example.co.uk", "example.co.uk"),
    ("co.uk", "co.uk"),
    ("com", "com"),
    ("shop.example.com.au", "example.com.au"),
    ("alice.github.io", "alice.github.io"),
    ("docs.alice.github.io", "alice.github.io"),
    ("github.io", "github.io"),
    ("a.appspot.com", "a.appspot.com"),
    ("appspot.com", "appspot.com"),
    ("bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com"),
    ("вход.пример.рф", "xn--e1afmkfd.xn--p1ai"),
    ("xn--d1acufc.xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai"),
    ("рф", "xn--p1ai"),
    ("shop.BÜCHER.de", "xn--bcher-kva.de"),
    ("localhost", "localhost"),
    ("router", "router"),
    ("a.localhost", "a.localhost"),
    ("192.168.1.1", "192.168.1.1"),
    ("10.0.0.1", "10.0.0.1"),
    ("::1", "::1"),
    ("[::1]", "::1"),
    ("2001:0DB8::0001", "2001:db8::1"),
    ("[2001:db8::1]", "2001:db8::1"),
    ("a.b.c.kawasaki.jp", "b.c.kawasaki.jp"),
    ("city.kawasaki.jp", "city.kawasaki.jp"),
    ("a.x.ck", "a.x.ck"),
    ("www.ck", "www.ck"),
]


@pytest.mark.parametrize(("host", "expected"), REGISTRABLE_CASES)
def test_registrable_domain(host: str, expected: str) -> None:
    assert registrable_domain(host) == expected


@pytest.mark.parametrize("host", ["", "exa mple.com", "a..b", "-x.com", "[::1", "x" * 64 + ".com"])
def test_registrable_domain_rejects(host: str) -> None:
    with pytest.raises(ValueError, match=r"."):
        registrable_domain(host)


LINK_HOST_CASES: list[tuple[str, str]] = [
    ("https://example.com", "example.com"),
    ("https://www.example.com/login", "example.com"),
    ("example.com", "example.com"),
    ("www.example.com", "example.com"),
    ("HTTPS://WWW.EXAMPLE.COM.", "example.com"),
    ("https://example.com:443", "example.com"),
    ("https://example.com:8443", "example.com"),
    ("http://example.com:80", "example.com"),
    ("https://login.example.com", "login.example.com"),
    ("https://www.login.example.com", "login.example.com"),
    ("https://www2.example.com", "www2.example.com"),
    ("https://user:pw@example.com", "example.com"),
    ("https://example.com@evil.com", "evil.com"),
    ("https://пример.рф", "xn--e1afmkfd.xn--p1ai"),
    ("https://www.пример.рф", "xn--e1afmkfd.xn--p1ai"),
    ("https://xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai"),
    ("https://192.168.1.1:8080", "192.168.1.1"),
    ("https://[::1]:8443", "::1"),
    ("https://[2001:DB8::1]", "2001:db8::1"),
    ("http://localhost:3000", "localhost"),
    ("https://www", "www"),
    ("https://www.co.uk", "www.co.uk"),
    ("https://faß.de", "xn--fa-hia.de"),
    ("https://fass.de", "fass.de"),
    ("https://evil.com\\@example.com", "evil.com"),
    ("", ""),
    ("not a url", ""),
    ("https://", ""),
    ("javascript:alert(1)", ""),
    ("https://exa mple.com", ""),
    ("https://example.com:99999", ""),
    ("https://[::1", ""),
]


@pytest.mark.parametrize(("raw", "expected"), LINK_HOST_CASES)
def test_link_host(raw: str, expected: str) -> None:
    assert link_host(raw) == expected
