# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Security recommendations and the k-anonymous HIBP range client (against a local server)."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, ClassVar, override

import pytest
import requests

from passwords_app.app import i18n
from passwords_app.app.records import Item
from passwords_app.app.security import (
    HibpClient,
    Issue,
    Level,
    Report,
    analyze,
    breach_count,
    hibp_split,
    issue_text,
    level,
    level_fraction,
    level_text,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

# Fictional passwords; names avoid looking like credential assignments.
STRONG_PW = "gH7#qLz9!vT2mW"
OTHER_STRONG_PW = "Tr0ub4dor&3x"
WEAK_PW = "password"


@pytest.fixture(autouse=True)
def _english() -> None:
    i18n.setup(["en"])


def _item(item_id: str, pw: str | None, **fields: object) -> Item:
    values: dict[str, object] = {"id": item_id, "url": f"https://{item_id}.example", "password": pw}
    values.update(fields)
    return Item(**values)  # type: ignore[arg-type]


# ---------------------------------------------------------------- meter


@pytest.mark.parametrize(
    ("pw", "expected"),
    [
        ("", Level.VERY_WEAK),
        (WEAK_PW, Level.VERY_WEAK),
        ("correcthorse", Level.WEAK),
        ("bluehouse42", Level.GOOD),
        (STRONG_PW, Level.STRONG),
        (OTHER_STRONG_PW, Level.STRONG),
    ],
)
def test_level(pw: str, expected: Level) -> None:
    assert level(pw) is expected


def test_level_counts_user_inputs_as_guessable_and_ignores_empty_ones() -> None:
    assert level("alexander2026") is Level.WEAK
    assert level("alexander2026", user_inputs=["", "alexander2026"]) is Level.VERY_WEAK


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (Level.VERY_WEAK, "Very Weak"),
        (Level.WEAK, "Weak"),
        (Level.GOOD, "Good"),
        (Level.STRONG, "Strong"),
    ],
)
def test_level_text(value: Level, text: str) -> None:
    assert level_text(value) == text


def test_level_fraction_grows_with_strength_and_fills_at_strong() -> None:
    order = [Level.VERY_WEAK, Level.WEAK, Level.GOOD, Level.STRONG]
    fractions = [level_fraction(v) for v in order]
    assert fractions == sorted(fractions)
    assert len(set(fractions)) == len(fractions)
    assert fractions[0] > 0
    assert fractions[-1] == 1.0


# ---------------------------------------------------------------- analyze


def test_analyze_flags_weak_reused_and_compromised() -> None:
    items = [
        _item("a", STRONG_PW),
        _item("b", STRONG_PW),
        _item("c", STRONG_PW),
        _item("d", WEAK_PW),
        _item("e", OTHER_STRONG_PW),
    ]
    report = analyze(items, compromised=["e", "zzz-unknown"])
    assert report.of("a") == {Issue.REUSED}
    assert report.of("d") == {Issue.WEAK}
    assert report.of("e") == {Issue.COMPROMISED}
    assert report.reused_with["a"] == ("b", "c")
    assert report.reused_with["b"] == ("a", "c")
    assert "d" not in report.reused_with
    assert report.count(Issue.REUSED) == 3
    assert report.count(Issue.WEAK) == 1
    assert report.count(Issue.COMPROMISED) == 1
    assert sorted(report.flagged) == ["a", "b", "c", "d", "e"]


def test_reused_with_never_includes_the_item_itself() -> None:
    report = analyze([_item("a", STRONG_PW), _item("b", STRONG_PW)])
    for item_id, others in report.reused_with.items():
        assert item_id not in others


def test_weak_and_reused_combine() -> None:
    report = analyze([_item("a", WEAK_PW), _item("b", WEAK_PW)])
    assert report.of("a") == {Issue.WEAK, Issue.REUSED}


def test_items_without_password_are_skipped() -> None:
    report = analyze([_item("a", None), _item("b", ""), _item("c", STRONG_PW)])
    assert set(report.issues) == {"c"}
    assert report.of("a") == frozenset()
    assert report.flagged == []


def test_compromised_id_without_password_is_not_reported() -> None:
    assert analyze([_item("a", None)], compromised=["a"]).flagged == []


def test_weakness_considers_username_and_site() -> None:
    pw = "janedoe-shop"
    plain = analyze([_item("a", pw, url="https://bank.example")])
    personal = analyze([_item("a", pw, url="https://janedoe-shop.example", username="janedoe")])
    assert Issue.WEAK in personal.of("a")
    assert Issue.WEAK not in plain.of("a")


def test_items_without_url_are_analyzed() -> None:
    assert analyze([_item("a", WEAK_PW, url="")]).of("a") == {Issue.WEAK}


def test_empty_report() -> None:
    report = Report()
    assert report.of("x") == frozenset()
    assert report.flagged == []
    assert report.count(Issue.WEAK) == 0


@pytest.mark.parametrize(
    ("issue", "n", "text"),
    [
        (Issue.COMPROMISED, 0, "This password appeared in a data leak"),
        (Issue.WEAK, 3, "This password is easy to guess"),
        (Issue.REUSED, 0, "Also used on 1 other website"),
        (Issue.REUSED, 1, "Also used on 1 other website"),
        (Issue.REUSED, 4, "Also used on 4 other websites"),
    ],
)
def test_issue_text(issue: Issue, n: int, text: str) -> None:
    assert issue_text(issue, n) == text


# ---------------------------------------------------------------- HIBP helpers


def test_hibp_split_is_uppercase_sha1() -> None:
    prefix, suffix = hibp_split(WEAK_PW)
    assert (
        prefix + suffix == hashlib.sha1(WEAK_PW.encode(), usedforsecurity=False).hexdigest().upper()
    )
    assert (prefix, len(suffix)) == ("5BAA6", 35)


def test_hibp_split_encodes_utf8() -> None:
    prefix, suffix = hibp_split("пароль")
    digest = hashlib.sha1("пароль".encode(), usedforsecurity=False).hexdigest().upper()
    assert prefix + suffix == digest


_, PW_SUFFIX = hibp_split(WEAK_PW)


@pytest.mark.parametrize(
    ("body", "count"),
    [
        (f"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{PW_SUFFIX}:9659365\r\n", 9_659_365),
        (f"{PW_SUFFIX.lower()}:3", 3),
        (f"  {PW_SUFFIX}:7  \n", 7),
        (f"{PW_SUFFIX}:0", 0),
        (f"{PW_SUFFIX}:garbage", 0),
        ("0018A45C4D1DEF81644B54AB7F969B88D65:1", 0),
        ("", 0),
        (f"{PW_SUFFIX[:-1]}:5", 0),
    ],
)
def test_breach_count(body: str, count: int) -> None:
    assert breach_count(body, PW_SUFFIX) == count


def test_breach_count_suffix_case_insensitive() -> None:
    assert breach_count(f"{PW_SUFFIX}:2", PW_SUFFIX.lower()) == 2


# ---------------------------------------------------------------- HibpClient (local server)


@dataclass
class _Range:
    bodies: dict[str, str] = field(default_factory=dict)
    status: int = 200
    requests: list[tuple[str, dict[str, str]]] = field(default_factory=list)


class _Handler(BaseHTTPRequestHandler):
    state: ClassVar[_Range]

    def do_GET(self) -> None:
        self.state.requests.append((self.path, dict(self.headers.items())))
        prefix = self.path.rsplit("/", 1)[-1]
        payload = self.state.bodies.get(prefix, "").encode()
        self.send_response(self.state.status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    @override
    def log_message(self, format: str, *args: object) -> None:
        del format, args


@pytest.fixture
def hibp() -> Iterator[tuple[_Range, HibpClient]]:
    state = _Range()
    handler = type("Handler", (_Handler,), {"state": state})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = requests.Session()
    session.trust_env = False  # never route through a developer's proxy
    host, port = server.server_address[:2]
    client = HibpClient(base_url=f"http://{host!s}:{port}/range/", session=session)
    try:
        yield state, client
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join()


def _body(*rows: tuple[str, int]) -> str:
    return "\r\n".join(f"{suffix}:{count}" for suffix, count in rows)


def test_client_sends_only_the_prefix_and_asks_for_padding(
    hibp: tuple[_Range, HibpClient],
) -> None:
    state, client = hibp
    prefix, suffix = hibp_split(WEAK_PW)
    state.bodies[prefix] = _body((suffix.lower(), 42))
    assert client.compromised({"a": WEAK_PW}) == {"a"}
    [(path, headers)] = state.requests
    assert path == f"/range/{prefix}"
    assert suffix not in path
    assert WEAK_PW not in path
    assert headers.get("Add-Padding") == "true"


def test_padding_rows_do_not_count(hibp: tuple[_Range, HibpClient]) -> None:
    state, client = hibp
    prefix, suffix = hibp_split(STRONG_PW)
    state.bodies[prefix] = _body(("0" * 35, 3), (suffix, 0))
    assert client.compromised({"a": STRONG_PW}) == set()


def test_one_request_per_distinct_prefix(hibp: tuple[_Range, HibpClient]) -> None:
    state, client = hibp
    weak_prefix, weak_suffix = hibp_split(WEAK_PW)
    state.bodies[weak_prefix] = _body((weak_suffix, 5))
    found = client.compromised(
        {"a": WEAK_PW, "b": WEAK_PW, "c": STRONG_PW, "d": "", "e": OTHER_STRONG_PW}
    )
    assert found == {"a", "b"}
    paths = sorted(path for path, _headers in state.requests)
    expected = sorted(f"/range/{hibp_split(p)[0]}" for p in (WEAK_PW, STRONG_PW, OTHER_STRONG_PW))
    assert paths == expected


def test_nothing_to_check_sends_nothing(hibp: tuple[_Range, HibpClient]) -> None:
    state, client = hibp
    assert client.compromised({"a": ""}) == set()
    assert client.compromised({}) == set()
    assert state.requests == []


@pytest.mark.parametrize("status", [404, 429, 503])
def test_http_errors_raise(hibp: tuple[_Range, HibpClient], status: int) -> None:
    state, client = hibp
    state.status = status
    with pytest.raises(requests.HTTPError):
        client.compromised({"a": WEAK_PW})
