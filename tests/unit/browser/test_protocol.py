# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from passwords_app.browser.protocol import (
    MAX_ITEM_ID_CHARS,
    MAX_PASSWORD_CHARS,
    MAX_TITLE_CHARS,
    MAX_URL_CHARS,
    MAX_USERNAME_CHARS,
    PROTOCOL_VERSION,
    Candidate,
    Code,
    DaemonStatus,
    Fill,
    Login,
    Match,
    ProtocolError,
    Request,
    Save,
    Status,
    code_result,
    command_name,
    failure,
    fill_result,
    match_result,
    ok,
    origin,
    parse_request,
    request_id,
    save_result,
    status_result,
)

if TYPE_CHECKING:
    from passwords_app.browser.protocol import SaveAction

URL = "https://accounts.example.com/login?next=%2F"
FAKE_PW = "fictional-Passw0rd"
LONG_URL_PREFIX = "https://example.com/"


def bad(message: dict[str, object], reason: str) -> None:
    with pytest.raises(ProtocolError, match=reason) as caught:
        parse_request(message)
    assert caught.value.code == "bad-request"


def save_request(**fields: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": 1,
        "cmd": "save",
        "url": URL,
        "username": "alex@example.com",
        "password": FAKE_PW,
    }
    return base | fields


# ---------------------------------------------------------------------- envelope id


@pytest.mark.parametrize("rid", [0, 1, 7, 2**53 - 1, "a", "x" * 64, "req-1", "ü"])
def test_valid_request_ids_are_echoed(rid: int | str) -> None:
    assert request_id({"id": rid}) == rid
    assert parse_request({"id": rid, "cmd": "status"}) == Request(rid, Status())


@pytest.mark.parametrize(
    "rid", [-1, 2**53, 2**64, 1.0, 1.5, True, False, None, "", "x" * 65, "a\x00", [], {}]
)
def test_invalid_request_ids(rid: object) -> None:
    assert request_id({"id": rid}) is None
    bad({"id": rid, "cmd": "status"}, "id must be")


def test_missing_request_id() -> None:
    assert request_id({"cmd": "status"}) is None
    bad({"cmd": "status"}, "id must be")


# ---------------------------------------------------------------------- commands


def test_status() -> None:
    assert parse_request({"id": 1, "cmd": "status"}).command == Status()


def test_match() -> None:
    assert parse_request({"id": 1, "cmd": "match", "url": URL}).command == Match(URL)


def test_fill() -> None:
    message: dict[str, object] = {"id": 1, "cmd": "fill", "item_id": "ITEM-1", "url": URL}
    assert parse_request(message).command == Fill("ITEM-1", URL)


def test_code() -> None:
    message: dict[str, object] = {"id": "c", "cmd": "code", "item_id": "ITEM-1", "url": URL}
    assert parse_request(message) == Request("c", Code("ITEM-1", URL))


def test_save_minimal_defaults() -> None:
    command = parse_request(save_request()).command
    assert command == Save(URL, "alex@example.com", FAKE_PW, None, None, dry_run=False)


def test_save_all_fields() -> None:
    message = save_request(title="Northwind", item_id="ITEM-1", dry_run=True, username="")
    assert parse_request(message).command == Save(
        URL, "", FAKE_PW, "Northwind", "ITEM-1", dry_run=True
    )


def test_save_repr_hides_the_password() -> None:
    command = parse_request(save_request()).command
    assert FAKE_PW not in repr(command)
    assert FAKE_PW not in str(command)


def test_login_repr_hides_the_password() -> None:
    assert FAKE_PW not in repr(Login("alex@example.com", FAKE_PW))


@pytest.mark.parametrize("cmd", ["", "Status", "MATCH", "get", "list", "delete", "fill "])
def test_unknown_commands(cmd: str) -> None:
    bad({"id": 1, "cmd": cmd}, "unknown command")


@pytest.mark.parametrize("cmd", [None, 1, ["status"], {"name": "status"}, True])
def test_cmd_must_be_a_string(cmd: object) -> None:
    bad({"id": 1, "cmd": cmd}, "cmd must be a string")


def test_missing_cmd() -> None:
    bad({"id": 1}, "cmd must be a string")


def test_unknown_command_name_is_truncated_in_the_message() -> None:
    with pytest.raises(ProtocolError) as caught:
        parse_request({"id": 1, "cmd": "z" * 10_000})
    assert len(caught.value.message) < 200


@pytest.mark.parametrize(
    "message",
    [
        {"id": 1, "cmd": "status", "url": URL},
        {"id": 1, "cmd": "match", "url": URL, "item_id": "x"},
        {"id": 1, "cmd": "match", "url": URL, "URL": URL},
        {"id": 1, "cmd": "fill", "item_id": "x", "url": URL, "password": "p"},
        {"id": 1, "cmd": "fill", "item_id": "x", "url": URL, "frame": 0},
        {"id": 1, "cmd": "code", "item_id": "x", "url": URL, "dry_run": True},
        {"id": 1, "cmd": "save", "url": URL, "username": "", "password": "p", "notes": "n"},
        {"id": 1, "cmd": "save", "url": URL, "username": "", "password": "p", "otpauth": "o"},
        {"id": 1, "cmd": "save", "url": URL, "username": "", "password": "p", "id ": 1},
    ],
)
def test_unknown_fields_are_rejected(message: dict[str, object]) -> None:
    bad(message, "unknown field")


@pytest.mark.parametrize(
    ("message", "field"),
    [
        ({"id": 1, "cmd": "match"}, "url"),
        ({"id": 1, "cmd": "fill", "url": URL}, "item_id"),
        ({"id": 1, "cmd": "fill", "item_id": "x"}, "url"),
        ({"id": 1, "cmd": "code", "url": URL}, "item_id"),
        ({"id": 1, "cmd": "code", "item_id": "x"}, "url"),
        ({"id": 1, "cmd": "save", "username": "", "password": "p"}, "url"),
        ({"id": 1, "cmd": "save", "url": URL, "password": "p"}, "username"),
        ({"id": 1, "cmd": "save", "url": URL, "username": ""}, "password"),
    ],
)
def test_missing_fields(message: dict[str, object], field: str) -> None:
    bad(message, f"missing field '{field}'")


# ---------------------------------------------------------------------- url rule


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "http://example.com/",
        "HTTPS://EXAMPLE.COM/Path",
        "https://example.com:8443/a?b#c",
        "https://192.0.2.10:8443/",
        "https://[2001:db8::1]/",
        "https://user:pw@example.com/",
        "https://пример.example/",
        "https://xn--e1afmkfd.example/",
        LONG_URL_PREFIX + "a" * (MAX_URL_CHARS - len(LONG_URL_PREFIX)),
    ],
)
def test_accepted_urls(url: str) -> None:
    assert parse_request({"id": 1, "cmd": "match", "url": url}).command == Match(url)


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("", "1-4096"),
        (LONG_URL_PREFIX + "a" * (MAX_URL_CHARS - len(LONG_URL_PREFIX) + 1), "1-4096"),
        ("ftp://example.com/", "http"),
        ("file:///etc/passwd", "http"),
        ("javascript:alert(1)", "http"),
        ("data:text/html,hi", "http"),
        ("chrome-extension://djaiceficanbdafmmlcmgbfjefiapjaf/popup.html", "http"),
        ("moz-extension://abc/popup.html", "http"),
        ("about:blank", "http"),
        ("example.com", "http"),
        ("//example.com/", "http"),
        ("https:///path", "host"),
        ("https://", "host"),
        ("https://:443/", "host"),
        ("https://example.com:99999/", "parsed"),
        ("https://example.com:port/", "parsed"),
        ("https://[::1/", "parsed"),
        ("https://example.com/\x00", "U\\+0000"),
        ("https://example.com/\ud800", "surrogate"),
    ],
)
def test_rejected_urls(url: str, reason: str) -> None:
    bad({"id": 1, "cmd": "match", "url": url}, reason)


@pytest.mark.parametrize("url", [None, 1, ["https://example.com"], {"href": "x"}, True])
def test_url_must_be_a_string(url: object) -> None:
    bad({"id": 1, "cmd": "match", "url": url}, "url must be a string")


# ---------------------------------------------------------------------- item_id rule


@pytest.mark.parametrize("cmd", ["fill", "code"])
@pytest.mark.parametrize(
    ("item_id", "reason"),
    [
        ("", "1-256"),
        ("x" * (MAX_ITEM_ID_CHARS + 1), "1-256"),
        ("a\x00b", "U\\+0000"),
        (1, "item_id must be a string"),
        (None, "item_id must be a string"),
    ],
)
def test_rejected_item_ids(cmd: str, item_id: object, reason: str) -> None:
    bad({"id": 1, "cmd": cmd, "item_id": item_id, "url": URL}, reason)


def test_item_id_at_limit() -> None:
    item_id = "x" * MAX_ITEM_ID_CHARS
    message: dict[str, object] = {"id": 1, "cmd": "fill", "item_id": item_id, "url": URL}
    assert parse_request(message).command == Fill(item_id, URL)


# ---------------------------------------------------------------------- save fields


@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        ({"username": "u" * (MAX_USERNAME_CHARS + 1)}, "username must have 0-1024"),
        ({"username": None}, "username must be a string"),
        ({"username": "a\x00"}, "U\\+0000"),
        ({"password": ""}, "password must have 1-4096"),
        ({"password": "p" * (MAX_PASSWORD_CHARS + 1)}, "password must have 1-4096"),
        ({"password": 12345678}, "password must be a string"),
        ({"password": "p\x00w"}, "U\\+0000"),
        ({"password": "\udfff"}, "surrogate"),
        ({"title": "t" * (MAX_TITLE_CHARS + 1)}, "title must have 0-256"),
        ({"title": None}, "title must be a string"),
        ({"title": "\x00"}, "U\\+0000"),
        ({"item_id": ""}, "item_id must have 1-256"),
        ({"item_id": 5}, "item_id must be a string"),
        ({"dry_run": "true"}, "dry_run must be a boolean"),
        ({"dry_run": 1}, "dry_run must be a boolean"),
        ({"dry_run": None}, "dry_run must be a boolean"),
        ({"url": "ftp://example.com/"}, "http"),
    ],
)
def test_rejected_save_fields(fields: dict[str, object], reason: str) -> None:
    bad(save_request(**fields), reason)


def test_save_field_limits_are_inclusive() -> None:
    message = save_request(
        username="u" * MAX_USERNAME_CHARS,
        password="p" * MAX_PASSWORD_CHARS,
        title="t" * MAX_TITLE_CHARS,
    )
    command = parse_request(message).command
    assert isinstance(command, Save)
    assert len(command.username) == MAX_USERNAME_CHARS
    assert len(command.password) == MAX_PASSWORD_CHARS
    assert command.title is not None
    assert len(command.title) == MAX_TITLE_CHARS


def test_save_empty_title_is_kept_as_empty() -> None:
    command = parse_request(save_request(title="")).command
    assert isinstance(command, Save)
    assert command.title == ""


def test_save_one_char_password() -> None:
    shortest = "p"
    command = parse_request(save_request(password=shortest)).command
    assert isinstance(command, Save)
    assert command.password == shortest


# ---------------------------------------------------------------------- helpers


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ({"cmd": "fill"}, "fill"),
        ({"cmd": "save"}, "save"),
        ({"cmd": "hack"}, None),
        ({"cmd": 3}, None),
        ({}, None),
    ],
)
def test_command_name_only_returns_known_commands(
    message: dict[str, object], expected: str | None
) -> None:
    assert command_name(message) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://accounts.example.com/login?next=/", "https://accounts.example.com"),
        ("http://example.com", "http://example.com"),
        ("HTTPS://Example.COM/A", "https://example.com"),
        ("https://example.com:8443/x", "https://example.com:8443"),
        ("https://user:hunter2@example.com/x", "https://example.com"),
        ("https://192.0.2.10:8443/admin", "https://192.0.2.10:8443"),
        ("https://[2001:db8::1]:8443/x", "https://[2001:db8::1]:8443"),
        ("https://example.com#frag", "https://example.com"),
    ],
)
def test_origin(url: str, expected: str) -> None:
    assert origin(url) == expected


# ---------------------------------------------------------------------- responses


def test_ok_shape() -> None:
    assert ok(7, {"a": 1}) == {"id": 7, "ok": True, "result": {"a": 1}}


def test_failure_shape() -> None:
    assert failure(None, "malformed", "frame is not JSON") == {
        "id": None,
        "ok": False,
        "error": {"code": "malformed", "message": "frame is not JSON"},
    }


def test_status_result_shape() -> None:
    assert status_result(DaemonStatus("idle", "", 42)) == {
        "state": "idle",
        "message": "",
        "item_count": 42,
        "protocol": PROTOCOL_VERSION,
    }


def test_match_result_has_exactly_the_public_fields() -> None:
    candidate = Candidate(
        id="ITEM-1",
        title="Northwind",
        username="alex@example.com",
        url="https://northwind.example",
        alt_urls=("https://mail.northwind.example",),
        has_code=True,
    )
    assert match_result([candidate]) == {
        "items": [
            {
                "id": "ITEM-1",
                "title": "Northwind",
                "username": "alex@example.com",
                "url": "https://northwind.example",
                "alt_urls": ["https://mail.northwind.example"],
                "has_code": True,
            }
        ]
    }


def test_match_result_empty() -> None:
    assert match_result([]) == {"items": []}


def test_fill_result_shape() -> None:
    assert fill_result(Login("alex@example.com", FAKE_PW)) == {
        "username": "alex@example.com",
        "password": FAKE_PW,
    }


def test_code_result_shape() -> None:
    assert code_result("492039", 17) == {"code": "492039", "seconds_left": 17}


@pytest.mark.parametrize(
    ("action", "item_id", "saved"),
    [("create", None, False), ("create", "N", True), ("update", "U", True), ("none", "U", False)],
)
def test_save_result_shape(action: SaveAction, item_id: str | None, saved: bool) -> None:
    result = save_result(action, item_id, saved=saved)
    assert result == {"action": action, "id": item_id, "saved": saved}
