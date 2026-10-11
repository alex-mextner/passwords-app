# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The real native host process against `FakeDaemon` on a private session bus."""

from __future__ import annotations

import json
import struct
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from tests.browser.native_host_support import HostProcess, candidates, error_code, result
from tests.fakes.fake_daemon import FakeDaemon, FakeDaemonThread
from tests.harness.dbus_session import private_bus, private_session

from passwords_app.browser.daemon import DaemonClient
from passwords_app.browser.framing import MAX_PAYLOAD
from passwords_app.browser.native_host import Host
from passwords_app.core.otp import code_at, parse_otpauth

if TYPE_CHECKING:
    from collections.abc import Iterator

    from tests.harness.dbus_session import PrivateSession

__all__ = ["private_bus", "private_session"]

pytestmark = [pytest.mark.integration, pytest.mark.timeout(90)]

# Fictional credentials only.
NORTHWIND_PW = "nw-Fictional-1"
MAIL_PW = "mail-Fictional-2"
EXAMPLE_PW = "ex-Fictional-3"
SEED = "JBSWY3DPEHPK3PXP"
OTPAUTH = f"otpauth://totp/Northwind:alex%40example.com?secret={SEED}&issuer=Northwind"
NOTES = "notes-are-private-too"
NEW_PW = "brand-New-Fictional-4"
SECRETS = (NORTHWIND_PW, MAIL_PW, EXAMPLE_PW, SEED, NOTES, "otpauth")
CANDIDATE_KEYS = {"id", "title", "username", "url", "alt_urls", "has_code"}


@pytest.fixture
def daemon(private_bus: str) -> Iterator[FakeDaemonThread]:
    fake = FakeDaemon(state="idle", apple_id="alex.doe@example.com")
    with FakeDaemonThread(private_bus, fake) as thread:
        yield thread


@pytest.fixture
def ids(daemon: FakeDaemonThread) -> dict[str, str]:
    def seed(d: FakeDaemon) -> dict[str, str]:
        return {
            "northwind": d.add_item(
                "https://northwind.example",
                "alex@example.com",
                NORTHWIND_PW,
                title="Northwind",
                notes=NOTES,
                otpauth=OTPAUTH,
                alt_urls=("https://portal.northwind.example",),
            ),
            "mail": d.add_item(
                "https://mail.northwind.example/login", "alex.mail", MAIL_PW, title="NW Mail"
            ),
            "example": d.add_item("https://example.com", "alex", EXAMPLE_PW, title="Example"),
        }

    return daemon.call(seed)


@pytest.fixture
def host(private_session: PrivateSession) -> Iterator[HostProcess]:
    with HostProcess(private_session.env) as process:
        yield process
    assert process.returncode == 0
    for secret in SECRETS:
        assert secret not in process.stderr


def calls(daemon: FakeDaemonThread) -> list[str]:
    return daemon.call(lambda d: list(d.calls))


# ---------------------------------------------------------------------- status


def test_status(host: HostProcess, ids: dict[str, str]) -> None:
    response = host.request({"id": 1, "cmd": "status"})
    assert response["id"] == 1
    assert result(response) == {"state": "idle", "message": "", "item_count": 3, "protocol": 1}


def test_status_reflects_daemon_state(host: HostProcess, daemon: FakeDaemonThread) -> None:
    daemon.call(lambda d: d.go_offline("No connection to iCloud"))
    status = result(host.request({"id": "s", "cmd": "status"}))
    assert status["state"] == "offline"
    assert status["message"] == "No connection to iCloud"


# ---------------------------------------------------------------------- match


def test_match_returns_only_public_fields(host: HostProcess, ids: dict[str, str]) -> None:
    response = host.request({"id": 2, "cmd": "match", "url": "https://northwind.example/x"})
    items = candidates(response)
    assert len(items) == 2
    for item in items:
        assert set(item) == CANDIDATE_KEYS
    raw = json.dumps(response)
    for secret in SECRETS:
        assert secret not in raw


def test_match_exact_host_first(host: HostProcess, ids: dict[str, str]) -> None:
    items = result(
        host.request({"id": 3, "cmd": "match", "url": "https://mail.northwind.example/"})
    )
    assert items["items"] == [
        {
            "id": ids["mail"],
            "title": "NW Mail",
            "username": "alex.mail",
            "url": "https://mail.northwind.example/login",
            "alt_urls": [],
            "has_code": False,
        },
        {
            "id": ids["northwind"],
            "title": "Northwind",
            "username": "alex@example.com",
            "url": "https://northwind.example",
            "alt_urls": ["https://portal.northwind.example"],
            "has_code": True,
        },
    ]


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com.evil.example/login",
        "http://example.com/login",
        "https://example.com:8443/login",
        "https://example.org/login",
        "https://unrelated.example/",
    ],
)
def test_match_nothing_for_other_sites(host: HostProcess, ids: dict[str, str], url: str) -> None:
    assert result(host.request({"id": 4, "cmd": "match", "url": url})) == {"items": []}


# ---------------------------------------------------------------------- fill


def test_fill_matching_item(host: HostProcess, ids: dict[str, str]) -> None:
    response = host.request(
        {"id": 5, "cmd": "fill", "item_id": ids["example"], "url": "https://www.example.com/in"}
    )
    assert response["id"] == 5
    assert result(response) == {"username": "alex", "password": EXAMPLE_PW}


def test_fill_same_site_item(host: HostProcess, ids: dict[str, str]) -> None:
    response = host.request(
        {
            "id": 6,
            "cmd": "fill",
            "item_id": ids["northwind"],
            "url": "https://mail.northwind.example/",
        }
    )
    assert result(response) == {"username": "alex@example.com", "password": NORTHWIND_PW}


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com.evil.example/login",  # lookalike
        "http://example.com/login",  # https -> http downgrade
        "https://example.com:8443/login",  # different port
        "https://example.org/login",  # different registrable domain
        "https://northwind.example/",  # a real candidate page, but for another item
    ],
)
def test_fill_refused_for_non_matching_url(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str], url: str
) -> None:
    response = host.request({"id": 7, "cmd": "fill", "item_id": ids["example"], "url": url})
    assert response["id"] == 7
    assert error_code(response) == "not-allowed"
    assert EXAMPLE_PW not in json.dumps(response)
    assert "Get" not in calls(daemon)


def test_fill_unknown_item_is_not_allowed(host: HostProcess, ids: dict[str, str]) -> None:
    response = host.request(
        {"id": 8, "cmd": "fill", "item_id": "NO-SUCH-ITEM", "url": "https://example.com/"}
    )
    assert error_code(response) == "not-allowed"


# ---------------------------------------------------------------------- code


def test_code_without_seed(host: HostProcess, ids: dict[str, str]) -> None:
    params = parse_otpauth(OTPAUTH)
    before = datetime.now(UTC)
    response = host.request(
        {"id": 9, "cmd": "code", "item_id": ids["northwind"], "url": "https://northwind.example/"}
    )
    after = datetime.now(UTC)
    value = result(response)
    assert set(value) == {"code", "seconds_left"}
    assert value["code"] in {code_at(params, before)[0], code_at(params, after)[0]}
    assert isinstance(value["seconds_left"], int)
    assert 1 <= value["seconds_left"] <= 30
    assert SEED not in json.dumps(response)


def test_code_for_item_without_code_is_not_found(host: HostProcess, ids: dict[str, str]) -> None:
    response = host.request(
        {"id": 10, "cmd": "code", "item_id": ids["example"], "url": "https://example.com/"}
    )
    assert error_code(response) == "not-found"


@pytest.mark.parametrize(
    "url", ["https://northwind.example.evil.example/", "http://northwind.example/"]
)
def test_code_refused_for_non_matching_url(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str], url: str
) -> None:
    response = host.request({"id": 11, "cmd": "code", "item_id": ids["northwind"], "url": url})
    assert error_code(response) == "not-allowed"
    assert "GetCode" not in calls(daemon)


# ---------------------------------------------------------------------- save


def save(host: HostProcess, rid: int, **fields: object) -> dict[str, object]:
    return host.request({"id": rid, "cmd": "save", **fields})


def stored(daemon: FakeDaemonThread, item_id: str) -> tuple[str, str, str, str | None]:
    def read(d: FakeDaemon) -> tuple[str, str, str, str | None]:
        c = d.items[item_id]
        return c.url, c.username, c.password, c.title

    return daemon.call(read)


def item_count(daemon: FakeDaemonThread) -> int:
    return daemon.call(lambda d: len(d.items))


def test_save_create_reduces_url_to_origin(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str]
) -> None:
    response = save(
        host,
        12,
        url="https://signup.example.com:8443/register?step=2#done",
        username="new.user",
        password=NEW_PW,
        title="Example Signup",
    )
    value = result(response)
    assert value["action"] == "create"
    assert value["saved"] is True
    new_id = value["id"]
    assert isinstance(new_id, str)
    assert new_id not in ids.values()
    assert stored(daemon, new_id) == (
        "https://signup.example.com:8443",
        "new.user",
        NEW_PW,
        "Example Signup",
    )
    assert NEW_PW not in json.dumps(response)


def test_save_create_dry_run_writes_nothing(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str]
) -> None:
    response = save(
        host, 13, url="https://example.com/join", username="someone", password=NEW_PW, dry_run=True
    )
    assert result(response) == {"action": "create", "id": None, "saved": False}
    assert item_count(daemon) == len(ids)
    assert "Save" not in calls(daemon)


def test_save_update_by_username(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str]
) -> None:
    response = save(host, 14, url="https://example.com/login", username="alex", password=NEW_PW)
    assert result(response) == {"action": "update", "id": ids["example"], "saved": True}
    assert stored(daemon, ids["example"]) == ("https://example.com", "alex", NEW_PW, "Example")
    assert item_count(daemon) == len(ids)


def test_save_update_dry_run_writes_nothing(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str]
) -> None:
    response = save(
        host, 15, url="https://example.com/", username="alex", password=NEW_PW, dry_run=True
    )
    assert result(response) == {"action": "update", "id": ids["example"], "saved": False}
    assert stored(daemon, ids["example"])[2] == EXAMPLE_PW
    assert "Save" not in calls(daemon)


@pytest.mark.parametrize("dry_run", [False, True])
def test_save_unchanged_is_none(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str], dry_run: bool
) -> None:
    response = save(
        host, 16, url="https://example.com/", username="alex", password=EXAMPLE_PW, dry_run=dry_run
    )
    assert result(response) == {"action": "none", "id": ids["example"], "saved": False}
    assert "Save" not in calls(daemon)


def test_save_update_by_item_id_changes_username(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str]
) -> None:
    response = save(
        host,
        17,
        url="https://mail.northwind.example/settings",
        item_id=ids["mail"],
        username="alex.renamed",
        password=MAIL_PW,
    )
    assert result(response) == {"action": "update", "id": ids["mail"], "saved": True}
    assert stored(daemon, ids["mail"])[1:3] == ("alex.renamed", MAIL_PW)


def test_save_by_item_id_unchanged_is_none(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str]
) -> None:
    response = save(
        host,
        18,
        url="https://example.com/",
        item_id=ids["example"],
        username="alex",
        password=EXAMPLE_PW,
    )
    assert result(response) == {"action": "none", "id": ids["example"], "saved": False}


@pytest.mark.parametrize("dry_run", [False, True])
def test_save_with_foreign_item_id_is_not_allowed(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str], dry_run: bool
) -> None:
    response = save(
        host,
        19,
        url="https://example.com.evil.example/",
        item_id=ids["example"],
        username="alex",
        password=NEW_PW,
        dry_run=dry_run,
    )
    assert error_code(response) == "not-allowed"
    assert stored(daemon, ids["example"])[2] == EXAMPLE_PW
    assert "Save" not in calls(daemon)


def test_save_username_lookup_ignores_other_sites(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str]
) -> None:
    # "alex" exists for example.com, but this page is example.org: a new item, not an update.
    response = save(host, 20, url="https://example.org/", username="alex", password=NEW_PW)
    value = result(response)
    assert value["action"] == "create"
    assert value["id"] != ids["example"]
    assert stored(daemon, ids["example"])[2] == EXAMPLE_PW


def test_save_without_title_creates_item_without_title(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str]
) -> None:
    value = result(save(host, 21, url="https://new.example/", username="", password=NEW_PW))
    assert isinstance(value["id"], str)
    assert stored(daemon, value["id"]) == ("https://new.example", "", NEW_PW, None)


def test_save_update_prefers_the_best_match_among_duplicates(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str]
) -> None:
    exact = daemon.call(
        lambda d: d.add_item("https://shop.example.com", "alex", "shop-Fictional-5")
    )
    response = save(host, 22, url="https://shop.example.com/cart", username="alex", password=NEW_PW)
    assert result(response) == {"action": "update", "id": exact, "saved": True}
    assert stored(daemon, exact)[2] == NEW_PW
    assert stored(daemon, ids["example"])[2] == EXAMPLE_PW


def test_save_duplicate_already_holding_the_password_is_none(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str]
) -> None:
    daemon.call(lambda d: d.add_item("https://shop.example.com", "alex", "shop-Fictional-5"))
    response = save(host, 23, url="https://shop.example.com/", username="alex", password=EXAMPLE_PW)
    assert result(response) == {"action": "none", "id": ids["example"], "saved": False}


# ---------------------------------------------------------------------- daemon errors


@pytest.mark.parametrize(
    "case",
    [
        ("GetStatus", "Unavailable", "unavailable"),
        ("GetStatus", "AuthRequired", "auth-required"),
        ("Match", "Locked", "locked"),
        ("Match", "Unavailable", "unavailable"),
        ("Get", "NotFound", "not-found"),
        ("Get", "Locked", "locked"),
        ("GetCode", "NotFound", "not-found"),
        ("Save", "Invalid", "invalid"),
        ("Save", "AuthRequired", "auth-required"),
        ("Match", "org.freedesktop.DBus.Error.NoReply", "daemon-unavailable"),
        ("Match", "WrongCode", "internal"),
    ],
    ids="-".join,
)
def test_daemon_errors_are_mapped(
    host: HostProcess, daemon: FakeDaemonThread, ids: dict[str, str], case: tuple[str, str, str]
) -> None:
    method, error, expected = case
    daemon.call(lambda d: d.fail_next(method, error, f"injected secret {NORTHWIND_PW}"))
    requests: dict[str, dict[str, object]] = {
        "GetStatus": {"cmd": "status"},
        "Match": {"cmd": "match", "url": "https://example.com/"},
        "Get": {"cmd": "fill", "item_id": ids["example"], "url": "https://example.com/"},
        "GetCode": {"cmd": "code", "item_id": ids["northwind"], "url": "https://northwind.example"},
        "Save": {"cmd": "save", "url": "https://x.example/", "username": "u", "password": NEW_PW},
    }
    response = host.request({"id": 30, **requests[method]})
    assert response["id"] == 30
    assert error_code(response) == expected
    # The daemon's message is not echoed: only fixed, secret-free texts.
    assert NORTHWIND_PW not in json.dumps(response)
    # The host keeps serving after a daemon error.
    assert result(host.request({"id": 31, "cmd": "status"}))["state"] == "idle"


def test_daemon_absent_then_started(
    private_session: PrivateSession, private_bus: str, host: HostProcess
) -> None:
    response = host.request({"id": 40, "cmd": "status"})
    assert error_code(response) == "daemon-unavailable"
    with FakeDaemonThread(private_bus, FakeDaemon(state="idle")):
        assert result(host.request({"id": 41, "cmd": "status"}))["state"] == "idle"
    assert error_code(host.request({"id": 42, "cmd": "match", "url": "https://a.example"})) == (
        "daemon-unavailable"
    )


def test_unreachable_bus_is_daemon_unavailable(private_session: PrivateSession) -> None:
    env = dict(private_session.env)
    env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={private_session.root}/no-such-bus"
    with HostProcess(env) as process:
        assert error_code(process.request({"id": 43, "cmd": "status"})) == "daemon-unavailable"
    assert process.returncode == 0


# ---------------------------------------------------------------------- framing over the pipe


def test_malformed_frames_interleaved_with_valid_ones(
    host: HostProcess, ids: dict[str, str]
) -> None:
    frames = [
        (b"\xff\xfe", "malformed"),
        (b"[1,2]", "malformed"),
        (b"", "malformed"),
        (b'{"id":44,"cmd":"match","url":"https://example.com/"}', None),
        (
            b'{"id":45,"cmd":"fill","item_id":"x","url":"https://example.com/","extra":1}',
            "bad-request",
        ),
        (b'{"id":46', "malformed"),
        (b'{"id":47,"cmd":"status"}', None),
    ]
    for payload, _ in frames:
        host.send_raw(struct.pack("<I", len(payload)) + payload)
    for payload, expected in frames:
        response = host.receive()
        if expected is None:
            assert response["ok"] is True
            assert response["id"] == json.loads(payload)["id"]
        else:
            assert error_code(response) == expected


def test_oversize_frame_then_valid_frame(host: HostProcess, ids: dict[str, str]) -> None:
    host.send_raw(struct.pack("<I", MAX_PAYLOAD + 1) + b"x" * (MAX_PAYLOAD + 1))
    response = host.receive()
    assert response["id"] is None
    assert error_code(response) == "too-large"
    assert result(host.request({"id": 48, "cmd": "status"}))["item_count"] == 3


def test_eof_exits_zero(host: HostProcess) -> None:
    assert host.close() == 0


def test_eof_mid_frame_exits_zero(host: HostProcess) -> None:
    host.send_raw(struct.pack("<I", 100) + b'{"id":1,')
    assert host.close() == 0
    assert host.proc.stdout is not None


def test_browser_arguments_are_ignored(host: HostProcess, ids: dict[str, str]) -> None:
    # HostProcess passes a Chrome-style origin argument; the host must still serve.
    assert result(host.request({"id": 49, "cmd": "status"}))["protocol"] == 1


# ---------------------------------------------------------------------- timing


@pytest.mark.timeout(60)
async def test_slow_daemon_times_out_then_recovers(
    daemon: FakeDaemonThread, ids: dict[str, str]
) -> None:
    client = DaemonClient(call_timeout=0.3)
    host = Host(client)
    daemon.call(lambda d: setattr(d, "latency", 1.0))
    try:
        started = time.monotonic()
        response = await host.handle(b'{"id":50,"cmd":"status"}')
        assert error_code(response) == "daemon-unavailable"
        assert time.monotonic() - started < 1.0
        daemon.call(lambda d: setattr(d, "latency", 0.0))
        response = await host.handle(b'{"id":51,"cmd":"status"}')
        assert result(response)["state"] == "idle"
    finally:
        await client.close()


@pytest.mark.timeout(60)
async def test_reconnects_after_the_connection_was_closed(
    daemon: FakeDaemonThread, ids: dict[str, str]
) -> None:
    client = DaemonClient()
    host = Host(client)
    try:
        assert result(await host.handle(b'{"id":52,"cmd":"status"}'))["item_count"] == 3
        await client.close()
        assert result(await host.handle(b'{"id":53,"cmd":"status"}'))["item_count"] == 3
    finally:
        await client.close()


@pytest.mark.benchmark
def test_match_latency_budget(host: HostProcess, ids: dict[str, str]) -> None:
    # Warm-up: the first call pays for connecting to the bus.
    result(host.request({"id": 0, "cmd": "match", "url": "https://example.com/"}))
    rounds = 50
    started = time.perf_counter()
    for n in range(rounds):
        response = host.request({"id": n, "cmd": "match", "url": "https://mail.northwind.example/"})
        assert len(candidates(response)) == 2
    average = (time.perf_counter() - started) / rounds
    assert average < 0.05, f"average match round trip {average * 1000:.1f} ms"
