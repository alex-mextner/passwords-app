# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
# These tests seed and inspect the account's session store directly.
# pyright: reportPrivateUsage=false
"""`Account`: the sign-in state machine, the join, unattended refresh, and opening the store.

GrandSlam's SRP exchange is replaced by a scripted Apple (its wire protocol has its own tests);
loginDelegates and get_account_settings are a local plist server, CloudKit is `FakeCloudKit`.
"""

from __future__ import annotations

import plistlib
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Literal, override

import pytest
from tests.fakes.icloud_session import APPLE_ID, DEVICE, make_session

from passwords_app.core.model import Credential
from passwords_app.icloud import account as acct
from passwords_app.icloud.auth import grandslam
from passwords_app.icloud.auth import icloud as icloud_auth
from passwords_app.icloud.auth import session as sess
from passwords_app.icloud.auth.gsa import CodeRejectedError, GSAError
from passwords_app.icloud.escrow.srp import EscrowError, WrongEscrowPasscodeError
from passwords_app.icloud.octagon import client as octagon
from passwords_app.icloud.values import Record, child
from passwords_app.sync.ports import AuthRequired

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from tests.fakes.cloudkit_server import FakeCloudKit

FAKE_PASSWORD = "FAKE-PASSWORD-FOR-TESTS"
FAKE_CK = "FAKE-CK-VALUE"
FAKE_PET = "FAKE-PET-VALUE"


class Setup:
    """loginDelegates + get_account_settings, answering plists."""

    def __init__(self) -> None:
        self.settings_status = 200
        self.login_status = 0
        self.ck_token = FAKE_CK
        self.calls: list[str] = []
        self.gateway = ""
        self.expire_next_settings = 0
        # When set, get_account_settings answers 401 to any other X-Mme-Client-Info.
        self.accept_only_client_info: str | None = None
        self.settings_client_infos: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            disable_nagle_algorithm = True
            server_version = "FakeSetup"

            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.calls.append(self.path)
                status, body = outer.answer(self.path, self.headers.get("X-Mme-Client-Info", ""))
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            @override
            def log_message(self, format: str, *args: object) -> None:
                del format, args

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host!s}:{port}"

    def answer(self, path: str, client_info: str) -> tuple[int, bytes]:
        if path == "/login":
            mm = {
                "status": self.login_status,
                "service-data": {"tokens": {"mmeAuthToken": "FAKE-MME"}},
            }
            return 200, plistlib.dumps(
                {"dsid": "1234567890", "delegates": {"com.apple.mobileme": mm}}
            )
        self.settings_client_infos.append(client_info)
        if self.accept_only_client_info not in {None, client_info}:
            return 401, b""
        if self.expire_next_settings:
            self.expire_next_settings -= 1
            return 401, plistlib.dumps({"ErrorID": "UNAUTHORIZED"})
        if self.settings_status != 200:
            return self.settings_status, plistlib.dumps({"ErrorID": "UNAUTHORIZED"})
        services = {
            "keychainsync": {"url": "https://escrow.invalid"},
            "gateway": {"url": self.gateway},
        }
        return 200, plistlib.dumps(
            {"webservices": services, "tokens": {"cloudKitToken": self.ck_token}}
        )


class ScriptedApple:
    """Stands in for GrandSlam: password check, optional second factor, PET."""

    def __init__(self) -> None:
        self.second_factor: str | None = None
        self.code = "123456"
        self.triggered: list[str] = []
        self.starts = 0

    @staticmethod
    def spd() -> Record:
        return {
            "adsid": "000-adsid",
            "DsPrsId": 1234567890,
            "t": {"com.apple.gs.idms.pet": {"token": FAKE_PET, "expiry": 1}},
        }

    def start(
        self, gsa: object, username: str, password: str
    ) -> tuple[Record, grandslam.SecondFactor | None]:
        del gsa
        self.starts += 1
        if password != FAKE_PASSWORD:
            msg = "wrong password"
            raise GSAError(msg)
        if self.second_factor is None:
            return self.spd(), None
        kind: Literal["trusted", "sms"] = "trusted" if self.second_factor == "trusted" else "sms"
        return self.spd(), grandslam.SecondFactor(kind, username, "idms")

    def trigger(self, gsa: object, factor: grandslam.SecondFactor) -> None:
        del gsa
        self.triggered.append(factor.kind)

    def finish(
        self, gsa: object, username: str, password: str, factor: grandslam.SecondFactor, code: str
    ) -> Record:
        del gsa, username, password, factor
        if code != self.code:
            msg = "code rejected"
            raise CodeRejectedError(msg)
        self.second_factor = None
        return self.spd()


class NoAnisette:
    def headers(self) -> dict[str, str]:
        return {"X-Apple-I-MD": "md", "X-Apple-I-MD-M": "m"}


@pytest.fixture(autouse=True)
def _fresh_key_cache(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(sess, "_default_collection", lambda: None)
    sess.forget_cached_keys()
    yield
    sess.forget_cached_keys()


@pytest.fixture
def setup_server() -> Iterator[Setup]:
    server = Setup()
    yield server
    server.server.shutdown()
    server.server.server_close()


@pytest.fixture
def apple(monkeypatch: pytest.MonkeyPatch) -> ScriptedApple:
    scripted = ScriptedApple()
    monkeypatch.setattr(grandslam, "start", scripted.start)
    monkeypatch.setattr(grandslam, "trigger", scripted.trigger)
    monkeypatch.setattr(grandslam, "finish", scripted.finish)
    return scripted


@pytest.fixture
def account(tmp_path: Path, setup_server: Setup) -> acct.Account:
    endpoints = acct.Endpoints(
        gsa="https://gsa.invalid",
        login_delegates=f"{setup_server.url}/login",
        account_settings=f"{setup_server.url}/settings",
    )
    return acct.Account(tmp_path / "cfg", anisette=NoAnisette(), endpoints=endpoints)


def _record(account: acct.Account) -> Record:
    record = account._sessions.load()
    assert record is not None
    return record


def _ck_token(record: Record) -> object:
    return child(child(record, "mme"), "tokens").get("cloudKitToken")


# --- status ------------------------------------------------------------------------------------


def test_fresh_computer_is_signed_out(account: acct.Account) -> None:
    assert account.status() == acct.AccountStatus(apple_id=None, signed_in=False, joined=False)


def test_session_the_key_cannot_open_is_signed_out(account: acct.Account) -> None:
    # The keyring was replaced since the session was saved: the file is there but unreadable.
    account.paths.ensure()
    account.paths.session.write_bytes(bytes(range(64)))
    assert account.status() == acct.AccountStatus(apple_id=None, signed_in=False, joined=False)
    with pytest.raises(acct.SignInRequired):
        account.open_keychain()


def test_default_config_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert acct.Account(anisette=NoAnisette()).paths.root == tmp_path / "passwords-app"


def test_sign_in_step_values() -> None:
    assert [s.value for s in acct.SignInStep] == ["code", "device", "done"]


# --- sign-in -----------------------------------------------------------------------------------


def test_sign_in_without_second_factor_needs_a_device(
    account: acct.Account, apple: ScriptedApple
) -> None:
    assert account.sign_in(APPLE_ID, FAKE_PASSWORD) is acct.SignInStep.DEVICE
    assert account.status() == acct.AccountStatus(APPLE_ID, signed_in=True, joined=False)
    record = _record(account)
    assert record["password"] == FAKE_PASSWORD
    assert child(record, "webservices")["keychainsync"] == "https://escrow.invalid"
    assert _ck_token(record) == FAKE_CK
    assert apple.triggered == []


def test_second_factor_code_flow(account: acct.Account, apple: ScriptedApple) -> None:
    apple.second_factor = "trusted"
    assert account.sign_in(APPLE_ID, FAKE_PASSWORD) is acct.SignInStep.CODE
    assert apple.triggered == ["trusted"]
    assert account.status().signed_in is False
    with pytest.raises(acct.WrongCode):
        account.submit_code("000000")
    assert account.submit_code(" 123456 ") is acct.SignInStep.DEVICE
    assert account.status().signed_in


def test_code_can_be_sent_by_text_message(account: acct.Account, apple: ScriptedApple) -> None:
    apple.second_factor = "trusted"
    account.sign_in(APPLE_ID, FAKE_PASSWORD)
    assert account.request_sms() is acct.SignInStep.CODE
    assert apple.triggered == ["trusted", "sms"]
    assert account.submit_code("123456") is acct.SignInStep.DEVICE


@pytest.mark.parametrize("step", ["submit_code", "request_sms"])
def test_code_steps_need_a_pending_sign_in(account: acct.Account, step: str) -> None:
    def act() -> object:
        return account.submit_code("1") if step == "submit_code" else account.request_sms()

    with pytest.raises(acct.AccountError, match="waiting for a code"):
        act()


def test_wrong_password_saves_nothing(account: acct.Account, apple: ScriptedApple) -> None:
    del apple
    with pytest.raises(acct.AccountError, match="wrong password"):
        account.sign_in(APPLE_ID, "nope")
    assert account.status().signed_in is False


def test_login_delegates_failure_is_an_account_error(
    account: acct.Account, apple: ScriptedApple, setup_server: Setup
) -> None:
    del apple
    setup_server.login_status = 1
    with pytest.raises(acct.AccountError, match="loginDelegates"):
        account.sign_in(APPLE_ID, FAKE_PASSWORD)
    assert account.status().signed_in is False


def test_pushed_code_is_asked_for_when_login_delegates_refuses_the_pet(
    account: acct.Account,
    apple: ScriptedApple,
    setup_server: Setup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows-identity GSA: SRP passes without `au`, a code is pushed, loginDelegates says 1."""
    spd_with_idms = {**ScriptedApple.spd(), "GsIdmsToken": "idms"}
    monkeypatch.setattr(ScriptedApple, "spd", staticmethod(lambda: spd_with_idms))
    setup_server.login_status = 1
    assert account.sign_in(APPLE_ID, FAKE_PASSWORD) is acct.SignInStep.CODE
    assert apple.triggered == []  # Apple already pushed it: do not send a second, competing code
    assert account.status().signed_in is False
    setup_server.login_status = 0
    assert account.submit_code("123456") is acct.SignInStep.DEVICE
    assert account.status().signed_in


@pytest.mark.parametrize(
    "refusal",
    [(2, "idms"), (1, None)],
    ids=["other-status", "no-idms-token-to-answer-with"],
)
def test_login_delegates_refusal_without_a_pushed_code_stays_an_error(
    account: acct.Account,
    apple: ScriptedApple,
    setup_server: Setup,
    monkeypatch: pytest.MonkeyPatch,
    refusal: tuple[int, str | None],
) -> None:
    del apple
    login_status, idms = refusal
    spd = {**ScriptedApple.spd(), **({"GsIdmsToken": idms} if idms else {})}
    monkeypatch.setattr(ScriptedApple, "spd", staticmethod(lambda: spd))
    setup_server.login_status = login_status
    with pytest.raises(acct.AccountError):
        account.sign_in(APPLE_ID, FAKE_PASSWORD)
    assert account.status().signed_in is False


@pytest.mark.parametrize(
    ("accepted", "requests_made"),
    [
        (icloud_auth.LOGIN_DELEGATES_CLIENT_INFO, 1),
        (icloud_auth.ICLOUD_CLIENT_INFO, 2),
    ],
    ids=["windows-identity", "mac-identity"],
)
def test_sign_in_finishes_under_whichever_identity_get_account_settings_accepts(
    account: acct.Account,
    apple: ScriptedApple,
    setup_server: Setup,
    accepted: str,
    requests_made: int,
) -> None:
    """A token minted under the Windows identity is asked for as a Windows client first, so a
    fresh sign-in needs one request; a Mac-minted token saved by an old version needs a retry."""
    del apple
    setup_server.accept_only_client_info = accepted
    assert account.sign_in(APPLE_ID, FAKE_PASSWORD) is acct.SignInStep.DEVICE
    assert account.status().signed_in
    assert setup_server.settings_client_infos[-1] == accepted
    assert len(setup_server.settings_client_infos) == requests_made


def test_sign_in_names_the_refusal_when_no_identity_is_accepted(
    account: acct.Account, apple: ScriptedApple, setup_server: Setup
) -> None:
    """A token minted seconds ago is not 'expired': say that Apple refused it, and how."""
    del apple
    setup_server.settings_status = 401
    with pytest.raises(acct.AccountError) as raised:
        account.sign_in(APPLE_ID, FAKE_PASSWORD)
    message = str(raised.value)
    assert "HTTP 401" in message
    assert "Windows" in message
    assert "Mac" in message
    assert "expired" not in message
    assert account.status().signed_in is False
    assert setup_server.settings_client_infos == [
        icloud_auth.LOGIN_DELEGATES_CLIENT_INFO,
        icloud_auth.ICLOUD_CLIENT_INFO,
    ]


def test_re_sign_in_keeps_the_keychain_identity(
    account: acct.Account, apple: ScriptedApple
) -> None:
    del apple
    account.sign_in(APPLE_ID, FAKE_PASSWORD)
    record = _record(account)
    oct_state = octagon.ensure_peer_identity(record, DEVICE)
    oct_state["joined"] = True
    record["octagon"] = oct_state
    account._sessions.save(record)
    assert account.sign_in(APPLE_ID, FAKE_PASSWORD) is acct.SignInStep.DONE
    assert _record(account)["octagon"] == record["octagon"]


def test_another_apple_id_starts_without_the_old_identity(
    account: acct.Account, apple: ScriptedApple
) -> None:
    del apple
    account.sign_in(APPLE_ID, FAKE_PASSWORD)
    record = _record(account)
    record["octagon"] = {"peer_id": "SHA256:old", "joined": True}
    account._sessions.save(record)
    assert account.sign_in("someone.else@example.com", FAKE_PASSWORD) is acct.SignInStep.DEVICE
    assert "octagon" not in _record(account)


def test_sign_out_forgets_the_session_but_not_the_device(
    account: acct.Account, apple: ScriptedApple
) -> None:
    del apple
    account.sign_in(APPLE_ID, FAKE_PASSWORD)
    account.paths.zone_cache.write_text("{}")
    account.sign_out()
    assert account.status().signed_in is False
    assert not account.paths.zone_cache.exists()
    assert account.paths.device.exists()


# --- unattended refresh --------------------------------------------------------------------------


def test_refresh_renews_the_cloudkit_token(
    account: acct.Account, apple: ScriptedApple, setup_server: Setup
) -> None:
    account.sign_in(APPLE_ID, FAKE_PASSWORD)
    setup_server.ck_token = "RENEWED"
    record = _record(account)
    account.refresh_tokens(record)
    assert _ck_token(record) == "RENEWED"
    assert apple.starts == 1  # no new password sign-in was needed


def test_expired_token_is_re_minted_with_the_saved_password(
    account: acct.Account, apple: ScriptedApple, setup_server: Setup
) -> None:
    account.sign_in(APPLE_ID, FAKE_PASSWORD)
    record = _record(account)
    setup_server.expire_next_settings = 2  # Apple refuses the token under both identities
    account.refresh_tokens(record)
    assert apple.starts == 2
    assert setup_server.calls.count("/login") == 2


def test_expired_token_without_saved_password_needs_sign_in(
    account: acct.Account, apple: ScriptedApple, setup_server: Setup
) -> None:
    del apple
    account.sign_in(APPLE_ID, FAKE_PASSWORD)
    record = _record(account)
    del record["password"]
    setup_server.settings_status = 401
    with pytest.raises(acct.SignInRequired):
        account.refresh_tokens(record)


def test_unattended_refresh_never_pushes_a_code(
    account: acct.Account, apple: ScriptedApple, setup_server: Setup
) -> None:
    account.sign_in(APPLE_ID, FAKE_PASSWORD)
    apple.second_factor = "trusted"
    setup_server.settings_status = 401
    with pytest.raises(acct.SignInRequired, match="verification code"):
        account.refresh_tokens(_record(account))
    assert apple.triggered == []


def test_changed_password_needs_sign_in(
    account: acct.Account, apple: ScriptedApple, setup_server: Setup
) -> None:
    del apple
    account.sign_in(APPLE_ID, FAKE_PASSWORD)
    record = _record(account)
    record["password"] = "changed on another device"
    setup_server.settings_status = 401
    with pytest.raises(acct.SignInRequired):
        account.refresh_tokens(record)


# --- joining -------------------------------------------------------------------------------------

BOTTLES: list[Record] = [
    {
        "id": "bottle-1",
        "otbottle": b"x",
        "meta": {
            "serial": "F2LX",
            "ClientMetadata": {"device_name": "Alice's iPhone", "device_model": "iPhone 15"},
        },
    },
    {"id": "bottle-2", "otbottle": b"y", "meta": {}},
]


@pytest.fixture
def signed_in(
    account: acct.Account, apple: ScriptedApple, monkeypatch: pytest.MonkeyPatch
) -> acct.Account:
    del apple
    account.sign_in(APPLE_ID, FAKE_PASSWORD)
    record = _record(account)
    mme = child(record, "mme")
    mme["cloudKitUserId"] = "_u"
    record["mme"] = mme
    account._sessions.save(record)

    def no_bottles_listed(*_a: object, **_k: object) -> list[Record]:
        return BOTTLES

    monkeypatch.setattr(octagon.OctagonClient, "list_recoverable_bottles", no_bottles_listed)
    return account


def test_recovery_devices_are_described(signed_in: acct.Account) -> None:
    assert signed_in.recovery_devices() == [
        acct.RecoveryDevice("bottle-1", "Alice's iPhone", "iPhone 15", "F2LX"),
        acct.RecoveryDevice("bottle-2", "Apple device", "", ""),
    ]
    assert "octagon" in _record(signed_in)  # the peer identity exists before any attempt


def test_join_with_the_right_passcode(
    signed_in: acct.Account, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, object] = {}

    def join(  # noqa: PLR0913, PLR0917 - mirrors OctagonClient.join_via_escrow
        self: octagon.OctagonClient,
        host: str,
        email: str,
        pet: str,
        passcode: bytes,
        chosen: Record,
        *,
        confirm_irreversible: bool,
    ) -> str:
        seen.update(host=host, email=email, pet=pet, passcode=passcode, chosen=chosen["id"])
        seen["confirm"] = confirm_irreversible
        oct_state = child(self.record, "octagon")
        oct_state["joined"] = True
        self.record["octagon"] = oct_state
        return "SHA256:sponsor"

    monkeypatch.setattr(octagon.OctagonClient, "join_via_escrow", join)
    signed_in.recovery_devices()
    assert signed_in.join("bottle-1", "1234") is acct.SignInStep.DONE
    assert seen == {
        "host": "https://escrow.invalid",
        "email": APPLE_ID,
        "pet": FAKE_PET,
        "passcode": b"1234",
        "chosen": "bottle-1",
        "confirm": True,
    }
    assert signed_in.status().joined


def test_wrong_passcode(signed_in: acct.Account, monkeypatch: pytest.MonkeyPatch) -> None:
    def join(*_a: object, **_k: object) -> str:
        msg = "the passcode was not accepted"
        raise WrongEscrowPasscodeError(msg)

    monkeypatch.setattr(octagon.OctagonClient, "join_via_escrow", join)
    signed_in.recovery_devices()
    with pytest.raises(acct.WrongPasscode):
        signed_in.join("bottle-1", "0000")
    assert not signed_in.status().joined


def test_escrow_outage_is_an_account_error(
    signed_in: acct.Account, monkeypatch: pytest.MonkeyPatch
) -> None:
    def join(*_a: object, **_k: object) -> str:
        msg = "escrowproxy/recover returned HTTP 503"
        raise EscrowError(msg)

    monkeypatch.setattr(octagon.OctagonClient, "join_via_escrow", join)
    signed_in.recovery_devices()
    with pytest.raises(acct.AccountError) as info:
        signed_in.join("bottle-1", "0000")
    assert not isinstance(info.value, acct.WrongPasscode)


def test_join_needs_a_listed_device_and_a_passcode(signed_in: acct.Account) -> None:
    with pytest.raises(acct.AccountError, match="unknown device"):
        signed_in.join("bottle-1", "1234")
    signed_in.recovery_devices()
    with pytest.raises(acct.AccountError, match="empty"):
        signed_in.join("bottle-1", "")


def test_join_steps_need_a_sign_in(account: acct.Account) -> None:
    with pytest.raises(acct.SignInRequired):
        account.recovery_devices()
    with pytest.raises(acct.SignInRequired):
        account.join("bottle-1", "1234")


# --- opening the store -------------------------------------------------------------------------


@pytest.fixture
def joined(account: acct.Account, fake: FakeCloudKit, setup_server: Setup) -> acct.Account:
    setup_server.gateway = fake.url
    setup_server.ck_token = fake.token
    account.paths.ensure()
    DEVICE.save(account.paths.device)
    account._sessions.save(make_session(fake))
    return account


def test_open_keychain_needs_a_join(account: acct.Account, apple: ScriptedApple) -> None:
    del apple
    account.sign_in(APPLE_ID, FAKE_PASSWORD)
    with pytest.raises(acct.SignInRequired, match="joined"):
        account.open_keychain()


def test_open_keychain_needs_a_sign_in(account: acct.Account) -> None:
    with pytest.raises(acct.SignInRequired):
        account.open_keychain()


async def test_remote_store_reads_the_joined_keychain(
    joined: acct.Account, fake: FakeCloudKit
) -> None:
    t = datetime(2024, 1, 1, tzinfo=UTC)
    cred = Credential("00000000-0000-4000-8000-000000000001", "https://a.example", "u", "p", t, t)
    fake.put_login(cred)
    snap = await joined.remote_store().fetch()
    assert snap.items[cred.id].credential.password == "p"
    assert joined.paths.zone_cache.exists()


async def test_open_store_needs_sign_in_after_sign_out(joined: acct.Account) -> None:
    store = joined.remote_store()
    await store.fetch()
    joined.sign_out()
    with pytest.raises(AuthRequired):
        await store.fetch()


async def test_remote_store_needing_sign_in_is_auth_required(
    joined: acct.Account, setup_server: Setup
) -> None:
    record = _record(joined)
    del record["password"]
    joined._sessions.save(record)
    setup_server.settings_status = 401
    with pytest.raises(AuthRequired):
        await joined.remote_store().fetch()


def test_status_reads_a_session_from_earlier_versions(joined: acct.Account) -> None:
    assert joined.status() == acct.AccountStatus(APPLE_ID, signed_in=True, joined=True)
