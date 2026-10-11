# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Every Apple call turns transport and parse failures into its module's error.

Callers only catch the package's own exceptions, so a raw `requests.Timeout`, a plistlib error
or an `IndexError` on an empty body would escape as a crash instead of a status the daemon can
report. The fake session answers each request with a canned response.
"""

# pyright: reportPrivateUsage=false
# The GSA request primitive is exercised directly: it is where every GSA call maps errors.

from __future__ import annotations

import base64
import gzip
import json
import plistlib
from typing import TYPE_CHECKING, Any, override

import pytest
import requests

from passwords_app.icloud.auth import icloud
from passwords_app.icloud.auth.anisette import REUSE_SECONDS, Anisette, AnisetteError
from passwords_app.icloud.auth.gsa import GSAClient, GSAError
from passwords_app.icloud.escrow.srp import (
    EscrowError,
    EscrowGateError,
    EscrowRecovery,
    KeyVaultMessage,
    WrongEscrowPasscodeError,
)
from passwords_app.icloud.proto import codec
from passwords_app.icloud.proto.codec import Writer
from passwords_app.icloud.transport import ckks, cloudkit
from passwords_app.icloud.transport.cloudkit import CloudKitError, CloudKitTransport, DeviceConfig

if TYPE_CHECKING:
    from collections.abc import Mapping


def _response(content: bytes, status: int = 200, content_type: str = "") -> requests.Response:
    resp = requests.Response()
    resp._content = content
    resp.status_code = status
    if content_type:
        resp.headers["Content-Type"] = content_type
    return resp


class _Http(requests.Session):
    """Replays `answers` in order (an exception instance is raised instead of returned)."""

    def __init__(self, *answers: requests.Response | Exception) -> None:
        super().__init__()
        self.answers = list(answers)
        self.calls: list[dict[str, Any]] = []

    @override
    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:  # type: ignore[override]
        self.calls.append({"method": method, "url": url, **kwargs})
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


class _Device:
    device_id = "DEVICE"
    serial = "C02TEST"
    local_user_uuid = "LOCAL"

    def meta_headers(self) -> dict[str, str]:
        return {}


class _Anisette:
    def headers(self) -> dict[str, str]:
        return {"X-Apple-I-MD": "otp", "X-Apple-I-MD-M": "machine"}


def _plist(value: Mapping[str, object] | list[object], status: int = 200) -> requests.Response:
    return _response(plistlib.dumps(value), status, "text/x-xml-plist")


# A plist cut off mid-transfer: plistlib hands this to expat, whose error is not a ValueError.
_TRUNCATED_XML = b'<?xml version="1.0"?><plist><dict>'


# ---------------------------------------------------------------- GSA 2FA


def _gsa(http: _Http) -> GSAClient:
    return GSAClient(_Device(), _Anisette(), http=http)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (_plist({"ec": -21669, "em": "Incorrect verification code."}), "Incorrect verification"),
        (_response(b"", 401), "401"),
        (_response(b"<html/>", 500, "text/html"), "500"),
        (requests.ConnectionError("reset"), "request failed: reset"),
        (_response(_TRUNCATED_XML, 200, "text/x-xml-plist"), "200"),
    ],
    ids=["wrong-code", "token-rejected", "server-error", "transport", "truncated-xml"],
)
@pytest.mark.parametrize("kind", ["trusted", "sms"])
def test_rejected_or_failed_2fa_submit_raises_gsa_error(
    answer: requests.Response | Exception, message: str, kind: str
) -> None:
    client = _gsa(_Http(answer))
    submit = client.submit_trusted_factor if kind == "trusted" else client.submit_sms_factor
    with pytest.raises(GSAError, match=message):
        submit("123456", "1", "idms")


@pytest.mark.parametrize("kind", ["trusted", "sms"])
def test_accepted_2fa_code_returns_quietly(kind: str) -> None:
    http = _Http(_plist({"ec": 0}))
    client = _gsa(http)
    if kind == "trusted":
        client.submit_trusted_factor("123456", "1", "idms")
        assert http.calls[0]["headers"]["security-code"] == "123456"
    else:
        client.submit_sms_factor("654321", "1", "idms")
        assert http.calls[0]["json"]["securityCode"] == {"code": "654321"}


@pytest.mark.parametrize("trigger", ["trigger_trusted_factor", "trigger_sms_factor"])
def test_2fa_trigger_transport_failure_is_gsa_error(trigger: str) -> None:
    client = _gsa(_Http(requests.Timeout("slow")))
    with pytest.raises(GSAError, match="trigger request failed: slow"):
        getattr(client, trigger)("1", "idms")


def test_every_gsa_call_pins_the_apple_bundle() -> None:
    from passwords_app.icloud import tls  # noqa: PLC0415

    http = _Http(_plist({"Response": {}}), _response(b""), _plist({"ec": 0}))
    client = _gsa(http)
    client._request({"o": "init"})
    client.trigger_trusted_factor("1", "idms")
    client.submit_trusted_factor("1", "1", "idms")
    assert [call["verify"] for call in http.calls] == [tls.apple_ca_bundle()] * 3
    assert all(call["url"].startswith("https://gsa.apple.com/") for call in http.calls)


# ---------------------------------------------------------------- setup.icloud.com

_DELEGATES_OK = {
    "dsid": "1234",
    "delegates": {
        "com.apple.mobileme": {
            "status": 0,
            "service-data": {"tokens": {"mmeAuthToken": "mme", "cloudKitToken": "ck"}},
        }
    },
}


def _login(http: _Http) -> tuple[str, str, dict[str, Any], dict[str, Any]]:
    return icloud.login_mobileme(
        "user@example.invalid",
        "pet",
        "adsid",
        "client",
        _Device(),  # type: ignore[arg-type]
        _Anisette(),
        http=http,
    )


def test_login_mobileme_returns_dsid_token_and_service_data() -> None:
    dsid, token, service, raw = _login(_Http(_plist(_DELEGATES_OK)))
    assert (dsid, token) == ("1234", "mme")
    assert service["tokens"]["cloudKitToken"] == "ck"
    assert raw == _DELEGATES_OK


def test_login_mobileme_authenticates_with_apple_id_and_pet() -> None:
    import base64  # noqa: PLC0415

    http = _Http(_plist(_DELEGATES_OK))
    _login(http)
    expected = "Basic " + base64.b64encode(b"user@example.invalid:pet").decode()
    assert http.calls[0]["headers"]["Authorization"] == expected
    assert http.calls[0]["headers"]["X-Apple-ADSID"] == "adsid"


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (requests.ConnectionError("down"), "loginDelegates request failed: down"),
        (_response(b"<html>busy</html>", 503, "text/html"), "HTTP 503 without a plist"),
        (_plist(["list"]), "non-dictionary plist"),
        (
            _plist({"delegates": {"com.apple.mobileme": {"status": 1, "status-message": "no"}}}),
            "loginDelegates status 1: no",
        ),
        (
            _plist({"delegates": {"com.apple.mobileme": {"status": 0, "service-data": {}}}}),
            "without a dsid and mmeAuthToken",
        ),
        (_plist({"status": 0}), "without a dsid and mmeAuthToken"),
    ],
    ids=["transport", "html", "list", "status", "no-token", "no-delegates"],
)
def test_login_mobileme_failures_are_icloud_errors(
    answer: requests.Response | Exception, message: str
) -> None:
    with pytest.raises(icloud.ICloudError, match=message):
        _login(_Http(answer))


def _settings(http: _Http, record: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    return icloud.fetch_account_settings(
        record if record is not None else {"mme": {"dsid": "1", "mmeAuthToken": "t"}},
        _Device(),  # type: ignore[arg-type]
        _Anisette(),
        http=http,
    )


def test_account_settings_returns_status_and_plist() -> None:
    assert _settings(_Http(_plist({"status": 0, "x": 1}, 200))) == (200, {"status": 0, "x": 1})


def test_account_settings_keeps_a_401_plist_for_the_caller() -> None:
    assert _settings(_Http(_plist({"ErrorID": "UNAUTHORIZED"}, 401)))[0] == 401


@pytest.mark.parametrize(
    "record", [{}, {"mme": {"dsid": "1"}}, {"mme": {"mmeAuthToken": "t"}}], ids=str
)
def test_account_settings_without_stored_token_never_calls_out(record: dict[str, Any]) -> None:
    http = _Http()
    with pytest.raises(icloud.ICloudError, match="no mmeAuthToken stored"):
        _settings(http, record)
    assert http.calls == []


@pytest.mark.parametrize(
    "answer",
    [
        requests.Timeout("t"),
        _response(b"", 502),
        _response(b"garbage", 200),
        _response(_TRUNCATED_XML, 200),
    ],
    ids=["timeout", "empty-502", "garbage", "truncated-xml"],
)
def test_account_settings_failures_are_icloud_errors(answer: requests.Response | Exception) -> None:
    with pytest.raises(icloud.ICloudError):
        _settings(_Http(answer))


def test_account_settings_reports_a_bodiless_401_so_the_caller_can_reauthenticate() -> None:
    # Account.refresh_tokens re-mints the token only on a recognised 401; failing on the empty
    # body here would turn an expired token into a hard error.
    assert _settings(_Http(_response(b"", 401))) == (401, {})


# ---------------------------------------------------------------- CloudKit


def _ck_ok(fields: Writer | None = None) -> requests.Response:
    op = Writer().message(3, Writer().uint64(1, cloudkit.RESULT_SUCCESS))
    if fields is not None:
        op.message(213, fields)
    return _response(gzip.compress(cloudkit.delimit(op.finish())))


def _transport(http: _Http) -> CloudKitTransport:
    return CloudKitTransport("ck", "_user", DeviceConfig("DEV", "C02"), _Anisette(), http=http)


def test_fetch_records_returns_the_retrieve_changes_payload() -> None:
    payload = Writer().bytes(2, b"token")
    assert _transport(_Http(_ck_ok(payload))).fetch_records(b"") == payload.finish()


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (requests.ConnectionError("reset"), "network error"),
        (_response(b"<html>", 503), "HTTP 503"),
        (_response(b"", 401), "HTTP 401"),
        (_response(b""), "no response operation"),
        (_response(b"\xff"), "undecodable body"),
        (_response(b"\x05ab"), "undecodable body"),
        (_response(gzip.compress(b"\x05ab")), "undecodable body"),
        (_response(cloudkit.delimit(b"\x0a\x09short")), "malformed response operation"),
    ],
    ids=[
        "transport",
        "503",
        "401",
        "empty",
        "truncated-varint",
        "short-frame",
        "gzip-short-frame",
        "bad-proto",
    ],
)
def test_cloudkit_failures_are_cloudkit_errors(
    answer: requests.Response | Exception, message: str
) -> None:
    with pytest.raises(CloudKitError, match=message):
        _transport(_Http(answer)).fetch_records(b"")


def test_cloudkit_http_failure_carries_the_status() -> None:
    with pytest.raises(CloudKitError) as info:
        _transport(_Http(_response(b"", 421))).fetch_records(b"")
    assert info.value.http_status == 421


def test_cloudkit_result_failure_carries_code_and_description() -> None:
    error = Writer().string(4, "zone not found")
    op = Writer().message(3, Writer().uint64(1, 3).message(2, error)).finish()
    with pytest.raises(CloudKitError, match="zone not found") as info:
        _transport(_Http(_response(cloudkit.delimit(op)))).fetch_records(b"")
    assert info.value.code == 3
    assert info.value.description == "zone not found"


def test_explicit_zero_result_code_is_a_failure_not_success() -> None:
    # Only an absent code defaults to success; an explicit 0 with a stale-record error must
    # stay a conflict so a write never silently overwrites another device's edit.
    raw = cloudkit.build_response_operation(
        "U", 210, code=0, client_error=cloudkit.CLIENT_STALE_RECORD_UPDATE, description="stale"
    )
    result = cloudkit.parse_response_operation(raw)
    assert not result.ok
    assert result.conflict


def test_cloudkit_requests_go_to_the_configured_gateway() -> None:
    http = _Http(_ck_ok())
    transport = CloudKitTransport(
        "ck", "_user", DeviceConfig("DEV", "C02"), _Anisette(), http=http, gateway="http://x/"
    )
    transport.fetch_records(b"")
    assert http.calls[0]["url"] == "http://x/ckdatabase/api/client/record/sync"
    assert http.calls[0]["headers"]["x-cloudkit-authtoken"] == "ck"


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (requests.ConnectionError("x"), "network error"),
        (_response(b"", 401), "HTTP 401"),
        (_response(b"not json", 200), "without a cloudKitUserId"),
        (_response(json.dumps({"other": 1}).encode(), 200), "without a cloudKitUserId"),
        (_response(json.dumps([1]).encode(), 200), "without a cloudKitUserId"),
        (_response(json.dumps({"cloudKitUserId": ""}).encode(), 200), "empty cloudKitUserId"),
    ],
    ids=["transport", "401", "not-json", "missing", "list", "empty"],
)
def test_ck_app_init_failures_are_cloudkit_errors(
    answer: requests.Response | Exception, message: str
) -> None:
    with pytest.raises(CloudKitError, match=message):
        cloudkit.ck_app_init("c", "b", "1", "t", _Anisette(), http=_Http(answer))


# ---------------------------------------------------------------- escrowproxy


def _escrow(http: _Http) -> EscrowRecovery:
    return EscrowRecovery("https://escrow.invalid", "e", "pet", _Anisette(), http=http)


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (requests.Timeout("slow"), "request failed: slow"),
        (_response(b"", 500), "HTTP 500"),
        (_response(b"<html/>", 200), "not a plist"),
        (_plist([1]), "non-dictionary"),
        (_response(_TRUNCATED_XML, 200), "not a plist"),
    ],
    ids=["transport", "500", "html", "list", "truncated-xml"],
)
def test_escrow_failures_are_escrow_errors_not_consent_errors(
    answer: requests.Response | Exception, message: str
) -> None:
    with pytest.raises(EscrowError, match=message) as info:
        _escrow(_Http(answer)).list_records()
    assert not isinstance(info.value, EscrowGateError)


def _srp_init_answer() -> requests.Response:
    # Header, then identifier, salt and server public value B; B=2 is enough to reach the
    # recover POST, whose answer is what these tests vary.
    message = KeyVaultMessage(bytes(24))
    for section in (b"id", b"salt", b"\x02"):
        message.section(section)
    blob = base64.b64encode(message.pack()).decode()
    return _plist({"dsid": "123", "respBlob": blob})


@pytest.mark.parametrize("status", [401, 403, 429])
def test_recover_auth_or_throttle_failure_is_not_a_wrong_passcode(status: int) -> None:
    # Calling these a wrong passcode would send the user to retype a correct passcode and
    # burn one of the ~10 escrow attempts on the next try.
    recovery = _escrow(_Http(_srp_init_answer(), _response(b"", status)))
    with pytest.raises(EscrowError) as info:
        recovery.try_recover_escrow("record", b"123456", confirm_irreversible=True)
    assert not isinstance(info.value, WrongEscrowPasscodeError)
    assert info.value.http_status == status


def test_recover_rejected_proof_is_a_wrong_passcode() -> None:
    recovery = _escrow(_Http(_srp_init_answer(), _response(b"", 400)))
    with pytest.raises(WrongEscrowPasscodeError):
        recovery.try_recover_escrow("record", b"123456", confirm_irreversible=True)


# ---------------------------------------------------------------- protobuf framing


@pytest.mark.parametrize(
    "data",
    [b"\x09\x01\x02", b"\x0d\x01", b"\x08", b"\x0a\x05abc", b"\x08\xff"],
    ids=["i64", "i32", "varint-missing", "len", "varint-unterminated"],
)
def test_truncated_fields_raise_proto_error(data: bytes) -> None:
    with pytest.raises(codec.ProtoError):
        codec.decode_fields(data)


def test_change_with_a_non_message_record_field_is_malformed_not_a_deletion() -> None:
    # A deletion is an entry without field 5; a varint there is damage and must not drop
    # the record from the cache.
    zone = ckks.ZoneId("Passwords", "_user")
    change = Writer().message(1, ckks.record_identifier("A", zone)).uint64(5, 7).finish()
    with pytest.raises(codec.ProtoError, match="not a message"):
        ckks.parse_retrieve_changes_response(ckks.build_changes_page([change], b"t", 3))


_ZONE = ckks.ZoneId("Passwords", "_user")


@pytest.mark.parametrize(
    ("name", "record"),
    [
        ("A", b""),
        ("A", ckks.encode_record(ckks.CloudKitRecord("B", "item", {}, zone=_ZONE))),
        ("A", ckks.encode_record(ckks.CloudKitRecord("A", "", {}, zone=_ZONE))),
    ],
    ids=["empty-record", "other-record", "no-type"],
)
def test_change_whose_record_lacks_identity_is_malformed(name: str, record: bytes) -> None:
    # Such a record would replace the cached login with one no reader recognises, which the
    # sync engine would take as the login having been deleted.
    change = ckks.build_change(name, _ZONE, "tag", record)
    with pytest.raises(codec.ProtoError, match="record"):
        ckks.parse_retrieve_changes_response(ckks.build_changes_page([change], b"t", 3))


@pytest.mark.parametrize(
    "page",
    [
        b"",
        Writer().bytes(2, b"t").finish(),
        Writer().bytes(2, b"t").uint64(4, 9).finish(),
        Writer().uint64(1, 5).bytes(2, b"t").uint64(4, 3).finish(),
    ],
    ids=["empty", "no-status", "unknown-status", "non-message-change"],
)
def test_unreadable_change_page_is_malformed_not_caught_up(page: bytes) -> None:
    # Accepting any of these would mark the zone as caught up (or advance its token) while
    # changes were lost, so a later fetch could never bring them back.
    with pytest.raises(codec.ProtoError):
        ckks.parse_retrieve_changes_response(page)


def test_fixed_width_fields_decode_little_endian() -> None:
    data = b"\x09" + (7).to_bytes(8, "little") + b"\x15" + (9).to_bytes(4, "little")
    assert codec.decode_fields(data) == {1: [7], 2: [9]}


@pytest.mark.parametrize("value", [0, 1, 127, 128, 300, 2**63, 2**64 - 1])
def test_varint_round_trip(value: int) -> None:
    assert codec.read_varint(codec.encode_varint(value), 0) == (
        value,
        len(codec.encode_varint(value)),
    )


# ---------------------------------------------------------------- anisette reuse


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _anisette(*answers: requests.Response | Exception) -> tuple[Anisette, _Http, _Clock]:
    http, clock = _Http(*answers), _Clock()
    return Anisette("http://anisette.local", http=http, clock=clock), http, clock


def _machine(otp: str) -> requests.Response:
    body = {"X-Apple-I-MD": otp, "X-Apple-I-MD-M": "m", "Unrelated": "dropped"}
    return _response(json.dumps(body).encode(), 200)


def test_anisette_reuses_one_answer_inside_the_window() -> None:
    anisette, http, clock = _anisette(_machine("a"), _machine("b"))
    first = anisette.headers()
    clock.now += REUSE_SECONDS - 0.01
    assert anisette.headers() == first == {"X-Apple-I-MD": "a", "X-Apple-I-MD-M": "m"}
    assert len(http.calls) == 1


def test_anisette_refreshes_after_the_window() -> None:
    anisette, http, clock = _anisette(_machine("a"), _machine("b"))
    anisette.headers()
    clock.now += REUSE_SECONDS
    assert anisette.headers()["X-Apple-I-MD"] == "b"
    assert len(http.calls) == 2


def test_anisette_hands_out_copies() -> None:
    anisette, _, _ = _anisette(_machine("a"))
    anisette.headers()["X-Apple-I-MD"] = "tampered"
    assert anisette.headers()["X-Apple-I-MD"] == "a"


@pytest.mark.parametrize(
    "answer",
    [
        requests.ConnectionError("refused"),
        _response(b"", 500),
        _response(b"not json", 200),
        _response(b"[]", 200),
        _response(json.dumps({"X-Apple-I-MD": "only-otp"}).encode(), 200),
    ],
    ids=["down", "500", "not-json", "list", "partial"],
)
def test_anisette_failures_are_anisette_errors(answer: requests.Response | Exception) -> None:
    anisette, _, _ = _anisette(answer)
    with pytest.raises(AnisetteError, match="anisette"):
        anisette.headers()


def test_anisette_failure_is_not_cached() -> None:
    anisette, _, _ = _anisette(requests.ConnectionError("refused"), _machine("a"))
    with pytest.raises(AnisetteError):
        anisette.headers()
    assert anisette.headers()["X-Apple-I-MD"] == "a"
