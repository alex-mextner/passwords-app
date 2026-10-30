# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
# These tests drive GSAClient's private request/header helpers and fake raw response bodies.
# pyright: reportPrivateUsage=false
"""Offline regression tests for GrandSlam request identities and error handling."""

from __future__ import annotations

import plistlib
from typing import Any, Protocol, override

import pytest
import requests

from passwords_app.icloud import const
from passwords_app.icloud.auth.gsa import GSAClient, GSAError


class _Device:
    def meta_headers(self) -> dict[str, str]:
        return {"X-Mme-Device-Id": "device-id"}


class _Anisette:
    def headers(self) -> dict[str, str]:
        return {
            "X-Apple-I-MD": "otp",
            "X-Apple-I-MD-M": "machine",
        }


def _response(
    content: bytes, *, status: int = 200, content_type: str = "text/x-xml-plist"
) -> requests.Response:
    resp = requests.Response()
    resp._content = content
    resp.status_code = status
    resp.headers["Content-Type"] = content_type
    return resp


class Answer(Protocol):
    def __call__(self, **kwargs: Any) -> requests.Response: ...


class _Http(requests.Session):
    """Answers every request with `answer` and records the last call's arguments."""

    def __init__(self) -> None:
        super().__init__()
        self.answer: Answer = lambda **_: _plist_response()
        self.captured: dict[str, Any] = {}

    @override
    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:  # type: ignore[override]
        self.captured = {"method": method, "url": url, **kwargs}
        return self.answer(**kwargs)


@pytest.fixture
def http() -> _Http:
    return _Http()


@pytest.fixture
def client(http: _Http) -> GSAClient:
    return GSAClient(_Device(), _Anisette(), http=http)  # type: ignore[arg-type]


def _plist_response(response: object = None, *, status: int = 200) -> requests.Response:
    body = {"Response": response if response is not None else {"Status": {"ec": 0}}}
    return _response(plistlib.dumps(body), status=status)


def test_srp_request_uses_akd_identity(http: _Http, client: GSAClient) -> None:
    client._request({"u": "nobody@example.invalid", "o": "init"})
    captured = http.captured

    assert captured["url"] == const.GSA_ENDPOINT
    client_info = captured["headers"]["X-MMe-Client-Info"]
    assert client_info == const.GSA_CLIENT_INFO
    assert "com.apple.akd/1.0" in client_info
    assert "com.apple.dt.Xcode" not in client_info


def test_twofa_headers_use_akd_with_xcode_application_context(client: GSAClient) -> None:
    headers = client._twofa_headers("123", "token")

    assert headers["X-Mme-Client-Info"] == const.GSA_CLIENT_INFO
    assert "com.apple.akd/1.0" in headers["X-Mme-Client-Info"]
    assert "com.apple.dt.Xcode" not in headers["X-Mme-Client-Info"]
    assert headers["User-Agent"] == "Xcode"
    assert headers["X-Apple-App-Info"] == "com.apple.gs.xcode.auth"
    assert headers["X-Xcode-Version"] == "11.2 (11B41)"


def test_request_returns_response_dictionary(http: _Http, client: GSAClient) -> None:
    expected = {"Status": {"ec": 0}, "sp": "s2k"}
    http.answer = lambda **_: _plist_response(expected)

    assert client._request({"o": "init"}) == expected


def test_html_503_becomes_actionable_gsa_error(http: _Http, client: GSAClient) -> None:
    html = b"<html><title>503 Service Temporarily Unavailable</title></html>"
    http.answer = lambda **_: _response(html, status=503, content_type="text/html")

    with pytest.raises(GSAError) as exc_info:
        client._request({"o": "init"})

    message = str(exc_info.value)
    assert "GSA init returned HTTP 503" in message
    assert "expected a plist" in message
    assert "text/html" in message
    assert f"{len(html)} bytes" in message


def test_non_plist_200_becomes_gsa_error(http: _Http, client: GSAClient) -> None:
    http.answer = lambda **_: _response(b"not a plist", content_type="text/plain")

    with pytest.raises(GSAError, match="GSA complete returned HTTP 200"):
        client._request({"o": "complete"})


def test_transport_error_becomes_gsa_error(http: _Http, client: GSAClient) -> None:
    def timeout(**_: object) -> requests.Response:
        msg = "timed out"
        raise requests.Timeout(msg)

    http.answer = timeout

    with pytest.raises(GSAError, match="GSA init request failed: timed out"):
        client._request({"o": "init"})


def test_missing_response_dictionary_becomes_gsa_error(http: _Http, client: GSAClient) -> None:
    http.answer = lambda **_: _response(plistlib.dumps({"Status": {"ec": 0}}))

    with pytest.raises(GSAError, match="without a Response dictionary"):
        client._request({"o": "init"})


def test_non_dictionary_plist_becomes_gsa_error(http: _Http, client: GSAClient) -> None:
    http.answer = lambda **_: _response(plistlib.dumps(["unexpected"]))

    with pytest.raises(GSAError, match="without a Response dictionary"):
        client._request({"o": "init"})


def test_non_success_plist_preserves_apple_status(http: _Http, client: GSAClient) -> None:
    response = {"Status": {"ec": -20101, "em": "bad account"}}
    http.answer = lambda **_: _plist_response(response, status=401)

    with pytest.raises(GSAError) as exc_info:
        client._request({"o": "init"})

    message = str(exc_info.value)
    assert "HTTP 401" in message
    assert "ec=-20101" in message
    assert "bad account" in message


@pytest.mark.parametrize("code", [-20970, -80045])
def test_probe_client_returns_apples_answer_for_an_account_nobody_owns(
    http: _Http, client: GSAClient, code: int
) -> None:
    http.answer = lambda **_: _plist_response({"Status": {"ec": code, "em": "x"}})

    assert client.probe_client() == code

    sent = plistlib.loads(http.captured["data"])["Request"]
    assert sent["o"] == "init"
    assert sent["u"].endswith("@example.invalid")
    assert set(sent) >= {"A2k", "ps", "cpd"}


def test_probe_client_without_a_status_code_is_none(http: _Http, client: GSAClient) -> None:
    http.answer = lambda **_: _plist_response({"Status": {}})
    assert client.probe_client() is None


def test_probe_client_asks_about_a_fresh_account_name_each_time(
    http: _Http, client: GSAClient
) -> None:
    names = []
    for _ in range(2):
        client.probe_client()
        names.append(plistlib.loads(http.captured["data"])["Request"]["u"])

    assert names[0] != names[1]
