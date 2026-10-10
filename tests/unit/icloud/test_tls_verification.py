# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Every Apple connection verifies the server certificate.

The vendored client disabled verification for GrandSlam and iCloud setup, so anyone on the
network path could read the Apple ID password and tokens. These tests drive the real
`requests`/`ssl` path against a local HTTPS server with a throwaway CA: the client must refuse
it, and accept it only when that CA is the trusted bundle.
"""

from __future__ import annotations

import plistlib
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import requests
from cryptography import x509
from tests.unit.icloud.tls_server import HttpsServer, Reply, build_pki, serve

from passwords_app.icloud import const, tls
from passwords_app.icloud.auth import gsa, icloud
from passwords_app.icloud.auth.gsa import GSAClient

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

SRC = Path(__file__).resolve().parents[3] / "src" / "passwords_app"


class _Device:
    def meta_headers(self) -> dict[str, str]:
        return {"X-Mme-Device-Id": "device-id"}


class _Anisette:
    def headers(self) -> dict[str, str]:
        return {"X-Apple-I-MD": "otp", "X-Apple-I-MD-M": "machine"}


def _ok(_method: str, _path: str, _body: bytes) -> Reply:
    return Reply(200, plistlib.dumps({"Response": {"Status": {"ec": 0}}, "status": 0}))


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[HttpsServer]:
    # A proxy or CA override in the developer's environment would skew what is trusted.
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
    httpd, handle = serve(build_pki(tmp_path), _ok)
    yield handle
    httpd.shutdown()
    httpd.server_close()


def _gsa_request(server: HttpsServer, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(const, "GSA_ENDPOINT", server.base_url + "/grandslam/GsService2")
    GSAClient(_Device(), _Anisette())._request({"o": "init"})  # type: ignore[arg-type]


def _login_delegates(server: HttpsServer, _monkeypatch: pytest.MonkeyPatch) -> None:
    icloud.login_mobileme(
        "user@example.invalid",
        "pet",
        "adsid",
        "client",
        _Device(),  # type: ignore[arg-type]
        _Anisette(),  # type: ignore[arg-type]
        url=server.base_url + "/setup/iosbuddy/loginDelegates",
    )


def _to_local(server: HttpsServer, monkeypatch: pytest.MonkeyPatch) -> None:
    """Send the module's fixed gsa.apple.com URLs to the local server, keeping every kwarg."""
    real = requests.request

    def rewrite(method: str) -> Callable[..., requests.Response]:
        def send(url: str, **kwargs: Any) -> requests.Response:
            return real(method, url.replace("https://gsa.apple.com", server.base_url), **kwargs)

        return send

    for method in ("get", "put", "post"):
        monkeypatch.setattr(gsa.requests, method, rewrite(method))


def _gsa_2fa(name: str, *args: str) -> Callable[[HttpsServer, pytest.MonkeyPatch], None]:
    def call(server: HttpsServer, monkeypatch: pytest.MonkeyPatch) -> None:
        _to_local(server, monkeypatch)
        getattr(GSAClient(_Device(), _Anisette()), name)(*args)  # type: ignore[arg-type]

    return call


def _account_settings(server: HttpsServer, _monkeypatch: pytest.MonkeyPatch) -> None:
    icloud.fetch_account_settings(
        {"mme": {"dsid": "1", "mmeAuthToken": "t"}},
        _Device(),  # type: ignore[arg-type]
        _Anisette(),  # type: ignore[arg-type]
        url=server.base_url + "/setup/get_account_settings",
    )


CALLS: list[tuple[str, Callable[[HttpsServer, pytest.MonkeyPatch], None]]] = [
    ("gsa", _gsa_request),
    ("trigger-trusted", _gsa_2fa("trigger_trusted_factor", "1", "idms")),
    ("submit-trusted", _gsa_2fa("submit_trusted_factor", "123456", "1", "idms")),
    ("trigger-sms", _gsa_2fa("trigger_sms_factor", "1", "idms")),
    ("submit-sms", _gsa_2fa("submit_sms_factor", "123456", "1", "idms")),
    ("login-delegates", _login_delegates),
    ("account-settings", _account_settings),
]

# GrandSlam calls must trust the bundled Apple roots and nothing else.
GSA_CALLS = [(n, c) for n, c in CALLS if n not in {"login-delegates", "account-settings"}]


@pytest.mark.timeout(30)
@pytest.mark.parametrize("call", [c for _, c in CALLS], ids=[n for n, _ in CALLS])
def test_untrusted_certificate_is_refused(
    call: Callable[[HttpsServer, pytest.MonkeyPatch], None],
    server: HttpsServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(requests.exceptions.SSLError):
        call(server, monkeypatch)


@pytest.mark.timeout(30)
@pytest.mark.parametrize("call", [c for _, c in GSA_CALLS], ids=[n for n, _ in GSA_CALLS])
def test_gsa_trusts_the_bundled_roots(
    call: Callable[[HttpsServer, pytest.MonkeyPatch], None],
    server: HttpsServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Pointing the bundle at the test CA makes the same call succeed, so the refusal above
    # comes from verification against the bundle and not from some unrelated failure.
    monkeypatch.setattr(tls, "apple_ca_bundle", lambda: server.ca_pem)
    call(server, monkeypatch)


def test_bundle_holds_the_apple_roots() -> None:
    pem = Path(tls.apple_ca_bundle()).read_bytes()
    names = {cert.subject.rfc4514_string() for cert in x509.load_pem_x509_certificates(pem)}
    assert "CN=Apple Root CA,OU=Apple Certification Authority,O=Apple Inc.,C=US" in names
    assert len(names) == 3


def test_no_source_file_turns_verification_off() -> None:
    offenders = [
        str(path.relative_to(SRC))
        for path in SRC.rglob("*.py")
        if re.search(r"verify\s*=\s*False|disable_warnings\(", path.read_text())
    ]
    assert offenders == []
