# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Every Apple connection verifies the server certificate.

A local HTTPS server presents a certificate from a CA the client has never seen; each call that
carries Apple credentials must refuse it with its module's error. The positive controls trust
that CA (as the Apple bundle for gsa.apple.com, as the default trust store elsewhere) and the
very same call succeeds - so the negative results prove verification, not a broken server.
"""

# pyright: reportPrivateUsage=false
# The GSA request primitive is exercised directly: it is where every GSA call verifies TLS.

from __future__ import annotations

import gzip
import json
import plistlib
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from tests.unit.icloud.tls_server import HttpsServer, Reply, Route

from passwords_app.icloud import tls
from passwords_app.icloud.auth import icloud
from passwords_app.icloud.auth.gsa import GSAClient, GSAError
from passwords_app.icloud.escrow.srp import EscrowError, EscrowRecovery
from passwords_app.icloud.proto.codec import Writer
from passwords_app.icloud.transport import cloudkit
from passwords_app.icloud.transport.cloudkit import CloudKitError, CloudKitTransport, DeviceConfig

if TYPE_CHECKING:
    from passwords_app.icloud.auth.device import Device


class _Device:
    device_id = "00000000-0000-4000-8000-000000000001"
    serial = "C02TEST00001"
    local_user_uuid = "00000000-0000-4000-8000-000000000002"

    def meta_headers(self) -> dict[str, str]:
        return {"X-Mme-Device-Id": self.device_id}


class _Anisette:
    def headers(self) -> dict[str, str]:
        return {"X-Apple-I-MD": "otp", "X-Apple-I-MD-M": "machine"}


def _device() -> Device:
    return _Device()  # type: ignore[return-value]


def _apple_route(method: str, path: str, _body: bytes) -> Reply:  # noqa: PLR0911 - one answer per endpoint
    """Minimal well-formed answers for every endpoint the calls below reach."""
    reply = Reply
    plist = "text/x-xml-plist"
    if path.startswith("/grandslam/GsService2/validate"):
        return reply(200, plistlib.dumps({"ec": 0}), plist)
    if path.startswith("/grandslam/GsService2"):
        return reply(200, plistlib.dumps({"Response": {"Status": {"ec": 0}}}), plist)
    if path.startswith("/auth/verify/"):
        return reply(200, b"", plist)
    if path.startswith("/setup/iosbuddy/loginDelegates"):
        service = {"tokens": {"mmeAuthToken": "token"}, "appleAccountInfo": {"dsid": "1"}}
        delegates = {"com.apple.mobileme": {"status": 0, "service-data": service}}
        return reply(200, plistlib.dumps({"status": 0, "delegates": delegates}), plist)
    if path.startswith("/setup/get_account_settings"):
        return reply(200, plistlib.dumps({"status": 0}), plist)
    if path.startswith("/setup/setup/ck/v1/ckAppInit"):
        return reply(200, json.dumps({"cloudKitUserId": "_user"}).encode(), "application/json")
    if path.startswith(("/ckdatabase/", "/ckcoderouter/")):
        response_operation = Writer().message(3, Writer().uint64(1, 1)).finish()
        body = gzip.compress(cloudkit.delimit(response_operation))
        return reply(200, body, "application/x-protobuf")
    if path.startswith("/escrowproxy/api/"):
        return reply(200, plistlib.dumps({"metadataList": []}), "application/x-apple-plist")
    msg = f"unexpected {method} {path}"
    raise AssertionError(msg)


def _gsa(server: HttpsServer) -> GSAClient:
    return GSAClient(_device(), _Anisette(), base_url=server.base_url)


def _transport(server: HttpsServer) -> CloudKitTransport:
    return CloudKitTransport(
        "ck-token", "_user", DeviceConfig("DEVICE", "C02TEST"), _Anisette(), gateway=server.base_url
    )


Call = Callable[["HttpsServer"], object]

GSA_CALLS: dict[str, Call] = {
    "gsa-request": lambda s: _gsa(s)._request({"o": "init"}),
    "trigger-trusted": lambda s: _gsa(s).trigger_trusted_factor("1", "idms"),
    "submit-trusted": lambda s: _gsa(s).submit_trusted_factor("123456", "1", "idms"),
    "trigger-sms": lambda s: _gsa(s).trigger_sms_factor("1", "idms"),
    "submit-sms": lambda s: _gsa(s).submit_sms_factor("123456", "1", "idms"),
}

ICLOUD_CALLS: dict[str, Call] = {
    "login-mobileme": lambda s: icloud.login_mobileme(
        "user@example.invalid",
        "pet",
        "adsid",
        "client",
        _device(),
        _Anisette(),
        url=f"{s.base_url}/setup/iosbuddy/loginDelegates",
    ),
    "account-settings": lambda s: icloud.fetch_account_settings(
        {"mme": {"dsid": "1", "mmeAuthToken": "token"}},
        _device(),
        _Anisette(),
        url=f"{s.base_url}/setup/get_account_settings",
    ),
}

CLOUDKIT_CALLS: dict[str, Call] = {
    "ck-app-init": lambda s: cloudkit.ck_app_init(
        cloudkit.CUTTLEFISH_CONTAINER,
        cloudkit.CUTTLEFISH_BUNDLE,
        "1",
        "token",
        _Anisette(),
        url=f"{s.base_url}/setup/setup/ck/v1/ckAppInit",
    ),
    "perform": lambda s: _transport(s).fetch_records(b""),
}

ESCROW_CALLS: dict[str, Call] = {
    "escrow-invoke": lambda s: EscrowRecovery(
        s.base_url, "user@example.invalid", "pet", _Anisette()
    ).list_records(),
}

ALL_CALLS: list[tuple[str, Call, type[Exception]]] = [
    *((name, call, GSAError) for name, call in GSA_CALLS.items()),
    *((name, call, icloud.ICloudError) for name, call in ICLOUD_CALLS.items()),
    *((name, call, CloudKitError) for name, call in CLOUDKIT_CALLS.items()),
    *((name, call, EscrowError) for name, call in ESCROW_CALLS.items()),
]


@pytest.mark.parametrize(
    ("call", "error"), [(c, e) for _, c, e in ALL_CALLS], ids=[n for n, _, _ in ALL_CALLS]
)
def test_unknown_issuer_is_refused(
    https_server: Callable[[Route], HttpsServer], call: Call, error: type[Exception]
) -> None:
    server = https_server(_apple_route)
    with pytest.raises(error, match=r"(?i)certificate"):
        call(server)


@pytest.mark.parametrize("call", list(GSA_CALLS.values()), ids=list(GSA_CALLS))
def test_gsa_trusts_its_ca_only_through_the_apple_bundle(
    https_server: Callable[[Route], HttpsServer],
    monkeypatch: pytest.MonkeyPatch,
    call: Call,
) -> None:
    server = https_server(_apple_route)
    # The system store must not be what lets gsa.apple.com through: trusting the CA there
    # changes nothing, trusting it as the Apple bundle does.
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", server.ca_pem)
    with pytest.raises(GSAError, match=r"(?i)certificate"):
        call(server)
    monkeypatch.setattr(tls, "apple_ca_bundle", lambda: server.ca_pem)
    call(server)


@pytest.mark.parametrize(
    "call",
    [*ICLOUD_CALLS.values(), *CLOUDKIT_CALLS.values(), *ESCROW_CALLS.values()],
    ids=[*ICLOUD_CALLS, *CLOUDKIT_CALLS, *ESCROW_CALLS],
)
def test_other_hosts_use_the_default_trust_store(
    https_server: Callable[[Route], HttpsServer],
    monkeypatch: pytest.MonkeyPatch,
    call: Call,
) -> None:
    server = https_server(_apple_route)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", server.ca_pem)
    call(server)


def test_apple_bundle_holds_the_apple_roots() -> None:
    from cryptography import x509  # noqa: PLC0415 - only this test parses certificates

    pem = Path(tls.apple_ca_bundle()).read_bytes()
    names = {cert.subject.rfc4514_string() for cert in x509.load_pem_x509_certificates(pem)}
    assert "CN=Apple Root CA,OU=Apple Certification Authority,O=Apple Inc.,C=US" in names
    assert len(names) == 3


def test_no_module_silences_urllib3_warnings() -> None:
    """`urllib3.disable_warnings()` only ever hid `verify=False`; left in, it would hide a
    regression. A fresh interpreter shows what importing the package does to the filters."""
    probe = (
        "import warnings, urllib3\n"
        "import passwords_app.icloud.auth.gsa, passwords_app.icloud.auth.icloud\n"
        "import passwords_app.icloud.transport.cloudkit, passwords_app.icloud.escrow.srp\n"
        "insecure = urllib3.exceptions.InsecureRequestWarning\n"
        "print(next(f[0] for f in warnings.filters if issubclass(insecure, f[2])))\n"
    )
    result = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() != "ignore"
