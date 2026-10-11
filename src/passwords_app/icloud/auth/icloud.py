# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Reach iCloud services with the long-lived mmeAuthToken (no password, no 2FA).

loginDelegates mints it from a fresh PET; get_account_settings returns the service-URL map.
Both hosts chain to a public root, so they use the default trust store. See RESEARCH.md.
"""

from __future__ import annotations

import base64
import logging
import plistlib
from http import HTTPStatus
from typing import TYPE_CHECKING

import requests

from passwords_app.icloud import tls
from passwords_app.icloud.auth.headers import identity_headers
from passwords_app.icloud.errors import AppleError
from passwords_app.icloud.values import PLIST_ERRORS, Record, child, is_dict, mapping, text

if TYPE_CHECKING:
    from passwords_app.icloud.auth.anisette import AnisetteSource
    from passwords_app.icloud.auth.device import Device

logger = logging.getLogger(__name__)

LOGIN_DELEGATES_URL = "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
ACCOUNT_SETTINGS_URL = "https://setup.icloud.com/setup/get_account_settings"

# AOSKit/accountsd identity for the iCloud setup endpoints (distinct from the GSA akd UA).
ICLOUD_USER_AGENT = "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0"
ICLOUD_CLIENT_INFO = (
    "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>"
)
_TIMEOUT = 20
_ALT_URL_KEYS = ("url", "escrowProxyUrl", "configURL", "wsUrl")


class ICloudError(AppleError):
    pass


class ICloudAuthError(ICloudError):
    """The stored mmeAuthToken was refused; it must be re-minted from a fresh sign-in."""


def _basic(user: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


def _post_plist(
    http: requests.Session | None, url: str, headers: dict[str, str], body: bytes, what: str
) -> tuple[int, Record]:
    try:
        resp = (http or tls.new_session()).post(url, headers=headers, data=body, timeout=_TIMEOUT)
    except requests.RequestException as e:
        msg = f"{what} request failed: {e}"
        raise ICloudError(msg) from e
    logger.debug("%s -> HTTP %s (%d bytes)", what, resp.status_code, len(resp.content))
    try:
        data = plistlib.loads(resp.content)
    except PLIST_ERRORS as e:
        # An expired token often comes back as a bare 401; the caller must still see the
        # status to re-mint the token instead of failing on the missing body.
        if resp.status_code == HTTPStatus.UNAUTHORIZED:
            return resp.status_code, {}
        msg = f"{what} returned HTTP {resp.status_code} without a plist body"
        raise ICloudError(msg) from e
    if not is_dict(data):
        msg = f"{what} returned HTTP {resp.status_code} with a non-dictionary plist"
        raise ICloudError(msg)
    return resp.status_code, mapping(data)


def login_mobileme(  # noqa: PLR0913, PLR0917 - mirrors the loginDelegates inputs one-to-one
    username: str,
    pet: str,
    adsid: str,
    client_id: str,
    device: Device,
    anisette: AnisetteSource,
    *,
    url: str = LOGIN_DELEGATES_URL,
    http: requests.Session | None = None,
) -> tuple[str, str, Record, Record]:
    """Exchange the fresh PET for the persistent mmeAuthToken.

    Returns (dsid, mme_auth_token, service_data, raw_response).
    """
    body = plistlib.dumps(
        {
            "apple-id": username,
            "delegates": {"com.apple.mobileme": {}},
            "password": pet,
            "client-id": client_id,
        }
    )
    # Same device identity as GSA, so loginDelegates sees the device that just passed 2FA.
    headers = {
        "X-Apple-ADSID": adsid,
        "User-Agent": ICLOUD_USER_AGENT,
        "X-Mme-Client-Info": ICLOUD_CLIENT_INFO,
        "Accept": "*/*",
    }
    headers.update(identity_headers(device, anisette))
    headers["Authorization"] = _basic(username, pet)  # apple-id:PET (NOT dsid:PET)

    _, data = _post_plist(http, url, headers, body, "loginDelegates")
    mm = child(child(data, "delegates"), "com.apple.mobileme")
    status = mm.get("status", data.get("status"))
    if status != 0:
        why = text(mm, "status-message") or text(data, "status-message") or "unknown error"
        msg = f"loginDelegates status {status}: {why}"
        raise ICloudError(msg)

    service_data = child(mm, "service-data")
    dsid = data.get("dsid") or child(service_data, "appleAccountInfo").get("dsid")
    token = text(child(service_data, "tokens"), "mmeAuthToken")
    if not dsid or not token:
        msg = "loginDelegates succeeded without a dsid and mmeAuthToken"
        raise ICloudError(msg)
    return str(dsid), token, service_data, data


def fetch_account_settings(
    record: Record,
    device: Device,
    anisette: AnisetteSource,
    *,
    url: str = ACCOUNT_SETTINGS_URL,
    http: requests.Session | None = None,
) -> tuple[int, Record]:
    """With the stored mmeAuthToken, fetch the account/webservices settings.

    Auth is `Basic base64(dsid:mmeAuthToken)`. Returns (http_status, parsed_plist).
    """
    mme = child(record, "mme")
    dsid = mme.get("dsid")
    token = text(mme, "mmeAuthToken")
    if not token or not dsid:
        msg = "no mmeAuthToken stored; sign in again"
        raise ICloudError(msg)

    headers = {
        "Authorization": _basic(str(dsid), token),
        "X-Mme-Client-Info": ICLOUD_CLIENT_INFO,
        "User-Agent": ICLOUD_USER_AGENT,
        "Accept": "*/*",
    }
    headers.update(identity_headers(device, anisette))
    return _post_plist(http, url, headers, b"", "get_account_settings")


def extract_webservices(settings: Record) -> dict[str, Record]:
    """Flatten the service-URL map from get_account_settings, tolerating both shapes.

      - modern:  settings["webservices"][name] = {"url": ..., "status": ...}
      - classic: settings["com.apple.mobileme"]["com.apple.Dataclass.X"] = {"url": ...}

    Returns {name: {"url": ...}} so callers can read ckdatabasews / keyvalue / escrowproxy.
    """
    out: dict[str, Record] = {}
    for name, value in child(settings, "webservices").items():
        service = mapping(value)
        if url := text(service, "url"):
            out[name] = {"url": url, "status": service.get("status")}

    # Some services carry their endpoint under a non-"url" key (KeychainSync -> escrowProxyUrl,
    # KeyValue -> configURL, Ubiquity -> wsUrl); capture those too.
    for name, value in child(settings, "com.apple.mobileme").items():
        service = mapping(value)
        url = next((u for k in _ALT_URL_KEYS if (u := text(service, k))), None)
        if not url:
            continue
        entry: Record = {"url": url, "status": service.get("status")}
        if escrow := text(service, "escrowProxyUrl"):
            entry["escrowProxyUrl"] = escrow
        # Normalise "com.apple.Dataclass.Foo" -> "foo" alongside the raw key.
        out.setdefault(name, entry)
        out.setdefault(name.rsplit(".", 1)[-1].lower(), entry)

    return out
