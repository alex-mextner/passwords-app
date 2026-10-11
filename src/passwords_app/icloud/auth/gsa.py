# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""GrandSlam (GSA) SRP-6a authentication.

Takes an explicit Device + Anisette instead of module globals. Produces the decrypted
server provisioning data (spd), which contains the account DSID and the PET
(password-equivalent token). Every call verifies gsa.apple.com against the bundled Apple roots.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import logging
import plistlib
from typing import TYPE_CHECKING, Any, Protocol, cast

import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from passwords_app.icloud import const, tls
from passwords_app.icloud.auth.headers import identity_headers
from passwords_app.icloud.errors import AppleError
from passwords_app.icloud.values import (
    PLIST_ERRORS,
    Record,
    blob,
    integer,
    is_dict,
    mapping,
    text,
)

if TYPE_CHECKING:
    from passwords_app.icloud.auth.anisette import AnisetteSource
    from passwords_app.icloud.auth.device import Device

# The untyped pure-Python backend: it exposes the RFC 5054 switches Apple's variant needs.
# They are process-wide; nothing else in the app uses the srp module.
_srp: Any = importlib.import_module("srp._pysrp")
_srp.rfc5054_enable()
_srp.no_username_in_x()

logger = logging.getLogger(__name__)

_TIMEOUT = 10
_S2K_PROTOCOLS = ("s2k", "s2k_fo")
_PLIST_PREFIXES = (b"<?xml", b"bplist", b"<plist")


class GSAError(AppleError):
    pass


class CodeRejectedError(GSAError):
    """Apple refused a second-factor code (wrong or expired)."""


class _SrpUser(Protocol):
    p: bytes

    def start_authentication(self) -> tuple[bytes, bytes]: ...
    def process_challenge(self, salt: bytes, b: bytes) -> bytes | None: ...
    def verify_session(self, m2: bytes) -> None: ...
    def authenticated(self) -> bool: ...
    def get_session_key(self) -> bytes | None: ...


class GSAClient:
    def __init__(
        self,
        device: Device,
        anisette: AnisetteSource,
        *,
        http: requests.Session | None = None,
        base_url: str = const.GSA_BASE_URL,
    ) -> None:
        self.device = device
        self.anisette = anisette
        self._http = http or tls.new_session()
        self._base_url = base_url.rstrip("/")
        # Stashed for the redacted debug transcript (set by authenticate()).
        self.last_init_response: Record | None = None
        self.last_complete_response: Record | None = None
        self.last_session_key: bytes | None = None

    def _cpd(self) -> Record:
        cpd: Record = {
            "bootstrap": True,
            "icscrec": True,
            "pbe": False,
            "prkgen": True,
            "svct": "iCloud",
        }
        cpd.update(identity_headers(self.device, self.anisette))
        return cpd

    def _send(  # noqa: PLR0913 - one place for every GSA request's knobs
        self,
        method: str,
        path: str,
        what: str,
        *,
        headers: dict[str, str],
        data: bytes | None = None,
        json: dict[str, object] | None = None,
    ) -> requests.Response:
        try:
            return self._http.request(
                method,
                f"{self._base_url}{path}",
                headers=headers,
                data=data,
                json=json,
                verify=tls.apple_ca_bundle(),
                timeout=_TIMEOUT,
            )
        except requests.RequestException as e:
            msg = f"{what} request failed: {e}"
            raise GSAError(msg) from e

    def _request(self, parameters: Record) -> Record:
        request: Record = {"cpd": self._cpd(), **parameters}
        body: Record = {"Header": {"Version": "1.0.1"}, "Request": request}
        operation = f"GSA {parameters.get('o', 'request')}"
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": const.GSA_USER_AGENT,
            "X-MMe-Client-Info": const.GSA_CLIENT_INFO,
        }
        resp = self._send(
            "POST", const.GSA_SERVICE_PATH, operation, headers=headers, data=plistlib.dumps(body)
        )
        payload = _parse_plist(resp, operation)
        response = mapping(payload).get("Response") if is_dict(payload) else None
        if not is_dict(response):
            msg = f"{operation} returned HTTP {resp.status_code} without a Response dictionary"
            raise GSAError(msg)
        if not resp.ok:
            msg = f"{operation} failed: HTTP {resp.status_code}: {_status(mapping(response))}"
            raise GSAError(msg)
        return mapping(response)

    def authenticate(self, username: str, password: str, stage: str) -> tuple[Record, Record]:
        usr = cast("_SrpUser", _srp.User(username, b"", hash_alg=_srp.SHA256, ng_type=_srp.NG_2048))
        _, a_pub = usr.start_authentication()

        init = self._request({"A2k": a_pub, "ps": list(_S2K_PROTOCOLS), "u": username, "o": "init"})
        self.last_init_response = init
        logger.debug("GSA init response keys: %s", list(init))
        protocol = text(init, "sp")
        if protocol is None:
            msg = f"{stage}: init failed: {_status(init)}"
            raise GSAError(msg)
        if protocol not in _S2K_PROTOCOLS:
            msg = f"unsupported protocol {protocol}"
            raise GSAError(msg)
        salt, server_b, iterations = blob(init, "s"), blob(init, "B"), integer(init, "i")
        cookie = init.get("c")
        if salt is None or server_b is None or iterations is None or cookie is None:
            msg = f"{stage}: init answer is missing the SRP challenge"
            raise GSAError(msg)

        # The password key needs the server's salt and iteration count, so it is set late.
        usr.p = _encrypt_password(password, salt, iterations, protocol)
        m1 = usr.process_challenge(salt, server_b)
        if m1 is None:
            msg = "failed to process SRP challenge (wrong password?)"
            raise GSAError(msg)

        complete = self._request({"c": cookie, "M1": m1, "u": username, "o": "complete"})
        self.last_complete_response = complete
        logger.debug("GSA complete response keys: %s", list(complete))
        m2, spd_blob = blob(complete, "M2"), blob(complete, "spd")
        if m2 is None or spd_blob is None:
            msg = f"{stage}: complete failed: {_status(complete)}"
            raise GSAError(msg)
        usr.verify_session(m2)
        if not usr.authenticated():
            msg = "server session verification failed (imposter?)"
            raise GSAError(msg)

        self.last_session_key = usr.get_session_key()
        spd = plistlib.loads(_decrypt_cbc(usr, spd_blob), fmt=plistlib.FMT_XML)
        if not is_dict(spd):
            msg = "GSA spd is not a dictionary"
            raise GSAError(msg)
        logger.debug("GSA spd top-level keys: %s", list(mapping(spd)))
        return complete, mapping(spd)

    def trigger_trusted_factor(self, dsid: str, idms_token: str) -> None:
        # Apple answers the trigger before the code is pushed; only transport failures count.
        self._send(
            "GET",
            "/auth/verify/trusteddevice",
            "trusted-device 2FA trigger",
            headers=self._twofa_headers(dsid, idms_token),
        )

    def submit_trusted_factor(self, code: str, dsid: str, idms_token: str) -> None:
        h = self._twofa_headers(dsid, idms_token)
        h["security-code"] = code
        resp = self._send("GET", "/grandslam/GsService2/validate", "trusted-device 2FA", headers=h)
        _check_code(resp, "trusted-device")

    def trigger_sms_factor(self, dsid: str, idms_token: str, phone_id: int = 1) -> None:
        self._send(
            "PUT",
            "/auth/verify/phone/",
            "SMS 2FA trigger",
            json={"phoneNumber": {"id": phone_id}, "mode": "sms"},
            headers=self._twofa_headers(dsid, idms_token),
        )

    def submit_sms_factor(self, code: str, dsid: str, idms_token: str, phone_id: int = 1) -> None:
        body: dict[str, object] = {
            "phoneNumber": {"id": phone_id},
            "mode": "sms",
            "securityCode": {"code": code},
        }
        resp = self._send(
            "POST",
            "/auth/verify/phone/securitycode",
            "SMS 2FA",
            json=body,
            headers=self._twofa_headers(dsid, idms_token),
        )
        _check_code(resp, "SMS")

    def _twofa_headers(self, dsid: str, idms_token: str) -> dict[str, str]:
        identity_token = base64.b64encode(f"{dsid}:{idms_token}".encode()).decode()
        h = {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": "Xcode",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": identity_token,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Mme-Client-Info": const.GSA_CLIENT_INFO,
        }
        h.update(identity_headers(self.device, self.anisette))
        return h


def _parse_plist(resp: requests.Response, operation: str) -> object:
    content = resp.content
    content_type = resp.headers.get("Content-Type", "unknown content type")
    if content.lstrip()[:6].startswith(_PLIST_PREFIXES):
        try:
            return plistlib.loads(content)
        except PLIST_ERRORS:
            pass
    msg = (
        f"{operation} returned HTTP {resp.status_code}; expected a plist, got {content_type} "
        f"({len(content)} bytes)"
    )
    raise GSAError(msg)


def _encrypt_password(password: str, salt: bytes, iterations: int, protocol: str) -> bytes:
    p = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        p = p.hex().encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, 32)


def _session_key(usr: _SrpUser, name: str) -> bytes:
    k = usr.get_session_key()
    if k is None:
        msg = "no SRP session key"
        raise GSAError(msg)
    return hmac.new(k, name.encode(), hashlib.sha256).digest()


def _decrypt_cbc(usr: _SrpUser, data: bytes) -> bytes:
    key = _session_key(usr, "extra data key:")
    iv = _session_key(usr, "extra data iv:")[:16]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    data = dec.update(data) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def _status(r: Record) -> str:
    s = mapping(r.get("Status", r))
    return f"ec={s.get('ec')} em={s.get('em')!r} au={s.get('au')!r}"


def _check_code(resp: requests.Response, kind: str) -> None:
    """Raise unless the 2FA endpoint accepted the code.

    A rejected code comes back as HTTP 200 with a bare plist; a rejected identity token as 401
    with no body at all.
    """
    try:
        body = mapping(plistlib.loads(resp.content))
    except PLIST_ERRORS as e:
        if resp.ok and resp.content.strip():
            # A cut-off answer says nothing about whether Apple took the code, so it must
            # not read as accepted.
            msg = f"{kind} 2FA answer (HTTP {resp.status_code}) is not a readable plist"
            raise GSAError(msg) from e
        body = {}
    if body.get("ec") or not resp.ok:
        msg = f"{kind} 2FA code rejected: {body.get('em') or resp.status_code}"
        raise CodeRejectedError(msg)
