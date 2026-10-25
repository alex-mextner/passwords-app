# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""escrowproxy SRP recovery: turn a device passcode into that device's bottle entropy.

IRREVERSIBLE: escrowproxy allows 10 attempts and destroys the escrow record on the 10th wrong
passcode. `try_recover_escrow` refuses to run without `confirm_irreversible=True`, which the
caller passes only once the user has chosen the device and typed its passcode. `list_records`
(GETRECORDS) is non-destructive and spends no attempt.

The SRP variant is SRP-6a over the RFC 5054 2048-bit group with SHA-256, hashing A and B in
their trimmed (no leading zero) big-endian form; the SRP username is the dsid escrowproxy
returns, not the Apple ID.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import os
import plistlib
import uuid as _uuid
from http import HTTPStatus
from typing import TYPE_CHECKING, ClassVar

import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from passwords_app.icloud import const, tls
from passwords_app.icloud.errors import AppleError
from passwords_app.icloud.proto.codec import Writer
from passwords_app.icloud.values import (
    PLIST_ERRORS,
    Record,
    blob,
    integer,
    is_dict,
    items,
    mapping,
    text,
)

if TYPE_CHECKING:
    from passwords_app.icloud.auth.anisette import AnisetteSource

# RFC 5054 2048-bit group (N, g=2). Standard public constant.
_N_HEX = (
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4"
    "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60"
    "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF"
    "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907"
    "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861"
    "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB"
    "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
)
N = int(_N_HEX, 16)
g = 2
_N_BYTES = (N.bit_length() + 7) // 8
_VERSION_CBC = 0
_VERSION_GCM = 2
_RECOVER_HEADER_TAG = 165
_AES_BLOCK = 16


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _pad(x: int) -> bytes:
    """Left-pad an integer to the modulus byte length (PAD() in RFC 5054)."""
    return x.to_bytes(_N_BYTES, "big")


def _trim(x: int) -> bytes:
    """Minimal big-endian bytes (no left-zero padding)."""
    return x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def unpack_message(bin_: bytes, header_len: int, section_count: int) -> tuple[bytes, list[bytes]]:
    """Split a KeyVault message: len(4) | header | (n+1) BE offsets | body of len(4)||data."""
    header = bin_[4 : header_len + 4]
    total_header_size = header_len + 4 + (section_count + 1) * 4
    offsets = bin_[header_len + 4 : header_len + 4 + section_count * 4]
    sections: list[bytes] = []
    for i in range(section_count):
        start = total_header_size + _int(offsets[i * 4 : i * 4 + 4])
        size = _int(bin_[start : start + 4])
        section = bin_[start + 4 : start + 4 + size]
        if len(offsets) < (i + 1) * 4 or len(section) != size:
            msg = "truncated escrow message"
            raise EscrowError(msg)
        sections.append(section)
    return header, sections


@dataclasses.dataclass(slots=True)
class KeyVaultMessage:
    header: bytes
    sections: list[bytes] = dataclasses.field(default_factory=list[bytes])

    def section(self, data: bytes) -> None:
        self.sections.append(len(data).to_bytes(4, "big") + data)

    def section_sized(self, data: bytes, size: int) -> None:
        total = len(data).to_bytes(4, "big") + data
        if len(total) > size:
            msg = f"section size {size} < actual {len(total)}"
            raise ValueError(msg)
        self.sections.append(total + b"\x00" * (size - len(total)))

    def pack(self) -> bytes:
        body = b""
        idx: list[int] = []
        for s in self.sections:
            idx.append(len(body))
            body += s
        idx.append(len(body))
        result = bytearray(
            b"\x00\x00\x00\x00" + self.header + b"".join(o.to_bytes(4, "big") for o in idx) + body
        )
        result[:4] = len(result).to_bytes(4, "big")
        return bytes(result)


@dataclasses.dataclass(frozen=True, slots=True)
class SrpClient:
    """SRP-6a client (RFC 5054 2048-bit group, SHA-256; trimmed-A/B convention)."""

    a: int

    @classmethod
    def new(cls, a_bytes: bytes) -> SrpClient:
        return cls(a=_int(a_bytes))

    @property
    def public_value(self) -> int:
        return pow(g, self.a, N)

    def public_a(self) -> bytes:
        """Return A, trimmed: escrowproxy hashes the trimmed form, so M1 and M2 must too."""
        return _trim(self.public_value)

    def process(
        self, username: bytes, password: bytes, salt: bytes, b_pub: bytes
    ) -> tuple[bytes, bytes]:
        """Return (K, M1) for the server's salt and B."""
        b_val = _int(b_pub)
        a_pub, b_norm = _trim(self.public_value), _trim(b_val)
        k = _int(sha256(_pad(N), _pad(g)))
        x = _int(sha256(salt, sha256(username + b":" + password)))
        u = _int(sha256(a_pub, b_norm))
        base = (b_val - (k * pow(g, x, N)) % N) % N
        shared = pow(base, self.a + u * x, N)
        key = sha256(_trim(shared))
        h_xor = bytes(p ^ q for p, q in zip(sha256(_pad(N)), sha256(_pad(g)), strict=True))
        m1 = sha256(h_xor, sha256(username), salt, a_pub, b_norm, key)
        return key, m1

    @staticmethod
    def server_proof(a_pub: bytes, m1: bytes, key: bytes) -> bytes:
        """Compute the expected server proof M2 = H(A || M1 || K) with the trimmed A we sent."""
        return sha256(a_pub, m1, key)


def encode_fetch_viable_bottles_request() -> bytes:
    return Writer().uint64(1, 1).bytes(2, b"").finish()


def _aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    """AES-CBC, stripping PKCS#7 padding when present (escrowproxy pads like OpenSSL)."""
    if not ct or len(ct) % _AES_BLOCK or len(iv) != _AES_BLOCK:
        msg = "escrow payload is not whole AES blocks"
        raise EscrowError(msg)
    # The caller checks the SRP server proof first; GCM-versioned records never come here.
    # nosemgrep: crypto-mode-without-authentication - escrowproxy's records are CBC by protocol
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    out = dec.update(ct) + dec.finalize()
    pad = out[-1]
    if 1 <= pad <= 16 and out[-pad:] == bytes([pad]) * pad:  # noqa: PLR2004 - the AES block
        out = out[:-pad]
    return out


class EscrowError(AppleError):
    """escrowproxy could not be reached or answered something unusable."""

    def __init__(self, message: str, *, http_status: int | None = None) -> None:
        super().__init__(message)
        self.http_status = http_status


class EscrowGateError(EscrowError):
    """A live recovery was attempted without explicit irreversible consent."""


class WrongEscrowPasscodeError(EscrowError):
    """The passcode did not open the escrow record; one of the ~10 attempts is spent."""


# 4xx answers to `recover` that reject the caller (expired PET, no access, rate limit) rather
# than the SRP proof, so they must not be reported as a wrong passcode.
_NOT_A_PASSCODE_VERDICT = frozenset(
    {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN, HTTPStatus.TOO_MANY_REQUESTS}
)


class EscrowRecovery:
    """The two-POST escrowproxy SRP that turns the passcode into the bottle entropy."""

    USER_ACTION = "com.apple.sbd: escrow recovery"
    # The body `command` is SCREAMING_SNAKE_CASE, not the URL slug or PascalCase variant.
    _COMMAND_VARIANT: ClassVar[dict[str, str]] = {
        "srp_init": "SRP_INIT",
        "recover": "RECOVER",
        "get_records": "GETRECORDS",
        "get_club_cert": "GETCLUB",
        "enroll": "ENROLL",
        "delete": "DELETE",
    }

    # escrowproxy wants the sbd UA + a fixed X-Mme-Client-Info that overwrites anisette's.
    ESCROW_USER_AGENT = "com.apple.sbd/638.100.48 com.apple.iCloudHelper/282"
    ESCROW_MME_CLIENT_INFO = (
        f"{const.WINDOWS_PLATFORM} <com.apple.AuthKit/1 (com.apple.sbd/638.100.48)>"
    )

    def __init__(  # noqa: PLR0913 - the escrowproxy credentials plus test seams
        self,
        host: str,
        email: str,
        pet: str,
        anisette: AnisetteSource,
        *,
        http: requests.Session | None = None,
        timeout: int = 30,
    ) -> None:
        self.host = host.rstrip("/")
        self.email = email
        self.pet = pet
        self.anisette = anisette
        self.timeout = timeout
        self._http = http or tls.new_session()

    def _headers(self) -> dict[str, str]:
        h = {
            "User-Agent": self.ESCROW_USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "X-Apple-I-Locale": "en_US",
            "x-apple-i-device-type": "1",
            "Content-Type": "application/x-apple-plst",
        }
        h.update(self.anisette.headers())
        h["X-Mme-Client-Info"] = self.ESCROW_MME_CLIENT_INFO  # overrides anisette's
        return h

    def _invoke(self, command: str, request: Record) -> Record:
        """POST one escrowproxy command (it carries the PET, so the certificate is verified)."""
        body = plistlib.dumps(request)
        try:
            resp = self._http.post(
                f"{self.host}/escrowproxy/api/{command}",
                headers=self._headers(),
                data=body,
                auth=(self.email, self.pet),
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            msg = f"escrowproxy/{command} request failed: {e}"
            raise EscrowError(msg) from e
        if not resp.ok:
            msg = f"escrowproxy/{command} returned HTTP {resp.status_code}"
            raise EscrowError(msg, http_status=resp.status_code)
        try:
            data = plistlib.loads(resp.content)
        except PLIST_ERRORS as e:
            msg = f"escrowproxy/{command} returned a body that is not a plist"
            raise EscrowError(msg) from e
        if not is_dict(data):
            msg = f"escrowproxy/{command} returned a non-dictionary plist"
            raise EscrowError(msg)
        return mapping(data)

    def _request(self, command_url: str, label: str, txn: str, **extra: object) -> Record:
        req: Record = {
            "command": self._COMMAND_VARIANT.get(command_url, command_url),
            "label": label,
            "transactionUUID": txn,
            "userActionLabel": self.USER_ACTION,
            "version": 1,
        }
        req.update({k: v for k, v in extra.items() if v is not None})
        return req

    def list_records(self, label: str = "com.apple.securebackup.record") -> list[Record]:
        """GETRECORDS: the escrow records and the metadata naming each device (no attempt spent).

        Returns `[{"label": <bottle id>, "meta": {...}}]`; `meta` has `serial`, `build`,
        `bottleID`, `ClientMetadata` and more.
        """
        txn = str(_uuid.uuid4()).upper()
        resp = self._invoke("get_records", self._request("get_records", label, txn))
        out: list[Record] = []
        for raw in items(resp.get("metadataList") or resp.get("metadata_list")):
            entry = mapping(raw)
            meta_b64 = text(entry, "metadata")
            meta: Record = {}
            if meta_b64:
                try:
                    meta = mapping(plistlib.loads(base64.b64decode(meta_b64)))
                except (binascii.Error, *PLIST_ERRORS):
                    meta = {}
            out.append({"label": text(entry, "label") or "", "meta": meta})
        return out

    def try_recover_escrow(
        self, label: str, passcode: bytes, *, confirm_irreversible: bool = False
    ) -> bytes:
        """Run the SRP recovery; return the EscrowBottle's BottledPeerEntropy.

        IRREVERSIBLE: a wrong passcode consumes one of the 10 attempts.
        """
        if not confirm_irreversible:
            msg = (
                "REFUSED: escrow recovery consumes one of 10 irreversible attempts. Pass "
                "confirm_irreversible=True only after the user has explicitly confirmed."
            )
            raise EscrowGateError(msg)
        txn = str(_uuid.uuid4()).upper()
        client = SrpClient.new(os.urandom(32))

        init = self._invoke(
            "srp_init",
            self._request(
                "srp_init", label, txn, blob=base64.b64encode(client.public_a()).decode()
            ),
        )
        dsid, resp_blob = text(init, "dsid"), text(init, "respBlob")
        if not dsid or not resp_blob:
            msg = "escrowproxy srp_init answer is incomplete"
            raise EscrowError(msg)
        club = integer(init, "clubTypeID")
        header, (id_section, salt, b_pub) = unpack_message(_b64(resp_blob), 24, 3)
        key, m1 = client.process(dsid.encode(), passcode, salt, b_pub)

        hdr = bytearray(header)
        hdr[0:4] = _RECOVER_HEADER_TAG.to_bytes(4, "big")
        hdr[4:8] = (_VERSION_GCM if club == 1 else _VERSION_CBC).to_bytes(4, "big")
        payload = KeyVaultMessage(bytes(hdr))
        payload.section_sized(id_section, 20)
        payload.section(m1)
        try:
            rec = self._invoke(
                "recover",
                self._request(
                    "recover", label, txn, blob=base64.b64encode(payload.pack()).decode()
                ),
            )
        except EscrowError as e:
            # A refused proof comes back as a client error; the attempt is spent either way.
            # Expired credentials and throttling are 4xx too but say nothing about the
            # passcode, so they stay plain escrow errors.
            if (
                e.http_status is not None
                and HTTPStatus.BAD_REQUEST <= e.http_status < HTTPStatus.INTERNAL_SERVER_ERROR
                and e.http_status not in _NOT_A_PASSCODE_VERDICT
            ):
                msg = "the passcode was not accepted"
                raise WrongEscrowPasscodeError(msg, http_status=e.http_status) from e
            raise
        return _open_recovered(rec, client, m1, key, passcode, gcm_header=club == 1)


def _b64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        msg = "escrowproxy answer is not base64"
        raise EscrowError(msg) from e


def _open_recovered(  # noqa: PLR0913 - the recover answer and the SRP state that opens it
    rec: Record,
    client: SrpClient,
    m1: bytes,
    key: bytes,
    passcode: bytes,
    *,
    gcm_header: bool,
) -> bytes:
    resp_blob = text(rec, "respBlob")
    if not resp_blob:
        msg = "the passcode was not accepted"
        raise WrongEscrowPasscodeError(msg)
    h, (proof, iv, ct) = unpack_message(_b64(resp_blob), 40 if gcm_header else 24, 3)
    if SrpClient.server_proof(client.public_a(), m1, key) != proof:
        msg = "the passcode was not accepted"
        raise WrongEscrowPasscodeError(msg)
    version = _int(h[4:8])
    if version == _VERSION_CBC:
        inner = _aes_cbc_decrypt(key, iv, ct)
    elif version == _VERSION_GCM:
        try:
            inner = AESGCM(key).decrypt(iv, ct, None)
        except InvalidTag as e:
            msg = "escrow record failed authentication"
            raise EscrowError(msg) from e
    else:
        msg = f"unsupported escrow record version {version}"
        raise EscrowError(msg)
    ih, ipayloads = unpack_message(inner, 16, 6)
    rounds, salt2 = _int(ih[8:12]), ipayloads[1]
    derived = hashlib.pbkdf2_hmac("sha256", passcode, salt2, rounds, dklen=16)
    bottle_plist = _aes_cbc_decrypt(derived, salt2[:16], ipayloads[3])
    try:
        bottle = mapping(plistlib.loads(bottle_plist))
    except PLIST_ERRORS as e:
        msg = "the escrow record does not hold a bottle"
        raise WrongEscrowPasscodeError(msg) from e
    entropy = blob(bottle, "BottledPeerEntropy")
    if entropy is None:
        msg = "the escrow record holds no bottle entropy"
        raise EscrowError(msg)
    return entropy
