# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Website logins as iCloud Keychain stores them, mapped to and from `Credential`.

A login is an `inet` item in access group `com.apple.cfnetwork` (server, account, password)
plus an optional Passwords-app sidecar in `com.apple.password-manager` whose `v_Data` is a
binary plist (title, notes, one-time-code setup, alternate sites, password history). The two
are joined on (server, account), case-insensitively; the sidecar's label is
"Password Manager Metadata: <server> (<account>)".

Rewrites start from the decrypted originals and replace only the fields that changed, so
attributes this client does not know about (and Apple adds over time) survive an edit.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import plistlib
import urllib.parse
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from passwords_app.core.model import Credential
from passwords_app.icloud.values import PLIST_ERRORS

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

AGRP_LOGIN = "com.apple.cfnetwork"
AGRP_SIDECAR = "com.apple.password-manager"
SIDECAR_LABEL = "Password Manager Metadata: "
SIDECAR_DESCRIPTION = "Password Manager Metadata"
SIDECAR_TYPE = int.from_bytes(b"mine", "big")  # FourCC 'mine'
LOGIN_DESCRIPTION = "Web form password"

_APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)
_SCHEME_TO_PTCL = {"https": "htps", "http": "http", "ftp": "ftp "}
_PTCL_TO_SCHEME = {v: k for k, v in _SCHEME_TO_PTCL.items()}
_DEFAULT_PORT = {"https": 443, "http": 80, "ftp": 21}
_TOTP_ALGORITHMS = ("SHA1", "SHA256", "SHA512")

Attributes = dict[str, object]


class UnsupportedCredentialError(ValueError):
    """A credential iCloud Keychain cannot store as a website login (e.g. a non-web URL)."""


class UnreadableLoginError(ValueError):
    """A website login on iCloud whose password or metadata this client cannot read."""


class DuplicateLoginError(UnsupportedCredentialError):
    """Another login already has this site and account; Apple's keychain allows only one."""


@dataclasses.dataclass(frozen=True, slots=True)
class StoredItem:
    """A decrypted keychain item and the record name it lives under."""

    record_name: str
    attrs: Attributes


@dataclasses.dataclass(frozen=True, slots=True)
class Login:
    """A login item with its sidecar, if it has one."""

    item: StoredItem
    sidecar: StoredItem | None

    @property
    def record_name(self) -> str:
        return self.item.record_name


@dataclasses.dataclass(frozen=True, slots=True)
class LoginAttributes:
    """What to write for a login: its item and, when it carries metadata, its sidecar."""

    item: Attributes
    sidecar: Attributes | None


# --- reading ---------------------------------------------------------------------------------


def _text(attrs: Mapping[str, object], key: str) -> str:
    value = attrs.get(key)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value if isinstance(value, str) else ""


def _join_key(attrs: Mapping[str, object]) -> tuple[str, str]:
    return _text(attrs, "srvr").lower(), _text(attrs, "acct").lower()


def primary_key(attrs: Mapping[str, object]) -> tuple[object, ...]:
    """Return the inet item's identity in Apple's keychain, minus the access group.

    Two logins with the same key cannot coexist (errSecDuplicateItem), and a sidecar carries
    its login's key under its own access group.
    """
    port = attrs.get("port")
    return (
        *_join_key(attrs),
        _ptcl(attrs.get("ptcl")),
        port if isinstance(port, int) else 0,
        _text(attrs, "path"),
        _text(attrs, "sdmn"),
        _text(attrs, "atyp"),
    )


def _fallback_key(attrs: Mapping[str, object]) -> tuple[object, ...]:
    return primary_key(attrs)[:4]


def _key_of(attrs: Mapping[str, object]) -> Attributes:
    return {k: attrs[k] for k in _PRIMARY_KEY_ATTRS if k in attrs}


# The attributes `primary_key` reads, copied from a login onto a sidecar created for it.
_PRIMARY_KEY_ATTRS = ("srvr", "acct", "ptcl", "port", "path", "sdmn", "atyp")


def is_login(attrs: Mapping[str, object]) -> bool:
    return attrs.get("agrp") == AGRP_LOGIN and attrs.get("class", "inet") == "inet"


def is_sidecar(attrs: Mapping[str, object]) -> bool:
    return attrs.get("agrp") == AGRP_SIDECAR


def pair_logins(items: Iterable[StoredItem]) -> list[Login]:
    """Join each login with its sidecar; items that are neither are left out.

    A sidecar matches on the login's full key first, then on (server, account, protocol, port)
    alone, so a path or domain Apple rewrote still joins while a sidecar left behind by a login
    on another port never does. A key shared by several unjoined logins or sidecars joins
    nothing, since any choice could show one login's notes on another; each sidecar joins at
    most one login.
    """
    logins, sidecars = _logins_and_sidecars(items)
    joined = _join_sidecars(logins, sidecars)
    return [Login(it, joined.get(it.record_name)) for it in logins]


def _logins_and_sidecars(items: Iterable[StoredItem]) -> tuple[list[StoredItem], list[StoredItem]]:
    logins: list[StoredItem] = []
    sidecars: list[StoredItem] = []
    for it in items:
        if is_login(it.attrs):
            logins.append(it)
        elif is_sidecar(it.attrs):
            sidecars.append(it)
    return logins, sidecars


def _join_sidecars(logins: list[StoredItem], sidecars: list[StoredItem]) -> dict[str, StoredItem]:
    """Each joined login's sidecar, by the login's record name (see `pair_logins`)."""
    joined: dict[str, StoredItem] = {}
    for key in (primary_key, _fallback_key):
        taken = {s.record_name for s in joined.values()}
        free_sides = _unique_by(key, [s for s in sidecars if s.record_name not in taken])
        free_logins = _unique_by(key, [lg for lg in logins if lg.record_name not in joined])
        for k, login in free_logins.items():
            if (side := free_sides.get(k)) is not None:
                joined[login.record_name] = side
    return joined


def _unique_by(
    key: Callable[[Mapping[str, object]], tuple[object, ...]], items: Iterable[StoredItem]
) -> dict[tuple[object, ...], StoredItem]:
    """Items by key, leaving out every key more than one item has."""
    out: dict[tuple[object, ...], StoredItem] = {}
    shared: set[tuple[object, ...]] = set()
    for it in items:
        k = key(it.attrs)
        if k in out or k in shared:
            out.pop(k, None)
            shared.add(k)
        else:
            out[k] = it
    return out


def sidecar_payload(sidecar: StoredItem | None) -> Attributes:
    """Return the sidecar's metadata, `{}` when it holds none.

    Raises `UnreadableLoginError` when there is a payload that does not parse: reading it as
    empty would report the notes, title and code as deleted.
    """
    if sidecar is None:
        return {}
    blob = sidecar.attrs.get("v_Data")
    if blob is None or blob == b"":
        return {}
    try:
        payload = plistlib.loads(blob, aware_datetime=True) if isinstance(blob, bytes) else None
    except PLIST_ERRORS as e:
        msg = f"the metadata of {sidecar.record_name} cannot be read"
        raise UnreadableLoginError(msg) from e
    if not isinstance(payload, dict):
        msg = f"the metadata of {sidecar.record_name} is not a dictionary"
        raise UnreadableLoginError(msg)
    return {str(k): v for k, v in cast("dict[object, object]", payload).items()}


def _aware(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return None


def _ptcl(value: object) -> str:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        try:
            return value.to_bytes(4, "big").decode("ascii")
        except (OverflowError, UnicodeDecodeError):
            return ""
    return value if isinstance(value, str) else ""


def url_of(attrs: Mapping[str, object]) -> str | None:
    """`scheme://host[:port][path]` from ptcl/srvr/port/path, or None without a server."""
    host = _text(attrs, "srvr").strip()
    if not host:
        return None
    scheme = _PTCL_TO_SCHEME.get(_ptcl(attrs.get("ptcl")), "https")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # an IPv6 literal
    port = attrs.get("port")
    suffix = ""
    if (
        isinstance(port, int)
        and not isinstance(port, bool)
        and port not in {0, _DEFAULT_PORT[scheme]}
    ):
        suffix = f":{port}"
    path = _text(attrs, "path")
    if path and not path.startswith(("/", "?")):  # "?q" is a query on the bare host
        path = "/" + path
    return f"{scheme}://{host}{suffix}{path}"


_OTP_FIELDS = ("secret", "algorithm", "digits", "period")
_OTP_DEFAULTS: dict[str, object] = {"algorithm": 0, "digits": 6, "period": 30}


def otpauth_from_totp(block: object, *, account: str = "") -> str | None:
    """Build an `otpauth://totp` URI for a sidecar `totp` dictionary; None without a secret.

    The URI the code was set up with (`originalURL`) is returned verbatim while it still
    describes the same code, so a URI written by this client reads back unchanged.
    """
    if not isinstance(block, dict):
        return None
    totp = cast("dict[str, object]", block)
    secret = totp.get("secret")
    if not isinstance(secret, bytes) or not secret:
        return None
    original = _current_original_url(totp)
    if original is not None:
        return original
    issuer = _text(totp, "issuer")
    name = _text(totp, "accountName") or account
    label = ":".join(p for p in (issuer, name) if p) or "iCloud"
    params = _otpauth_params(totp, secret, issuer)
    return f"otpauth://totp/{urllib.parse.quote(label)}?{urllib.parse.urlencode(params)}"


def _current_original_url(totp: Mapping[str, object]) -> str | None:
    """Return a `totp` dictionary's `originalURL` while it still describes the same code."""
    original = _text(totp, "originalURL")
    if not original.startswith("otpauth://totp/"):
        return None
    try:
        parsed = totp_from_otpauth(original)
    except UnsupportedCredentialError:
        parsed = {}
    if all(parsed.get(k) == totp.get(k, _OTP_DEFAULTS.get(k)) for k in _OTP_FIELDS):
        return original
    return None


def _otpauth_params(totp: Mapping[str, object], secret: bytes, issuer: str) -> dict[str, str]:
    algorithm = totp.get("algorithm")
    params: dict[str, str] = {"secret": base64.b32encode(secret).decode().rstrip("=")}
    if isinstance(algorithm, int) and 0 <= algorithm < len(_TOTP_ALGORITHMS):
        params["algorithm"] = _TOTP_ALGORITHMS[algorithm]
    for key in ("digits", "period"):
        value = totp.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            params[key] = str(value)
    if issuer:
        params["issuer"] = issuer
    return params


def _alt_sites(payload: Mapping[str, object]) -> tuple[str, ...]:
    raw = payload.get("s_as")
    out: list[str] = []
    for entry in cast("list[object]", raw) if isinstance(raw, list) else []:
        if isinstance(entry, dict):
            site = cast("dict[str, object]", entry).get("s")
            if isinstance(site, str) and site:
                out.append(site)
    return tuple(out)


def _optional_text(payload: Mapping[str, object], key: str) -> str | None:
    return _text(payload, key) or None


def to_credential(
    login: Login, *, item_id: str | None = None, group: str | None = None
) -> Credential | None:
    """Return the `Credential` a login describes, or None if it is not a website login.

    Raises `UnreadableLoginError` for a website login whose password or metadata cannot be
    read: leaving it out would read as its deletion.
    """
    attrs = login.item.attrs
    url = url_of(attrs)
    if url is None:
        return None
    secret = _password_text(login)
    payload = sidecar_payload(login.sidecar)
    username = _text(attrs, "acct")
    created = _aware(attrs.get("cdat")) or _APPLE_EPOCH
    modified = _modified(login, created)
    return Credential(
        id=item_id or login.record_name,
        url=url,
        username=username,
        password=secret,
        created=created,
        modified=modified,
        title=_optional_text(payload, "title"),
        notes=_optional_text(payload, "notes"),
        otpauth=otpauth_from_totp(payload.get("totp"), account=username),
        alt_urls=_alt_sites(payload),
        group=group,
    )


def _password_text(login: Login) -> str:
    password = login.item.attrs.get("v_Data", b"")
    try:
        secret = password.decode("utf-8") if isinstance(password, bytes) else None
    except UnicodeDecodeError:
        secret = None
    if secret is None:
        msg = f"the password of {login.record_name} is not text"
        raise UnreadableLoginError(msg)
    return secret


def _modified(login: Login, created: datetime) -> datetime:
    """Return the later of the login's and its sidecar's modification times."""
    modified = _aware(login.item.attrs.get("mdat")) or created
    if login.sidecar is not None:
        side_modified = _aware(login.sidecar.attrs.get("mdat"))
        if side_modified is not None and side_modified > modified:
            modified = side_modified
    return modified


# --- writing ---------------------------------------------------------------------------------


def _url_attrs(url: str) -> Attributes:
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    ptcl = _SCHEME_TO_PTCL.get(scheme)
    host = parts.hostname
    if ptcl is None or not host:
        msg = f"not a website address: {url!r}"
        raise UnsupportedCredentialError(msg)
    try:
        port = parts.port or 0
    except ValueError as e:
        msg = f"bad port in {url!r}"
        raise UnsupportedCredentialError(msg) from e
    if parts.fragment or parts.username is not None or parts.password is not None:
        # The keychain has no place for a fragment or user information; dropping either
        # would change the login on reread.
        msg = f"a fragment or user information cannot be stored: {url!r}"
        raise UnsupportedCredentialError(msg)
    path = parts.path
    if parts.query:
        path += "?" + parts.query
    return {"srvr": host, "ptcl": ptcl, "port": port, "path": path}


def totp_from_otpauth(uri: str, previous: object = None) -> Attributes:
    """Build the sidecar `totp` dictionary for an otpauth URI, keeping fields it cannot carry."""
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme != "otpauth" or parts.netloc != "totp":
        msg = "only otpauth://totp one-time codes are supported"
        raise UnsupportedCredentialError(msg)
    query = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query).items() if v}
    secret = _otp_secret(query)
    label = urllib.parse.unquote(parts.path.lstrip("/"))
    label_issuer, _, label_account = label.rpartition(":")
    totp: Attributes = (
        dict(cast("dict[str, object]", previous)) if isinstance(previous, dict) else {}
    )
    totp["secret"] = secret
    totp.update(_otp_settings(query))
    issuer = query.get("issuer") or label_issuer
    if issuer:
        totp["issuer"] = issuer
    else:
        totp.pop("issuer", None)
    if label_account:
        totp["accountName"] = label_account
    totp["originalURL"] = uri
    return totp


def _otp_secret(query: Mapping[str, str]) -> bytes:
    raw = query.get("secret", "").replace(" ", "").upper()
    try:
        secret = base64.b32decode(raw + "=" * (-len(raw) % 8))
    except (binascii.Error, ValueError) as e:
        msg = "the one-time-code secret is not base32"
        raise UnsupportedCredentialError(msg) from e
    if not secret:
        msg = "the one-time-code setup has no secret"
        raise UnsupportedCredentialError(msg)
    return secret


def _otp_settings(query: Mapping[str, str]) -> Attributes:
    """`algorithm`, `digits` and `period` from an otpauth query, defaulting what is missing."""
    algorithm = query.get("algorithm", "SHA1").upper()
    settings: Attributes = {
        "algorithm": _TOTP_ALGORITHMS.index(algorithm) if algorithm in _TOTP_ALGORITHMS else 0
    }
    for key, default in (("digits", 6), ("period", 30)):
        value = query.get(key, "")
        # isascii: "²".isdigit() is true, but int() refuses it.
        settings[key] = int(value) if value.isascii() and value.isdigit() else default
    return settings


def _item_hash(attrs: Mapping[str, object]) -> bytes:
    """`sha1`: a digest of the item's content.

    Apple's exact digest input is not public; receivers store it rather than recompute it, so a
    stable content digest keeps unchanged items byte-identical across rewrites.
    """
    body = {k: v for k, v in attrs.items() if k != "sha1"}
    # nosemgrep: insecure-hash-algorithm-sha1 - the keychain schema's `sha1` content fingerprint
    return hashlib.sha1(_plist(body), usedforsecurity=False).digest()


def _label(host: str, account: str) -> str:
    return f"{host} ({account})"


def _base_item(cred: Credential, now: datetime) -> Attributes:
    url = _url_attrs(cred.url)
    return {
        "class": "inet",
        "acct": cred.username,
        "atyp": "form",
        "cdat": cred.created,
        "mdat": now,
        "musr": b"",
        "pdmn": "ak",
        "sdmn": "",
        "tomb": 0,
        **url,
    }


def _payload_with(payload: Attributes, cred: Credential) -> Attributes:
    """`payload` with the credential's metadata replaced; untouched keys stay as they were."""
    out = dict(payload)
    for key, value in (("title", cred.title), ("notes", cred.notes)):
        if value:
            if _text(out, key) != value:
                out[key] = value.encode()
        else:
            out.pop(key, None)
    if cred.otpauth:
        if otpauth_from_totp(out.get("totp"), account=cred.username) != cred.otpauth:
            out["totp"] = totp_from_otpauth(cred.otpauth, out.get("totp"))
    else:
        out.pop("totp", None)
    if _alt_sites(out) != cred.alt_urls:
        if cred.alt_urls:
            out["s_as"] = [{"s": site} for site in cred.alt_urls]
        else:
            out.pop("s_as", None)
    return out


def _has_metadata(cred: Credential) -> bool:
    return bool(cred.title or cred.notes or cred.otpauth or cred.alt_urls)


def _sealed(attrs: Attributes) -> Attributes:
    attrs["sha1"] = _item_hash(attrs)
    return attrs


def new_login(cred: Credential, now: datetime) -> LoginAttributes:
    """Attributes for a brand-new login (and its sidecar when it has metadata)."""
    base = _base_item(cred, now)
    host = str(base["srvr"])
    item = {
        **base,
        "agrp": AGRP_LOGIN,
        "labl": _label(host, cred.username),
        "desc": LOGIN_DESCRIPTION,
        "v_Data": cred.password.encode(),
    }
    sidecar = None
    if _has_metadata(cred):
        sidecar = {
            **base,
            "agrp": AGRP_SIDECAR,
            "labl": SIDECAR_LABEL + _label(host, cred.username),
            "desc": SIDECAR_DESCRIPTION,
            "type": SIDECAR_TYPE,
            "v_Data": _plist(_payload_with({}, cred)),
        }
    return LoginAttributes(_sealed(item), _sealed(sidecar) if sidecar is not None else None)


def _plist(payload: Mapping[str, object]) -> bytes:
    return plistlib.dumps(
        dict(payload), fmt=plistlib.FMT_BINARY, sort_keys=True, aware_datetime=True
    )


def _rehome(attrs: Attributes, cred: Credential, *, label_prefix: str) -> None:
    """Point an item at the credential's site and account, keeping a custom label."""
    old_label = _label(_text(attrs, "srvr"), _text(attrs, "acct"))
    url_changed = url_of(attrs) != cred.url
    if url_changed:
        attrs.update(_url_attrs(cred.url))
    attrs["acct"] = cred.username
    if _text(attrs, "labl") in {label_prefix + old_label, ""}:
        attrs["labl"] = label_prefix + _label(_text(attrs, "srvr"), cred.username)


def updated_login(login: Login, cred: Credential, now: datetime) -> LoginAttributes:
    """Rewrite the login to `cred`: the original attributes with only changed fields replaced.

    A changed site or account rewrites both records so they stay joined; a sidecar is created
    when the login gains metadata and emptied (not deleted) when it loses it, as Apple does.
    """
    current = to_credential(login)
    item = dict(login.item.attrs)
    moved = current is None or (current.url, current.username) != (cred.url, cred.username)
    changed = False
    if moved:
        _rehome(item, cred, label_prefix="")
        changed = True
    if item.get("v_Data") != cred.password.encode():
        item["v_Data"] = cred.password.encode()
        changed = True
    if changed:
        item["mdat"] = now
        _sealed(item)

    sidecar: Attributes | None = None
    if login.sidecar is not None:
        sidecar = _updated_sidecar(login.sidecar, item, cred, now, moved=moved)
    elif _has_metadata(cred):
        sidecar = new_login(dataclasses.replace(cred, created=now), now).sidecar
        if sidecar is not None:
            # Take the item's own primary key, not one rebuilt from its URL: two logins can
            # share a URL (port 443 vs unset), and a rebuilt key would join the other one.
            sidecar.update(_key_of(item))
            _sealed(sidecar)
    return LoginAttributes(item, sidecar)


def _updated_sidecar(
    side: StoredItem, item: Attributes, cred: Credential, now: datetime, *, moved: bool
) -> Attributes:
    sidecar = dict(side.attrs)
    payload = sidecar_payload(side)  # raises rather than overwrite metadata it cannot read
    new_payload = _payload_with(payload, cred)
    side_changed = moved
    if moved:
        _rehome(sidecar, cred, label_prefix=SIDECAR_LABEL)
        # The renamed login keeps attributes its URL does not show (an explicit default
        # port); its sidecar must carry the same key or it stops joining.
        sidecar.update(_key_of(item))
    if new_payload != payload:
        sidecar["v_Data"] = _plist(new_payload)
        side_changed = True
    if side_changed:
        sidecar["mdat"] = now
        _sealed(sidecar)
    return sidecar
