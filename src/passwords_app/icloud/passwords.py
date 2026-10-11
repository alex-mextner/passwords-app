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

Deleting a login, as the Passwords app does it, moves both records into Recently Deleted
access groups (`moved_login`); those logins pair only with each other, never with live ones.
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
from passwords_app.core.urls import site_key, url_domain
from passwords_app.icloud.values import PLIST_ERRORS

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence

AGRP_LOGIN = "com.apple.cfnetwork"
AGRP_SIDECAR = "com.apple.password-manager"
# Apple's Passwords app deletes by moving a login and its sidecar into these groups (its
# Recently Deleted list, purged after 30 days); the records keep their names and attributes.
AGRP_LOGIN_DELETED = "com.apple.cfnetwork-recently-deleted"
AGRP_SIDECAR_DELETED = "com.apple.password-manager-recently-deleted"
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


def is_login(attrs: Mapping[str, object], *, deleted: bool = False) -> bool:
    """Tell whether `attrs` is a website login (`deleted`: one in Recently Deleted instead)."""
    agrp = AGRP_LOGIN_DELETED if deleted else AGRP_LOGIN
    return attrs.get("agrp") == agrp and attrs.get("class", "inet") == "inet"


def is_sidecar(attrs: Mapping[str, object], *, deleted: bool = False) -> bool:
    return attrs.get("agrp") == (AGRP_SIDECAR_DELETED if deleted else AGRP_SIDECAR)


def pair_logins(items: Iterable[StoredItem], *, deleted: bool = False) -> list[Login]:
    """Join each login with its sidecar; items that are neither are left out.

    A sidecar matches on the login's full key first, then on (server, account, protocol, port)
    alone, so a path or domain Apple rewrote still joins while a sidecar left behind by a login
    on another port never does. A key shared by several unjoined logins or sidecars joins
    nothing, since any choice could show one login's notes on another; each sidecar joins at
    most one login. `deleted` pairs the logins in Apple's Recently Deleted instead of the live
    ones; the two never mix.
    """
    logins, sidecars = _logins_and_sidecars(items, deleted=deleted)
    joined = _join_sidecars(logins, sidecars)
    return [Login(it, joined.get(it.record_name)) for it in logins]


def _logins_and_sidecars(
    items: Iterable[StoredItem], *, deleted: bool
) -> tuple[list[StoredItem], list[StoredItem]]:
    logins: list[StoredItem] = []
    sidecars: list[StoredItem] = []
    for it in items:
        if is_login(it.attrs, deleted=deleted):
            logins.append(it)
        elif is_sidecar(it.attrs, deleted=deleted):
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


# --- one login on several websites -----------------------------------------------------------
# Apple keeps a login used on several websites of one domain as one record per website, all
# with the same account and password, and the Passwords app shows them as one entry. Read
# one by one they would be separate logins, each with a "reused password" warning.


def _age(login: Login) -> tuple[datetime, str]:
    return _aware(login.item.attrs.get("cdat")) or _APPLE_EPOCH, login.record_name


def _domain(attrs: Mapping[str, object]) -> str | None:
    url = url_of(attrs)
    return url_domain(url) if url is not None else None


class _Groups:
    """Union-find over record positions; a group's root is its oldest record."""

    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def root(self, i: int) -> int:
        parent = self._parent
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def join(self, i: int, j: int) -> None:
        a, b = self.root(i), self.root(j)
        self._parent[max(a, b)] = min(a, b)


def _same_account_and_password(order: Sequence[Login]) -> list[list[tuple[int, str]]]:
    """(position, domain) of website records sharing account and password, two or more."""
    buckets: dict[tuple[str, bytes], list[tuple[int, str]]] = {}
    for i, login in enumerate(order):
        password, domain = login.item.attrs.get("v_Data"), _domain(login.item.attrs)
        if isinstance(password, bytes) and password and domain is not None:
            key = (_text(login.item.attrs, "acct"), password)
            buckets.setdefault(key, []).append((i, domain))
    return [members for members in buckets.values() if len(members) > 1]


def group_logins(logins: Iterable[Login]) -> list[tuple[Login, ...]]:
    """Group the records Apple shows as one login, each group oldest record first.

    Records join when they share account and password and either sit on one registrable
    domain or one lists the other's domain among its alternate sites, unless two of them
    hold different titles, notes or one-time codes. The oldest record (creation time, then
    record name) names the login, so its id stays put when Apple adds a website. Raises
    `UnreadableLoginError` for metadata that does not parse.
    """
    order = sorted(logins, key=_age)
    groups = _Groups(len(order))
    for members in _same_account_and_password(order):
        by_domain: dict[str, int] = {}
        for i, domain in members:
            groups.join(by_domain.setdefault(domain, i), i)
        for i, _ in members:
            for site in _alt_sites(sidecar_payload(order[i].sidecar)):
                if (other := by_domain.get(url_domain(site))) is not None:
                    groups.join(i, other)
    found: dict[int, list[Login]] = {}
    for i, login in enumerate(order):
        found.setdefault(groups.root(i), []).append(login)
    out: list[tuple[Login, ...]] = []
    for group in found.values():
        if _metadata_agrees(group):
            out.append(tuple(group))
        else:  # one entry would show one record's title or notes for another's
            out.extend((login,) for login in group)
    return out


def _metadata_agrees(group: Sequence[Login]) -> bool:
    """Whether no two records of `group` hold different titles, notes or one-time codes."""
    if len(group) == 1:
        return True
    payloads = [sidecar_payload(login.sidecar) for login in group]
    return all(
        len({repr(p[key]) for p in payloads if p.get(key)}) <= 1
        for key in ("title", "notes", "totp")
    )


def group_credential(group: Sequence[Login]) -> Credential | None:
    """Return the one `Credential` a group from `group_logins` describes (see `to_credential`).

    Its id and url are the first record's; the other records' websites and every record's
    alternate sites are its alternate sites, and each metadata field comes from the first
    record that has it.
    """
    first = to_credential(group[0])
    if first is None or len(group) == 1:
        return first
    rest = [c for c in map(to_credential, group[1:]) if c is not None]
    sites = _distinct_sites(
        [*(c.url for c in rest), *first.alt_urls, *(site for c in rest for site in c.alt_urls)]
    )
    sites.pop(site_key(first.url), None)
    title, notes, otpauth = _first_metadata((first, *rest))
    return dataclasses.replace(
        first,
        alt_urls=tuple(sites.values()),
        modified=max(c.modified for c in (first, *rest)),
        title=title,
        notes=notes,
        otpauth=otpauth,
    )


def _first_metadata(creds: Sequence[Credential]) -> tuple[str | None, str | None, str | None]:
    """Return the title, notes and one-time code, each from the first credential with one."""
    title = notes = otpauth = None
    for cred in reversed(creds):
        title, notes, otpauth = cred.title or title, cred.notes or notes, cred.otpauth or otpauth
    return title, notes, otpauth


def _distinct_sites(sites: Iterable[str]) -> dict[str, str]:
    """Return the first spelling of each website (see `site_key`), by its key, in order."""
    out: dict[str, str] = {}
    for site in sites:
        out.setdefault(site_key(site), site)
    return out


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


def moved_login(login: Login, now: datetime, *, deleted: bool) -> Login:
    """Move the login and its sidecar into Apple's Recently Deleted (`deleted`) or back out.

    This is how the Passwords app deletes and recovers a login: the records keep their names
    and attributes, only the access group changes (and the modification time, dating the move).
    """
    login_group, sidecar_group = (
        (AGRP_LOGIN_DELETED, AGRP_SIDECAR_DELETED) if deleted else (AGRP_LOGIN, AGRP_SIDECAR)
    )

    def move(it: StoredItem, agrp: str) -> StoredItem:
        return StoredItem(it.record_name, _sealed({**it.attrs, "agrp": agrp, "mdat": now}))

    side = move(login.sidecar, sidecar_group) if login.sidecar is not None else None
    return Login(move(login.item, login_group), side)


@dataclasses.dataclass(frozen=True, slots=True)
class GroupSave:
    """What every record of a login on several websites becomes when it is saved."""

    records: tuple[tuple[Login, LoginAttributes], ...]  # in the group's order
    dropped: frozenset[str]  # record names moved to Recently Deleted


def updated_group(group: Sequence[Login], cred: Credential, now: datetime) -> GroupSave:
    """Rewrite a group from `group_logins` to `cred`, never adding a record.

    The first record takes `cred.url`. Every other record keeps its own website while `cred`
    lists it and moves to Recently Deleted otherwise, or when the first record takes over its
    website. Alternate sites stay with the record that lists them while `cred` keeps them, so
    a group joined through them stays joined; a new website becomes an alternate site of the
    first record. A record's title, notes or one-time code is replaced by `cred`'s, so the
    group reads back as `cred`.
    """
    first = group[0]
    kept = _kept_records(group, cred)
    alt = _alt_sites_by_record((first, *kept), cred)
    live = {login.record_name for login in (first, *kept)}
    records: list[tuple[Login, LoginAttributes]] = []
    for login in group:
        if login.record_name in live:
            target = _record_target(login, cred, alt[login.record_name], first=login is first)
            records.append((login, updated_login(login, target, now)))
        else:
            moved = moved_login(login, now, deleted=True)
            side = moved.sidecar.attrs if moved.sidecar is not None else None
            records.append((login, LoginAttributes(moved.item.attrs, side)))
    dropped = frozenset(login.record_name for login in group) - live
    return GroupSave(tuple(records), dropped)


def _record_site(login: Login) -> str:
    return site_key(url_of(login.item.attrs) or "")


def _kept_records(group: Sequence[Login], cred: Credential) -> list[Login]:
    """Return the records after the first that keep their website (see `updated_group`)."""
    wanted = {site_key(site) for site in (cred.url, *cred.alt_urls)}
    main = site_key(cred.url)
    taken = main if _record_site(group[0]) != main else None
    return [
        login
        for login in group[1:]
        if _record_site(login) in wanted and _record_site(login) != taken
    ]


def _alt_sites_by_record(live: Sequence[Login], cred: Credential) -> dict[str, list[str]]:
    """Each live record's alternate sites; websites no record holds go to the first one."""
    wanted = {site_key(site) for site in (cred.url, *cred.alt_urls)}
    alt = {
        login.record_name: [
            site for site in _alt_sites(sidecar_payload(login.sidecar)) if site_key(site) in wanted
        ]
        for login in live
    }
    first = alt[live[0].record_name]
    first.extend(_unlinked_sites(live, cred, alt))
    covered = {site_key(cred.url), *(_record_site(login) for login in live[1:])}
    covered.update(site_key(site) for sites in alt.values() for site in sites)
    for key, site in _distinct_sites(cred.alt_urls).items():
        if key not in covered:
            first.append(site)
    return alt


def _unlinked_sites(
    live: Sequence[Login], cred: Credential, alt: Mapping[str, list[str]]
) -> list[str]:
    """Websites the first record must list so every live record still joins it.

    `group_logins` joins records on one domain, and a record to one whose domain it lists
    among its alternate sites. Records the saved group would not reach that way from the
    first one (on `cred.url`'s domain) get their website added to its alternate sites.
    """
    reached = {url_domain(cred.url)}  # domains of records joined to the first one
    listed = {url_domain(site) for site in alt[live[0].record_name]}
    pending = {
        login.record_name: (domain, url)
        for login in live[1:]
        if (domain := _domain(login.item.attrs)) and (url := url_of(login.item.attrs))
    }
    out: list[str] = []
    while pending:
        name = _joining(pending, alt, reached, listed)
        if name is None:  # bridge the oldest stray record through the first one
            name = next(iter(pending))
            out.append(pending[name][1])
        reached.add(pending.pop(name)[0])
        listed.update(url_domain(site) for site in alt[name])
    return out


def _joining(
    pending: Mapping[str, tuple[str, str]],
    alt: Mapping[str, list[str]],
    reached: set[str],
    listed: set[str],
) -> str | None:
    """Return a pending record `group_logins` joins to one already reached, if any."""
    for name, (domain, _) in pending.items():
        own = {url_domain(site) for site in alt[name]}
        if domain in reached or domain in listed or own & reached:
            return name
    return None


def _record_target(login: Login, cred: Credential, alt: list[str], *, first: bool) -> Credential:
    """Return what one live record of the group is saved as."""
    target = dataclasses.replace(cred, alt_urls=tuple(alt))
    if first:
        return target
    # Another record keeps its id and website, and only the metadata it already has.
    current = to_credential(login)
    return dataclasses.replace(
        target,
        id=login.record_name,
        url=url_of(login.item.attrs) or cred.url,
        title=cred.title if current and current.title else None,
        notes=cred.notes if current and current.notes else None,
        otpauth=cred.otpauth if current and current.otpauth else None,
    )
