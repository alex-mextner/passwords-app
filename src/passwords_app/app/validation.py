# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Edit-form validation, run before Save so the daemon only ever sees well-formed input.

A verification-code field accepts what users actually have: an `otpauth://` URI from a QR code
or the bare "setup key" a website prints; the latter becomes an `otpauth://` URI here.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from urllib.parse import quote, urlsplit

from passwords_app.app.i18n import _, ngettext
from passwords_app.app.records import Draft, display_host
from passwords_app.core.otp import OtpError, parse_otpauth
from passwords_app.core.urls import normalize_url

MAX_TITLE = 256
MAX_USERNAME = 512
MAX_PASSWORD = 4096
MAX_NOTES = 10_000
_SETUP_KEY = re.compile(r"[A-Z2-7]+=*")
# An explicit scheme only at the start: "example.com/?next=https://…" has none.
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")


class Field(StrEnum):
    URL = "url"
    USERNAME = "username"
    PASSWORD = "password"  # noqa: S105 - a field name, not a secret
    TITLE = "title"
    NOTES = "notes"
    OTPAUTH = "otpauth"
    ALT_URLS = "alt_urls"


@dataclass(frozen=True, slots=True)
class Validation:
    draft: Draft
    errors: dict[Field, str]

    @property
    def ok(self) -> bool:
        return not self.errors


def _web_url(text: str) -> str:
    """Return the normalized http(s) URL; ValueError with a user-facing message otherwise."""
    stripped = text.strip()
    if not stripped:
        raise ValueError(_("Enter a website"))
    explicit = _SCHEME.match(stripped) is not None
    scheme = urlsplit(stripped).scheme.lower() if explicit else "https"
    if scheme not in {"http", "https"}:
        raise ValueError(_("Use a web address such as example.com"))
    try:
        normalized = normalize_url(stripped)
    except ValueError:
        raise ValueError(_("This is not a valid web address")) from None
    # The parser also accepts forms without "//" (`file:\\host\share`); only the result tells.
    if urlsplit(normalized).scheme not in {"http", "https"}:
        raise ValueError(_("Use a web address such as example.com"))
    # The canonical form drops the query and fragment, but they are part of where the login
    # page is (`/#/login`, a tenant parameter); keep them so saving never moves the link.
    original = urlsplit(stripped if explicit else f"https://{stripped}")
    if not (original.query or original.fragment):
        return normalized
    path = "" if urlsplit(normalized).path else "/"
    query = f"?{original.query}" if original.query else ""
    fragment = f"#{original.fragment}" if original.fragment else ""
    return f"{normalized}{path}{query}{fragment}"


def setup_key_to_otpauth(key: str, *, account: str, issuer: str) -> str:
    """Turn a printed setup key (`JBSW Y3DP EHPK 3PXP`) into an `otpauth://totp/` URI."""
    compact = re.sub(r"[\s-]", "", key).upper()
    if not _SETUP_KEY.fullmatch(compact):
        raise ValueError(_("A setup key contains only letters A–Z and digits 2–7"))  # noqa: RUF001 - typographic dash in UI text
    padded = compact.rstrip("=")
    padded += "=" * (-len(padded) % 8)
    try:
        secret = base64.b32decode(padded)
    except binascii.Error:
        raise ValueError(_("This setup key is incomplete")) from None
    if len(secret) < 10:  # noqa: PLR2004 - RFC 4226 requires at least 128 bits; 80 is common
        raise ValueError(_("This setup key is too short"))
    label = quote(f"{issuer}:{account}" if issuer else account, safe="@:")
    query = f"secret={compact.rstrip('=')}"
    if issuer:
        query += f"&issuer={quote(issuer, safe='')}"
    return f"otpauth://totp/{label}?{query}"


def _code(draft: Draft) -> str:
    text = draft.otpauth.strip()
    if not text:
        return ""
    if text.lower().startswith("otpauth:"):
        try:
            parse_otpauth(text)
        except OtpError:
            raise ValueError(_("This verification code link is not valid")) from None
        return text
    return setup_key_to_otpauth(
        text,
        account=draft.username or display_host(draft.url),
        issuer=draft.title or display_host(draft.url),
    )


def _limit(what: str, n: int) -> str:
    messages = {
        "Passwords": ngettext(
            "Passwords are limited to {n} character", "Passwords are limited to {n} characters", n
        ),
        "User names": ngettext(
            "User names are limited to {n} character", "User names are limited to {n} characters", n
        ),
        "Titles": ngettext(
            "Titles are limited to {n} character", "Titles are limited to {n} characters", n
        ),
        "Notes": ngettext(
            "Notes are limited to {n} character", "Notes are limited to {n} characters", n
        ),
    }
    return messages[what].format(n=n)


def _alt_urls(draft: Draft, url: str, errors: dict[Field, str]) -> tuple[str, ...]:
    """Return the normalized, deduplicated extra websites minus the main one; record bad ones."""
    alt_urls: list[str] = []
    for raw in draft.alt_urls:
        if not raw.strip():
            continue
        try:
            alt_urls.append(_web_url(raw))
        except ValueError:
            errors[Field.ALT_URLS] = _("“{url}” is not a valid web address").format(url=raw.strip())
    return tuple(u for u in dict.fromkeys(alt_urls) if u != url)


def validate(draft: Draft) -> Validation:
    """Check every field; return the normalized draft and per-field messages."""
    errors: dict[Field, str] = {}
    url = draft.url
    try:
        url = _web_url(draft.url)
    except ValueError as exc:
        errors[Field.URL] = str(exc)

    alt_urls = _alt_urls(draft, url, errors)

    if not draft.password:
        errors[Field.PASSWORD] = _("Enter a password")
    elif len(draft.password) > MAX_PASSWORD:
        errors[Field.PASSWORD] = _limit("Passwords", MAX_PASSWORD)
    if len(draft.username) > MAX_USERNAME:
        errors[Field.USERNAME] = _limit("User names", MAX_USERNAME)
    if len(draft.title) > MAX_TITLE:
        errors[Field.TITLE] = _limit("Titles", MAX_TITLE)
    if len(draft.notes) > MAX_NOTES:
        errors[Field.NOTES] = _limit("Notes", MAX_NOTES)

    # D-Bus strings end at NUL, so the daemon would store a silently shortened value.
    for what, value in (
        (Field.PASSWORD, draft.password),
        (Field.USERNAME, draft.username),
        (Field.TITLE, draft.title),
        (Field.NOTES, draft.notes),
        (Field.OTPAUTH, draft.otpauth),
    ):
        if "\0" in value:
            errors.setdefault(what, _("Contains a character that cannot be saved"))

    otpauth = draft.otpauth
    try:
        otpauth = _code(draft)
    except ValueError as exc:
        errors[Field.OTPAUTH] = str(exc)

    normalized = replace(
        draft,
        url=url,
        title=draft.title.strip(),
        otpauth=otpauth,
        alt_urls=alt_urls,
    )
    return Validation(draft=normalized, errors=errors)
