# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Turn the label of a keyring item a person typed in Seahorse into a website + username.

Seahorse only lets people type a label and a secret, so the label is all we have. Accepted
shapes (spec §4): ``alice @ example.com``, ``example.com alice``, ``example.com — alice``
(also the en dash and a spaced hyphen; this is the shape our own labels use), and a bare
host or URL. The parser is strict on purpose: a label it cannot read with confidence is
reported back (`UnparseableLabelError`) so the user sees a notification, instead of a
guessed website that would push a password to the wrong site in iCloud. Notable refusals:

- ``alice@example.com`` alone is an e-mail address, not "alice at example.com".
- Hosts are checked with the stdlib IDNA codec (IDNA 2003). A Unicode host must survive the
  ASCII round trip unchanged; otherwise (``straße.de`` → ``strasse.de``, zero-width chars)
  the codec would silently change which site the password belongs to.
- Only http(s) URLs; a password inside the URL is refused rather than stored in the clear.
- Control and bidi-override characters (which can make a label display as something else).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import SplitResult, unquote, urlsplit


class LabelProblem(StrEnum):
    EMPTY = "empty label"
    CONTROL_CHARACTERS = "label contains control characters"
    AMBIGUOUS_EMAIL = "an e-mail address alone does not say which website it is for"
    NO_WEBSITE = "no website in the label"
    UNSUPPORTED_SCHEME = "only http and https websites are supported"
    MALFORMED_URL = "malformed URL"
    CREDENTIALS_IN_URL = "the URL contains a password"
    INVALID_HOST = "invalid host name"
    INVALID_PORT = "invalid port"


class UnparseableLabelError(ValueError):
    def __init__(self, problem: LabelProblem) -> None:
        super().__init__(problem.value)
        self.problem = problem


@dataclass(frozen=True, slots=True)
class ParsedLabel:
    url: str
    username: str


class _SiteError(Exception):
    def __init__(self, problem: LabelProblem) -> None:
        super().__init__(problem.value)
        self.problem = problem


_BIDI_CONTROLS = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
# Em/en dash never occur in host names, so they separate even without spaces; a plain
# hyphen does occur in host names and only separates when surrounded by whitespace.
_DASH = re.compile(r"\s*[\u2014\u2013]\s*|\s+-(?:\s+|$)")
_AT = re.compile(r"\s+@\s*|\s*@\s+")
# "word:" is a scheme unless digits follow (then it is "host:port").
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+-]*):(?!\d+(?:/|$))")
_EMAIL = re.compile(r"^[^\s@/:]+@[^\s@]+$")
_LDH_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
_MAX_HOST_LENGTH = 253
_MAX_PORT = 65535
_WEB_SCHEMES = frozenset({"http", "https"})


def _has_control(text: str) -> bool:
    return any(
        (ord(ch) < 0x20 and ch != "\t") or ord(ch) == 0x7F or ch in _BIDI_CONTROLS  # noqa: PLR2004
        for ch in text
    )


def _looks_like_site(token: str) -> bool:
    return (
        bool(token)
        and (any(ch in token for ch in ".:[") or token.lower() == "localhost")
        and not any(ch.isspace() for ch in token)
    )


def _ascii_host(host: str) -> str:
    try:
        ascii_host = host.encode("idna").decode("ascii")
        round_trip = ascii_host.encode("ascii").decode("idna")
    except UnicodeError as exc:
        raise _SiteError(LabelProblem.INVALID_HOST) from exc
    if not host.isascii() and round_trip != host:
        raise _SiteError(LabelProblem.INVALID_HOST)
    return ascii_host.lower()


def _check_domain(host: str, *, explicit_scheme: bool) -> None:
    ascii_host = _ascii_host(host)
    labels = ascii_host.split(".")
    if len(ascii_host) > _MAX_HOST_LENGTH or not all(_LDH_LABEL.match(lb) for lb in labels):
        raise _SiteError(LabelProblem.INVALID_HOST)
    if len(labels) == 1:
        # A single word is far more likely a title ("Gmail") than an intranet host, unless
        # the person spelled out the scheme.
        if not explicit_scheme and ascii_host != "localhost":
            raise _SiteError(LabelProblem.NO_WEBSITE)
        return
    if labels[-1].isdigit():
        # Dotted numbers that are not a valid IPv4 address ("256.1.1.1", "1.5").
        raise _SiteError(LabelProblem.INVALID_HOST)


def _check_host(parts: SplitResult, *, explicit_scheme: bool) -> str:
    """Return the host as it should appear in the URL (lowercased, brackets for IPv6)."""
    if parts.netloc.rpartition("@")[2].startswith("["):
        # urlsplit has already refused bracketed hosts that are not IPv6 literals.
        return f"[{parts.hostname}]"
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise _SiteError(LabelProblem.INVALID_HOST)
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        _check_domain(host, explicit_scheme=explicit_scheme)
    return host.lower()


def _port(parts: SplitResult) -> int | None:
    try:
        port = parts.port
    except ValueError as exc:
        raise _SiteError(LabelProblem.INVALID_PORT) from exc
    if port is not None and not 0 < port <= _MAX_PORT:
        raise _SiteError(LabelProblem.INVALID_PORT)
    return port


def _split_scheme(token: str) -> tuple[str, str, bool]:
    """Return ``(scheme, rest, explicit_scheme)``; a bare host reads as https."""
    scheme_match = _SCHEME.match(token)
    if scheme_match is None:
        if "@" in token.partition("/")[0]:
            # Without a scheme, "user@host" is an e-mail address, not a site.
            raise _SiteError(LabelProblem.NO_WEBSITE)
        return "https", token, False
    scheme = scheme_match.group(1).lower()
    if scheme not in _WEB_SCHEMES:
        raise _SiteError(LabelProblem.UNSUPPORTED_SCHEME)
    if not token[scheme_match.end() :].startswith("//"):
        raise _SiteError(LabelProblem.MALFORMED_URL)
    return scheme, token[scheme_match.end() + 2 :], True


def _url_username(parts: SplitResult) -> str:
    username = unquote(parts.username) if parts.username else ""
    if _has_control(username):
        # Percent-decoding can produce what the raw-label check could not see (%00, %0A).
        raise _SiteError(LabelProblem.CONTROL_CHARACTERS)
    return username


def _parse_site(token: str) -> tuple[str, str]:
    """Return ``(url, username_from_url)`` for a host or URL token, or raise `_SiteError`."""
    scheme, rest, explicit_scheme = _split_scheme(token)
    try:
        parts = urlsplit(f"{scheme}://{rest}")
    except ValueError as exc:
        raise _SiteError(LabelProblem.MALFORMED_URL) from exc
    if parts.password is not None:
        raise _SiteError(LabelProblem.CREDENTIALS_IN_URL)
    host = _check_host(parts, explicit_scheme=explicit_scheme)
    port = _port(parts)
    path = "" if parts.path == "/" and not parts.query else parts.path
    query = f"?{parts.query}" if parts.query else ""
    authority = host if port is None else f"{host}:{port}"
    return f"{scheme}://{authority}{path}{query}", _url_username(parts)


def _candidates(label: str) -> list[tuple[str, str, bool]]:
    """Every (site, username, explicit-separator) reading of the label, by preference."""
    found: list[tuple[str, str, bool]] = []
    dash = _DASH.search(label)
    if dash is not None:
        found.append((label[: dash.start()], label[dash.end() :], True))
    at_matches = list(_AT.finditer(label))
    if at_matches:
        # The last " @ " separates: usernames may themselves be e-mail addresses.
        last = at_matches[-1]
        found.append((label[last.end() :], label[: last.start()], True))
    words = label.split(maxsplit=1)
    found.append((words[0], words[1] if len(words) > 1 else "", False))
    return found


def parse_label(label: str) -> ParsedLabel:
    """Read a Seahorse label; raise `UnparseableLabelError` when unsure."""
    text = label.strip()
    if not text:
        raise UnparseableLabelError(LabelProblem.EMPTY)
    if _has_control(text):
        raise UnparseableLabelError(LabelProblem.CONTROL_CHARACTERS)
    if _EMAIL.match(text) and "://" not in text:
        raise UnparseableLabelError(LabelProblem.AMBIGUOUS_EMAIL)
    candidates = _candidates(text)
    if any(explicit for _, _, explicit in candidates):
        # The person named the site with a separator; reading the label another way
        # (e.g. a dotted username as the host) would only guess.
        candidates = [c for c in candidates if c[2]]
    return _first_site(candidates)


def _first_site(candidates: list[tuple[str, str, bool]]) -> ParsedLabel:
    """Return the first candidate that names a site, else raise the most specific refusal."""
    specific: LabelProblem | None = None
    for raw_site, username, explicit in candidates:
        site = raw_site.strip()
        if not _looks_like_site(site):
            continue
        try:
            url, url_username = _parse_site(site)
        except _SiteError as exc:
            if exc.problem is not LabelProblem.NO_WEBSITE:
                if explicit:
                    raise UnparseableLabelError(exc.problem) from exc
                specific = specific or exc.problem
            continue
        return ParsedLabel(url=url, username=username.strip() or url_username)
    raise UnparseableLabelError(specific or LabelProblem.NO_WEBSITE)
