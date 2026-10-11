# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""URL normalization and the page-vs-credential match used to decide what autofill may offer.

The invariant this module exists for: a password is never offered to a page whose registrable
domain differs from the one it was saved for. Anything ambiguous (unparsable input, IP literals,
hosts that are themselves public suffixes such as `github.io`) resolves to `MatchKind.NONE`.
"""

from __future__ import annotations

import functools
import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum, auto
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import idna
from publicsuffixlist import PublicSuffixList

if TYPE_CHECKING:
    from passwords_app.core.model import Credential

# Parsing the bundled list costs tens of milliseconds; do it once per process.
_PSL = PublicSuffixList()

_DEFAULT_PORTS = {"https": 443, "http": 80}
_WEB_SCHEMES = frozenset(_DEFAULT_PORTS)
_SPECIAL_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp", "file"})
# IDNA 2003 treats these as label separators, so `пример。рф` is `пример.рф`.
_DOTS = re.compile("[.\u3002\uff0e\uff61]")
_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
# A scheme is only recognised when what follows the colon is not a port number, so that
# `localhost:3000` and `example.com:8080/x` are read as scheme-less host:port.
_SCHEME = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*):(?![0-9]+(?:[/?#]|$))")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class MatchKind(StrEnum):
    EXACT_HOST = auto()
    SAME_SITE = auto()
    NONE = auto()


@dataclass(frozen=True, slots=True)
class _Url:
    scheme: str
    host: str  # punycode, lowercase; IPv6 without brackets
    port: int | None  # only when explicit and not the scheme default
    path: str
    is_ip: bool

    @property
    def effective_port(self) -> int | None:
        return self.port if self.port is not None else _DEFAULT_PORTS.get(self.scheme)


def _ascii_label(label: str) -> str:
    if label.isascii() and not label.lower().startswith("xn--"):
        ascii_label = label.lower()
    else:
        # Browsers map hosts with UTS #46 *non-transitional* processing, where `faß.de` is
        # `xn--fa-hia.de`, not `fass.de` as Python's IDNA 2003 codec would have it. Matching
        # must resolve a name exactly as the browser does, or one site's password is offered
        # on another. A-labels are validated by decoding, which rejects homograph tricks
        # hidden in malformed or non-canonical punycode.
        try:
            ascii_label = idna.encode(
                label, uts46=True, transitional=False, std3_rules=False
            ).decode("ascii")
        except (idna.IDNAError, UnicodeError) as exc:
            msg = "invalid URL: bad host label"
            raise ValueError(msg) from exc
    if not _LABEL.fullmatch(ascii_label):
        msg = "invalid URL: bad host label"
        raise ValueError(msg)
    return ascii_label


def _ipv6_host(bare: str) -> str:
    try:
        return ipaddress.IPv6Address(bare).compressed
    except ValueError as exc:
        msg = "invalid URL: bad IPv6 literal"
        raise ValueError(msg) from exc


def _host_labels(bare: str) -> list[str]:
    labels = _DOTS.split(bare)
    if len(labels) > 1 and labels[-1] == "":
        labels.pop()  # one trailing dot denotes the root, not an empty label
    if not labels or "" in labels:
        msg = "invalid URL: empty host label"
        raise ValueError(msg)
    return [_ascii_label(label) for label in labels]


def _ipv4_host(name: str) -> str:
    try:
        return str(ipaddress.IPv4Address(name))
    except ValueError as exc:
        msg = "invalid URL: bad IPv4 literal"
        raise ValueError(msg) from exc


def _normalize_host(host: str) -> tuple[str, bool]:
    """Return (canonical host, is IP literal). IPv6 comes back without brackets."""
    if _CONTROL.search(host):
        msg = "invalid URL: control character in host"
        raise ValueError(msg)
    bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    if ":" in bare:
        return _ipv6_host(bare), True
    ascii_labels = _host_labels(bare)
    name = ".".join(ascii_labels)
    if ascii_labels[-1].isdigit() or ascii_labels[-1].startswith("0x"):
        # Browsers parse a numeric last label as IPv4 (including `127.1`, `0x7f.0.0.1`); only
        # the canonical dotted quad is accepted so both sides compare as the same string.
        return _ipv4_host(name), True
    if len(name) > 253:  # noqa: PLR2004 - DNS name length limit
        msg = "invalid URL: host too long"
        raise ValueError(msg)
    return name, False


def _browser_text(text: str) -> str:
    """Add the default scheme and read backslashes as slashes the way a browser does."""
    scheme_match = _SCHEME.match(text)
    if scheme_match is None:
        text = "https://" + text
    if scheme_match is None or scheme_match.group(1).lower() in _SPECIAL_SCHEMES:
        # WHATWG URL parsing reads `\` as `/` before the query in special schemes, so the
        # browser sees `https://evil.com\@example.com` as host `evil.com`; do the same.
        end = min((i for i in (text.find("?"), text.find("#")) if i >= 0), default=len(text))
        text = text[:end].replace("\\", "/") + text[end:]
    return text


def _authority_host(netloc: str) -> str:
    # `hostname` would lowercase, strip brackets and drop userinfo, but it also hides malformed
    # bracket syntax; parse the authority ourselves from the raw netloc.
    authority = netloc.rpartition("@")[2]
    if authority.startswith("["):
        return authority[: authority.find("]") + 1]
    return authority.rpartition(":")[0] if ":" in authority else authority


# Autofill matches one page against every stored URL, and the same stored URLs on every
# page load; parsing (IDNA, regexes) dominates, so memoize. Results are immutable.
@functools.lru_cache(maxsize=8192)
def _parse(raw: str) -> _Url:
    text = raw.strip()
    if _CONTROL.search(text):
        msg = "invalid URL: control character"
        raise ValueError(msg)
    text = _browser_text(text)
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        msg = "invalid URL: unparsable"
        raise ValueError(msg) from exc
    host = _authority_host(parts.netloc)
    if not host:
        msg = "invalid URL: no host"
        raise ValueError(msg)
    if port == 0:
        msg = "invalid URL: port 0"
        raise ValueError(msg)
    scheme = parts.scheme.lower()
    name, is_ip = _normalize_host(host)
    if port == _DEFAULT_PORTS.get(scheme):
        port = None
    path = "" if parts.path == "/" else parts.path
    return _Url(scheme=scheme, host=name, port=port, path=path, is_ip=is_ip)


def _netloc(u: _Url) -> str:
    host = f"[{u.host}]" if ":" in u.host else u.host
    return host if u.port is None else f"{host}:{u.port}"


def normalize_url(raw: str) -> str:
    """Canonical `scheme://host[:port][/path]`; raises ValueError for anything without a host.

    Defaults to https when no scheme is given; drops userinfo, query, fragment, default ports
    and a lone `/` path so equivalent spellings compare equal.
    """
    u = _parse(raw)
    return f"{u.scheme}://{_netloc(u)}{u.path}"


@functools.lru_cache(maxsize=8192)
def registrable_domain(host: str) -> str:
    """Return the eTLD+1 of `host` (punycode, lowercase).

    IP literals and hosts that are themselves public suffixes (or single labels) are returned
    unchanged in canonical form; callers that compare sites must treat those as unsharable.
    """
    name, is_ip = _normalize_host(host)
    if is_ip:
        return name
    private = _PSL.privatesuffix(name)
    return name if private is None else str(private)


def _strip_www(host: str) -> str:
    # `www.ck` and `ck` are different owners when the remainder is itself a public suffix.
    if host.startswith("www.") and _PSL.privatesuffix(host[4:]) is not None:
        return host[4:]
    return host


def link_host(raw_url: str) -> str:
    """Host key used to pair first-sync items across stores; "" when `raw_url` has no host."""
    try:
        return _strip_www(_parse(raw_url).host)
    except ValueError:
        return ""


def _same_origin_rules_allow(page: _Url, cred: _Url) -> bool:
    if cred.scheme not in _WEB_SCHEMES:
        return False
    if cred.scheme == "https" and page.scheme == "http":
        return False  # never hand an https secret to a page an attacker on the path controls
    if page.port is None and cred.port is None:
        return True  # lets an http credential fill its https page (80 -> 443 upgrade)
    return page.effective_port == cred.effective_port


def _match_one(page: _Url, cred: _Url) -> MatchKind:
    if not _same_origin_rules_allow(page, cred):
        return MatchKind.NONE
    if _strip_www(page.host) == _strip_www(cred.host):
        return MatchKind.EXACT_HOST
    if page.is_ip or cred.is_ip:
        return MatchKind.NONE
    site = registrable_domain(page.host)
    # A site that is itself a public suffix (`github.io`) is shared by unrelated owners.
    if site != registrable_domain(cred.host) or _PSL.privatesuffix(site) is None:
        return MatchKind.NONE
    return MatchKind.SAME_SITE


def match(page_url: str, c: Credential) -> MatchKind:
    """Best match of `page_url` against the credential's url and alt_urls; never raises."""
    try:
        page = _parse(page_url)
    except ValueError:
        return MatchKind.NONE
    if page.scheme not in _WEB_SCHEMES:
        return MatchKind.NONE
    best = MatchKind.NONE
    for raw in (c.url, *c.alt_urls):
        try:
            kind = _match_one(page, _parse(raw))
        except ValueError:
            continue
        if kind is MatchKind.EXACT_HOST:
            return kind
        if kind is MatchKind.SAME_SITE:
            best = kind
    return best
