# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Security recommendations: weak, reused and (opt-in) compromised passwords.

Compromised checks use the Have I Been Pwned range API with k-anonymity: only the first five
hex characters of the password's SHA-1 leave the machine, the comparison of the rest happens
here, and the request asks for padding so the response size does not leak the prefix's count.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Final

import requests

from passwords_app.app.i18n import _, ngettext
from passwords_app.core.model import Credential
from passwords_app.core.strength import assess, reused

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from passwords_app.app.records import Item

HIBP_RANGE_URL: Final = "https://api.pwnedpasswords.com/range/"
_HIBP_TIMEOUT = 10.0
_PREFIX_LEN = 5
_STAMP = datetime(2000, 1, 1, tzinfo=UTC)


class Issue(StrEnum):
    COMPROMISED = "compromised"
    REUSED = "reused"
    WEAK = "weak"


class Level(StrEnum):
    VERY_WEAK = "very-weak"
    WEAK = "weak"
    GOOD = "good"
    STRONG = "strong"


def level(password: str, *, user_inputs: Iterable[str] = ()) -> Level:
    """Meter level for a password; anything the core calls weak is at most WEAK."""
    strength = assess(password, user_inputs=[u for u in user_inputs if u])
    if strength.score <= 1:
        return Level.VERY_WEAK
    if strength.weak:
        return Level.WEAK
    return Level.STRONG if strength.score >= 4 else Level.GOOD  # noqa: PLR2004 - zxcvbn max


def level_text(value: Level) -> str:
    texts = {
        Level.VERY_WEAK: _("Very Weak"),
        Level.WEAK: _("Weak"),
        Level.GOOD: _("Good"),
        Level.STRONG: _("Strong"),
    }
    return texts[value]


def level_fraction(value: Level) -> float:
    return {Level.VERY_WEAK: 0.15, Level.WEAK: 0.4, Level.GOOD: 0.7, Level.STRONG: 1.0}[value]


@dataclass(frozen=True, slots=True)
class Report:
    """Issues per item id; `reused_with` lists the other ids sharing that item's password."""

    issues: Mapping[str, frozenset[Issue]] = field(default_factory=dict[str, frozenset[Issue]])
    reused_with: Mapping[str, tuple[str, ...]] = field(default_factory=dict[str, tuple[str, ...]])

    def of(self, item_id: str) -> frozenset[Issue]:
        return self.issues.get(item_id, frozenset())

    @property
    def flagged(self) -> list[str]:
        return [i for i, found in self.issues.items() if found]

    def count(self, issue: Issue) -> int:
        return sum(1 for found in self.issues.values() if issue in found)


def _as_credential(item: Item) -> Credential:
    return Credential(
        id=item.id,
        url=item.url or "-",
        username=item.username,
        password=item.password or "",
        created=_STAMP,
        modified=_STAMP,
    )


def analyze(items: Iterable[Item], compromised: Iterable[str] = ()) -> Report:
    """Classify items that carry a password (fetched with Get); others are skipped."""
    with_password = [i for i in items if i.password]
    pwned = set(compromised)
    issues: dict[str, set[Issue]] = {i.id: set() for i in with_password}
    reused_with: dict[str, tuple[str, ...]] = {}
    for ids in reused(_as_credential(i) for i in with_password).values():
        for item_id in ids:
            issues[item_id].add(Issue.REUSED)
            reused_with[item_id] = tuple(other for other in ids if other != item_id)
    for item in with_password:
        password = item.password or ""
        if assess(password, user_inputs=[u for u in (item.username, item.host) if u]).weak:
            issues[item.id].add(Issue.WEAK)
        if item.id in pwned:
            issues[item.id].add(Issue.COMPROMISED)
    return Report(
        issues={k: frozenset(v) for k, v in issues.items()},
        reused_with=reused_with,
    )


def issue_text(issue: Issue, reused_count: int = 0) -> str:
    if issue is Issue.COMPROMISED:
        return _("This password appeared in a data leak")
    if issue is Issue.REUSED:
        n = max(1, reused_count)
        return ngettext(
            "Also used on {n} other website", "Also used on {n} other websites", n
        ).format(n=n)
    return _("This password is easy to guess")


def hibp_split(password: str) -> tuple[str, str]:
    """(prefix sent to the API, suffix kept local) of the uppercase SHA-1 hex digest."""
    # SHA-1 is what the HIBP range API is keyed by; it is not used for security here.
    digest = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    return digest[:_PREFIX_LEN], digest[_PREFIX_LEN:]


def breach_count(range_body: str, suffix: str) -> int:
    """Occurrences of `suffix` in a range response; padding rows (count 0) never match."""
    wanted = suffix.upper()
    for line in range_body.splitlines():
        found, _sep, count = line.strip().partition(":")
        if found.upper() == wanted:
            try:
                return int(count)
            except ValueError:
                return 0
    return 0


@dataclass(slots=True)
class HibpClient:
    """Blocking range client; call from a worker thread. One request per distinct prefix."""

    base_url: str = HIBP_RANGE_URL
    session: requests.Session = field(default_factory=requests.Session)

    def compromised(self, passwords: Mapping[str, str]) -> set[str]:
        """Ids (keys of `passwords`) whose password is in the breach corpus."""
        by_prefix: dict[str, list[tuple[str, str]]] = {}
        for item_id, password in passwords.items():
            if password:
                prefix, suffix = hibp_split(password)
                by_prefix.setdefault(prefix, []).append((item_id, suffix))
        found: set[str] = set()
        for prefix, entries in by_prefix.items():
            response = self.session.get(
                self.base_url + prefix,
                headers={"Add-Padding": "true", "User-Agent": "passwords-app"},
                timeout=_HIBP_TIMEOUT,
            )
            response.raise_for_status()
            found.update(i for i, suffix in entries if breach_count(response.text, suffix) > 0)
        return found
