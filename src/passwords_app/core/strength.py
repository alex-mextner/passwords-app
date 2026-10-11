# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Password strength (zxcvbn) and reuse detection for the security overview."""

from __future__ import annotations

import hashlib
import threading
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from zxcvbn import zxcvbn

from passwords_app.core.urls import url_domain

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from passwords_app.core.model import Credential

# zxcvbn's matching cost grows super-linearly with length; the first 256 characters already
# decide the score of any realistic password.
_MAX_ASSESSED = 256
_WEAK_BELOW = 3
# zxcvbn stores user_inputs in a module-global dictionary between building it and matching.
_ZXCVBN_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class Strength:
    score: int  # zxcvbn score 0..4
    weak: bool


def _zxcvbn_score(password: str, user_inputs: list[str]) -> int:
    with _ZXCVBN_LOCK:
        result = zxcvbn(password, user_inputs=user_inputs, max_length=_MAX_ASSESSED)
    score: int = result["score"]
    return score


def assess(password: str, *, user_inputs: Sequence[str] = ()) -> Strength:
    """Score `password`; `user_inputs` (username, site name, ...) count as guessable words."""
    if not password:
        return Strength(score=0, weak=True)
    score = _zxcvbn_score(password[:_MAX_ASSESSED], list(user_inputs))
    return Strength(score=score, weak=score < _WEAK_BELOW)


def reused(creds: Iterable[Credential]) -> dict[str, list[str]]:
    """Group credentials whose non-empty password serves more than one domain.

    As Apple marks it: the same password for several logins of one domain (an account on
    `example.com` and `login.example.com`, or two accounts on one site) is not reuse.
    Keys are SHA-256 hex digests of the password, never the password, because the result is
    shown in the UI and may be logged. Values are the sorted distinct credential ids.
    """
    groups: defaultdict[str, set[str]] = defaultdict(set)
    domains: defaultdict[str, set[str]] = defaultdict(set)
    for c in creds:
        if c.password:
            key = hashlib.sha256(c.password.encode()).hexdigest()
            groups[key].add(c.id)
            domains[key].add(url_domain(c.url))
    return {key: sorted(ids) for key, ids in groups.items() if len(domains[key]) > 1}
