# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Sidebar sections and which items each one shows."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from passwords_app.app.i18n import _, pgettext

if TYPE_CHECKING:
    from passwords_app.app.records import Item
    from passwords_app.app.security import Issue


class Kind(StrEnum):
    ALL = "all"
    CODES = "codes"
    SECURITY = "security"
    DELETED = "deleted"
    GROUP = "group"


@dataclass(frozen=True, slots=True)
class Section:
    kind: Kind
    group: str = ""

    @property
    def title(self) -> str:
        titles = {
            Kind.ALL: _("All"),
            Kind.CODES: _("Codes"),
            Kind.SECURITY: _("Security"),
            Kind.DELETED: pgettext("sidebar section", "Deleted"),
        }
        return self.group if self.kind is Kind.GROUP else titles[self.kind]

    @property
    def icon(self) -> str:
        icons = {
            Kind.ALL: "dialog-password-symbolic",
            Kind.CODES: "pa-codes-symbolic",
            Kind.SECURITY: "security-high-symbolic",
            Kind.DELETED: "user-trash-symbolic",
            Kind.GROUP: "pa-shared-group-symbolic",
        }
        return icons[self.kind]

    def includes(self, item: Item, issues: frozenset[Issue]) -> bool:
        if self.kind is Kind.CODES:
            return item.has_code
        if self.kind is Kind.SECURITY:
            return bool(issues)
        if self.kind is Kind.GROUP:
            return item.group == self.group
        return self.kind is Kind.ALL


ALL = Section(Kind.ALL)
CODES = Section(Kind.CODES)
SECURITY = Section(Kind.SECURITY)
DELETED = Section(Kind.DELETED)
FIXED = (ALL, CODES, SECURITY, DELETED)
