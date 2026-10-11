# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S25: a login in a shared password group is read on Linux (keyring, app's Shared Groups) and
an edit made on Linux goes back to the group.

The group is modelled as its own CKKS zone whose key is shared with this computer's keychain
peer (see `Phone.create_in_group`); the product reads only the "Passwords" zone today (#65).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from tests.e2e.apple import login
from tests.e2e.stack import SurfaceTimeoutError, wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack

EDITED = "FAKE-group-edited-on-linux"


@pytest.mark.xfail(
    strict=True,
    raises=SurfaceTimeoutError,
    reason="#65: shared password groups are never synced (only the Passwords zone is read)",
)
def test_s25_shared_group_login_is_read_and_edited_on_linux(stack: Stack) -> None:
    from passwords_app.app.sections import Kind, Section  # noqa: PLC0415

    shared = stack.apple.create_in_group(
        "Family",
        login("https://streaming.example", "family", "FAKE-shared-group"),
    )
    # The group really holds it, readable with the group's keys (the seeding works).
    assert stack.apple.group_logins("Family")[shared.id].password == shared.password
    app = stack.app

    item = wait_until(lambda: stack.keyring.by_id(shared.id), what="the group's login on Linux")
    assert item.attributes.get("group") == "Family"
    wait_until(
        lambda: Section(Kind.GROUP, "Family") in app.window.sidebar.rows, what="Shared Groups row"
    )
    app.edit(shared.id, password=EDITED)
    wait_until(
        lambda: stack.apple.group_logins("Family")[shared.id].password == EDITED,
        what="the Linux edit in the group's zone",
    )
