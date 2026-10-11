# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""A joined session record whose services point at a `FakeCloudKit`.

`make_session(fake)` returns the dict `SessionStore.save` would persist after a real sign-in
and join: account ids, tokens, a freshly generated keychain peer identity (whose TLK share
the fake now holds), and `webservices.gateway` aimed at the fake.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from passwords_app.icloud.auth.device import Device
from passwords_app.icloud.octagon import client as octagon

if TYPE_CHECKING:
    from tests.fakes.cloudkit_server import FakeCloudKit

APPLE_ID = "owner@example.com"
DEVICE = Device("6F1E2D3C-0000-4000-8000-00000000AB12", "C02TESTSERIAL", "LOCAL-USER-UUID")


def make_session(fake: FakeCloudKit, *, resolve_user_id: bool = True) -> dict[str, object]:
    record: dict[str, object] = {
        "username": APPLE_ID,
        "dsid": "000000-00-fake-adsid",
        "dsid_numeric": "1234567890",
        "password": "correct horse battery staple",
        "mme": {
            "dsid": "1234567890",
            "mmeAuthToken": "fake-mme-token",
            "tokens": {"cloudKitToken": fake.token},
        },
        "webservices": {"gateway": fake.url, "keychainsync": fake.url},
    }
    if resolve_user_id:
        mme = record["mme"]
        assert isinstance(mme, dict)
        mme["cloudKitUserId"] = fake.user_id
    oct_state = octagon.ensure_peer_identity(record, DEVICE)
    oct_state["joined"] = True
    keys = octagon.load_peer_keys(oct_state)
    peer_id = oct_state["peer_id"]
    assert isinstance(peer_id, str)
    fake.add_peer(peer_id, keys.encryption.private_key.public_key())
    return record
