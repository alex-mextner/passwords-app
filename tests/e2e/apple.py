# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
# Every token and password here is a fictional test value.
"""The Apple side of the end-to-end stack: everything the daemon talks to besides the keyring.

`AppleServices` is one local HTTP server standing in for Apple's sign-in hosts: the
`get_account_settings` and `loginDelegates` setup endpoints (plists, as in
tests/unit/icloud/test_account.py), an anisette server, and the decision GrandSlam would make
on an unattended re-login (read by `daemon_shim`, which replaces only the SRP exchange).
CloudKit itself is `FakeCloudKit` from tests/fakes.

`Phone` is "the iPhone": it creates, edits and deletes logins directly in the fake CloudKit
zone with the real record encoder and zone keys, and reads them back decrypted, exactly as
another Apple device would.
"""

from __future__ import annotations

import dataclasses
import json
import plistlib
import threading
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Self, override

from passwords_app.core.model import Credential
from passwords_app.icloud import passwords
from passwords_app.icloud.keychain import pipeline
from passwords_app.icloud.transport import ckks

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import ec
    from tests.fakes.cloudkit_server import FakeCloudKit

ANISETTE = {"X-Apple-I-MD": "FAKE-MD", "X-Apple-I-MD-M": "FAKE-MD-M"}


class AppleServices:
    """Setup (account settings, login delegates), anisette and the GrandSlam decision."""

    def __init__(self, cloudkit: FakeCloudKit) -> None:
        self.cloudkit = cloudkit
        # Flip to make get_account_settings answer 401, as Apple does once the stored
        # mmeAuthToken has expired.
        self.settings_unauthorized = False
        # What GrandSlam answers to the stored Apple ID password: None = signed in,
        # "trusted" = a second factor is required.
        self.second_factor: str | None = None
        self.calls: list[str] = []
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(self))
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._server.shutdown()
        self._server.server_close()

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host!s}:{port}"

    def expire_token(self) -> None:
        """Apple rotates the CloudKit session token: calls with the old one get 401 until the
        client fetches account settings again (which hand out the new one)."""
        self.cloudkit.token = f"FAKE-ck-{uuid.uuid4().hex}"

    def count(self, path: str) -> int:
        with self._lock:
            return self.calls.count(path)

    def _record(self, path: str) -> None:
        with self._lock:
            self.calls.append(path)

    def answer(self, method: str, path: str) -> tuple[int, bytes]:
        self._record(path)
        if method == "GET" and path == "/anisette":
            return 200, json.dumps(ANISETTE).encode()
        if method == "GET" and path == "/gsa":
            return 200, json.dumps({"second_factor": self.second_factor}).encode()
        if path == "/setup/login":
            delegate = {"status": 0, "service-data": {"tokens": {"mmeAuthToken": "FAKE-MME"}}}
            body = {"dsid": "1234567890", "delegates": {"com.apple.mobileme": delegate}}
            return 200, plistlib.dumps(body)
        if path == "/setup/settings":
            if self.settings_unauthorized:
                return 401, plistlib.dumps({"ErrorID": "UNAUTHORIZED"})
            services = {
                "keychainsync": {"url": self.cloudkit.url},
                "gateway": {"url": self.cloudkit.url},
            }
            tokens = {"cloudKitToken": self.cloudkit.token}
            return 200, plistlib.dumps({"webservices": services, "tokens": tokens})
        return 404, b""


def _handler(services: AppleServices) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "FakeAppleSetup"

        def _reply(self, method: str) -> None:
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            status, body = services.answer(method, self.path)
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            self._reply("GET")

        def do_POST(self) -> None:
            self._reply("POST")

        @override
        def log_message(self, format: str, *args: object) -> None:
            del format, args

    return Handler


def now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def login(  # noqa: PLR0913 - a credential has this many optional fields
    url: str,
    username: str,
    password: str,
    *,
    title: str | None = None,
    notes: str | None = None,
    otpauth: str | None = None,
    alt_urls: tuple[str, ...] = (),
    item_id: str | None = None,
) -> Credential:
    """A fictional login as an Apple device would create it (fresh uppercase UUID)."""
    stamp = now()
    return Credential(
        id=item_id or str(uuid.uuid4()).upper(),
        url=url,
        username=username,
        password=password,
        created=stamp,
        modified=stamp,
        title=title,
        notes=notes,
        otpauth=otpauth,
        alt_urls=alt_urls,
    )


class Phone:
    """Another Apple device on the same account, working on the fake CloudKit zone."""

    def __init__(self, cloudkit: FakeCloudKit) -> None:
        self.cloudkit = cloudkit
        # Keychain peers the account trusts (this computer, once signed in), so a zone
        # created later can share its key with them, as a trusted device does.
        self.peers: dict[str, ec.EllipticCurvePublicKey] = {}
        share_main_zone = cloudkit.add_peer

        def add_peer(peer_id: str, public: ec.EllipticCurvePublicKey) -> None:
            self.peers[peer_id] = public
            share_main_zone(peer_id, public)

        cloudkit.add_peer = add_peer  # type: ignore[method-assign]

    def _logins(self) -> dict[str, passwords.Login]:
        stored = [passwords.StoredItem(n, a) for n, a in self.cloudkit.items().items()]
        return {login.item.record_name: login for login in passwords.pair_logins(stored)}

    def create(self, cred: Credential) -> Credential:
        self.cloudkit.put_login(cred)
        return cred

    def edit(self, item_id: str, **changes: object) -> Credential:
        """Change fields of a login the way the Passwords app does (only changed attributes)."""
        login = self._logins()[item_id]
        current = passwords.to_credential(login)
        assert current is not None
        stamp = now()
        edited = dataclasses.replace(current, **changes, modified=stamp)  # type: ignore[arg-type]
        attrs = passwords.updated_login(login, edited, stamp)
        self.cloudkit.put_item(item_id, attrs.item)
        if attrs.sidecar is not None:
            name = login.sidecar.record_name if login.sidecar else str(uuid.uuid4()).upper()
            self.cloudkit.put_item(name, attrs.sidecar)
        return edited

    def delete(self, item_id: str) -> None:
        login = self._logins()[item_id]
        self.cloudkit.remove(item_id)
        if login.sidecar is not None:
            self.cloudkit.remove(login.sidecar.record_name)

    def logins(self) -> dict[str, Credential]:
        """Every login in the zone, decrypted with the zone keys."""
        return self.cloudkit.logins()

    def get(self, item_id: str) -> Credential | None:
        return self.logins().get(item_id)

    def find(self, url: str, username: str) -> Credential | None:
        matches = [c for c in self.logins().values() if (c.url, c.username) == (url, username)]
        assert len(matches) <= 1, f"duplicate logins for {username} at {url}: {matches}"
        return matches[0] if matches else None

    # --- shared password groups ----------------------------------------------------------------
    # FakeCloudKit models only the account's own "Passwords" zone. A shared group is modelled
    # here as one more CKKS zone named after the group, with its own key hierarchy whose TLK
    # is shared with every trusted peer; its logins use the same record format.

    def create_in_group(self, group: str, cred: Credential) -> Credential:
        fake = self.cloudkit
        zone = ckks.ZoneId(group, fake.user_id)
        keyring = fake.keys.keyring(group)
        attrs = passwords.new_login(cred, cred.modified)
        with fake._lock:
            if zone not in fake._zones:
                for record in fake.keys.records(zone):
                    fake._store(zone, record)
                for peer_id, public in self.peers.items():
                    fake._store(zone, fake.keys.share_for(zone, peer_id, public))
            fake._store(zone, pipeline.encrypt_item(attrs.item, cred.id, zone, keyring))
            if attrs.sidecar is not None:
                name = str(uuid.uuid4()).upper()
                fake._store(zone, pipeline.encrypt_item(attrs.sidecar, name, zone, keyring))
        return dataclasses.replace(cred, group=group)

    def group_logins(self, group: str) -> dict[str, Credential]:
        """Every login in the group's zone, decrypted with that zone's keys."""
        fake = self.cloudkit
        zone = ckks.ZoneId(group, fake.user_id)
        keyring = fake.keys.keyring(group)
        with fake._lock:
            records = [r for r in fake._zones[zone].records.values() if r.type == "item"]
        stored = [
            passwords.StoredItem(r.record_name, pipeline.decrypt_item(r, keyring)) for r in records
        ]
        out: dict[str, Credential] = {}
        for pair in passwords.pair_logins(stored):
            cred = passwords.to_credential(pair, group=group)
            if cred is not None:
                out[cred.id] = cred
        return out
