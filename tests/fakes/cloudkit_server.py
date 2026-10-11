# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""A local CloudKit gateway holding a real, encrypted keychain `Passwords` zone.

`FakeCloudKit` speaks the same protobuf framing as Apple's gateway for the calls the client
makes: ckAppInit, record/sync (incremental, paged, with deletion entries), record/save and
record/delete (zone-atomic, conditional on the change tag the request carries, never the one
inside the record, which Apple ignores), and the Cuttlefish `fetchRecoverableTLKShares`
invoke. Its records are made with the client's own encoder and
test-generated keys: a TLK, classA/classC keys wrapped by it, `currentkey` pointers, and a
TLK share ECIES-encrypted to each peer the test adds. Every saved item is decrypted on
arrival, so a record the client encrypts wrongly is refused like Apple would refuse it.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import gzip
import json
import os
import plistlib
import threading
import uuid
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Self, override

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from passwords_app.icloud import passwords
from passwords_app.icloud.keychain import crypto as kc
from passwords_app.icloud.keychain import pipeline
from passwords_app.icloud.proto.codec import Writer, decode_fields, first_bytes, first_int
from passwords_app.icloud.transport import ckks, cloudkit

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from passwords_app.core.model import Credential

USER_ID = "_fake-cloudkit-user"
CK_TOKEN = "fake-cloudkit-token"
ZONE = "Passwords"
_SF_TRAILER = b"\x00" * (97 + 16)  # SecurityFoundation's junk after the real ciphertext
_SERVER_NOT_FOUND = 3
_INVALID_FIELD_VALUE = 24


def ecies_encrypt_sf(public: ec.EllipticCurvePublicKey, plaintext: bytes) -> dict[str, bytes]:
    """SF-ECIES as Apple writes it (the inverse of `crypto.ecies_decrypt_sf`)."""
    eph = ec.generate_private_key(ec.SECP384R1())
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    derived = kc.x963_kdf(eph.exchange(ec.ECDH(), public), eph_pub, 48)
    sealed = AESGCM(derived[:32]).encrypt(derived[32:48], plaintext, None)
    return {
        "SFEphemeralSenderPublicKeyExternaRepresentation": eph_pub,
        "SFCiphertext": sealed[:-16] + _SF_TRAILER,
        "SFIESAuthenticationCode": sealed[-16:],
    }


def keyed_archive(fields: dict[str, bytes]) -> bytes:
    """An NSKeyedArchiver plist of one object whose values are NSData."""
    root: dict[str, object] = {"$class": plistlib.UID(2)}
    objects: list[object] = [
        "$null",
        root,
        {"$classname": "SFIESCiphertext", "$classes": ["SFIESCiphertext", "NSObject"]},
    ]
    for key, value in fields.items():
        objects.append(value)
        root[key] = plistlib.UID(len(objects) - 1)
    archive = {
        "$archiver": "NSKeyedArchiver",
        "$version": 100000,
        "$top": {"root": plistlib.UID(1)},
        "$objects": objects,
    }
    return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)


@dataclasses.dataclass
class ZoneKeys:
    """A zone's key hierarchy: the TLK and one current key per class, wrapped by it."""

    tlk_id: str
    tlk: bytes
    class_keys: dict[str, tuple[str, bytes]]

    @classmethod
    def generate(cls) -> ZoneKeys:
        return cls(
            str(uuid.uuid4()).upper(),
            os.urandom(64),
            {c: (str(uuid.uuid4()).upper(), os.urandom(64)) for c in ("classA", "classC")},
        )

    def keyring(self, zone: str) -> pipeline.KeyRing:
        return pipeline.KeyRing(
            dict(self.class_keys.values()),
            {(zone, cls_): key_id for cls_, (key_id, _) in self.class_keys.items()},
        )

    def records(self, zone: ckks.ZoneId) -> list[ckks.CloudKitRecord]:
        out: list[ckks.CloudKitRecord] = []
        for key_class, (key_id, key) in self.class_keys.items():
            wrapped = base64.b64encode(kc.siv_wrap(self.tlk, key)).decode()
            out.append(
                ckks.CloudKitRecord(
                    key_id,
                    "synckey",
                    {
                        "class": key_class,
                        "wrappedkey": wrapped,
                        "parentkeyref": ckks.CKReference(self.tlk_id),
                    },
                    zone=zone,
                )
            )
            out.append(
                ckks.CloudKitRecord(
                    key_class,
                    "currentkey",
                    {"parentkeyref": ckks.CKReference(key_id, ckks.REF_WEAK)},
                    zone=zone,
                )
            )
        return out

    def share_for(
        self, zone: ckks.ZoneId, peer_id: str, public: ec.EllipticCurvePublicKey
    ) -> ckks.CloudKitRecord:
        serialized = (
            Writer().string(1, self.tlk_id).string(2, zone.name).string(3, "tlk").bytes(4, self.tlk)
        ).finish()
        archive = keyed_archive(ecies_encrypt_sf(public, serialized))
        return ckks.CloudKitRecord(
            f"tlkshare-{self.tlk_id}::{peer_id}",
            "tlkshare",
            {"receiver": peer_id, "wrappedkey": base64.b64encode(archive).decode()},
            zone=zone,
        )


@dataclasses.dataclass
class _Zone:
    records: dict[str, ckks.CloudKitRecord] = dataclasses.field(
        default_factory=dict[str, ckks.CloudKitRecord]
    )
    log: list[tuple[int, str]] = dataclasses.field(default_factory=list[tuple[int, str]])


@dataclasses.dataclass
class Fault:
    """An injected failure: matching requests answer `status` (HTTP) or a per-op error."""

    path: str
    http_status: int | None = None
    client_error: int | None = None
    times: int = 1


class FakeCloudKit:
    """The local gateway. Use as a context manager; `url` is its base address."""

    def __init__(self, *, user_id: str = USER_ID, token: str = CK_TOKEN) -> None:
        self.user_id = user_id
        self.token = token
        self.zone = ckks.ZoneId(ZONE, user_id)
        self.keys = ZoneKeys.generate()
        self._zones: dict[ckks.ZoneId, _Zone] = {self.zone: _Zone()}
        self._seq = 0
        self._lock = threading.RLock()
        self.faults: list[Fault] = []
        self.requests: list[tuple[str, list[int]]] = []
        self.page_size = 500
        self.reverse_responses = False
        self.omit_save_etag = False
        self.on_request: Callable[[str], None] | None = None
        for rec in self.keys.records(self.zone):
            self._store(self.zone, rec)
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(self))
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    # --- lifecycle -----------------------------------------------------------------------------

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

    # --- server-side state (what other devices do) ---------------------------------------------

    def keyring(self) -> pipeline.KeyRing:
        return self.keys.keyring(ZONE)

    def add_peer(self, peer_id: str, public: ec.EllipticCurvePublicKey) -> None:
        """Share the zone's TLK with a keychain peer (as a trusted device would)."""
        with self._lock:
            self._store(self.zone, self.keys.share_for(self.zone, peer_id, public))

    def _store(self, zone: ckks.ZoneId, record: ckks.CloudKitRecord) -> str:
        self._seq += 1
        etag = f"etag-{self._seq}"
        z = self._zones.setdefault(zone, _Zone())
        z.records[record.record_name] = dataclasses.replace(record, etag=etag, zone=zone)
        z.log.append((self._seq, record.record_name))
        return etag

    def put_item(
        self,
        record_name: str,
        attrs: dict[str, object],
        *,
        extra: dict[str, ckks.FieldValue] | None = None,
    ) -> str:
        """Store an item encrypted like an Apple device would; return its change tag."""
        with self._lock:
            previous = self._zones[self.zone].records.get(record_name)
            if extra:
                base = previous or ckks.CloudKitRecord(record_name, "item", {}, zone=self.zone)
                previous = dataclasses.replace(base, fields={**base.fields, **extra})
            rec = pipeline.encrypt_item(
                attrs, record_name, self.zone, self.keyring(), previous=previous
            )
            return self._store(self.zone, rec)

    def put_login(
        self, cred: Credential, *, sidecar_name: str | None = None
    ) -> tuple[str, str | None]:
        """Store a login (and its sidecar when it has metadata); return their change tags."""
        attrs = passwords.new_login(cred, cred.modified)
        tag = self.put_item(cred.id, attrs.item)
        side_tag = None
        if attrs.sidecar is not None:
            side_tag = self.put_item(sidecar_name or str(uuid.uuid4()).upper(), attrs.sidecar)
        return tag, side_tag

    def remove(self, record_name: str) -> None:
        """Delete a record server-side (as another device would)."""
        with self._lock:
            z = self._zones[self.zone]
            if z.records.pop(record_name, None) is not None:
                self._seq += 1
                z.log.append((self._seq, record_name))

    def record(self, record_name: str) -> ckks.CloudKitRecord | None:
        with self._lock:
            return self._zones[self.zone].records.get(record_name)

    def item(self, record_name: str) -> dict[str, object]:
        """The decrypted attributes of an item, as an Apple device would read them."""
        rec = self.record(record_name)
        assert rec is not None, f"no record {record_name}"
        return pipeline.decrypt_item(rec, self.keyring())

    def items(self) -> dict[str, dict[str, object]]:
        with self._lock:
            names = [
                r.record_name for r in self._zones[self.zone].records.values() if r.type == "item"
            ]
        return {name: self.item(name) for name in names}

    def logins(self) -> dict[str, Credential]:
        stored = [passwords.StoredItem(n, a) for n, a in self.items().items()]
        out: dict[str, Credential] = {}
        for login in passwords.pair_logins(stored):
            cred = passwords.to_credential(login)
            if cred is not None:
                out[cred.id] = cred
        return out

    def fail(
        self,
        path: str,
        *,
        http_status: int | None = None,
        client_error: int | None = None,
        times: int = 1,
    ) -> None:
        with self._lock:
            self.faults.append(Fault(path, http_status, client_error, times))

    def _fault(self, path: str) -> Fault | None:
        with self._lock:
            for f in self.faults:
                if path.endswith(f.path) and f.times > 0:
                    f.times -= 1
                    return f
        return None

    # --- request handling ------------------------------------------------------------------------

    def handle(self, path: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes, str]:
        if self.on_request is not None:
            self.on_request(path)
        if path.startswith("/setup/setup/ck/v1/ckAppInit"):
            return (
                HTTPStatus.OK,
                json.dumps({"cloudKitUserId": self.user_id}).encode(),
                "application/json",
            )
        if headers.get("x-cloudkit-authtoken") != self.token:
            return HTTPStatus.UNAUTHORIZED, b"", "text/plain"
        fault = self._fault(path)
        if fault is not None and fault.http_status is not None:
            return fault.http_status, b"", "text/plain"
        ops = [cloudkit.parse_request(m) for m in cloudkit.undelimit(gzip.decompress(body))]
        self.requests.append((path, [op.op_type for op in ops]))
        with self._lock:
            if path.endswith("/record/sync"):
                answers = [self._sync(op, fault) for op in ops]
            elif path.endswith("/record/save"):
                answers = self._save(ops, fault)
            elif path.endswith("/record/delete"):
                answers = self._delete(ops, fault)
            elif path.endswith("/code/invoke"):
                answers = [self._invoke(op) for op in ops]
            else:
                return HTTPStatus.NOT_FOUND, b"", "text/plain"
        if self.reverse_responses:
            answers.reverse()
        payload = b"".join(cloudkit.delimit(a) for a in answers)
        return HTTPStatus.OK, gzip.compress(payload), "application/x-protobuf"

    def _sync(self, op: cloudkit.ParsedRequest, fault: Fault | None) -> bytes:
        if fault is not None and fault.client_error is not None:
            return cloudkit.build_response_operation(
                op.uuid, op.op_type, code=3, client_error=fault.client_error, description="injected"
            )
        req = decode_fields(op.payload(ckks.FIELD_RETRIEVE_CHANGES) or b"")
        token = first_bytes(req, 1)
        zone_id = ckks.parse_zone_identifier(first_bytes(req, 2) or b"")
        zone = self._zones.get(zone_id)
        if zone is None:
            return cloudkit.build_response_operation(
                op.uuid,
                op.op_type,
                code=3,
                client_error=cloudkit.CLIENT_ZONE_NOT_FOUND,
                description="no zone",
            )
        try:
            since = int(token.decode()) if token else 0
        except ValueError:
            return cloudkit.build_response_operation(
                op.uuid,
                op.op_type,
                code=3,
                client_error=cloudkit.CLIENT_FULL_RESET_NEEDED,
                description="token expired",
            )
        latest = {name: seq for seq, name in zone.log if seq > since}
        ordered = sorted(latest.items(), key=lambda kv: kv[1])
        limit = first_int(req, 4) or self.page_size
        page, more = (
            ordered[: min(limit, self.page_size)],
            len(ordered) > min(limit, self.page_size),
        )
        changes: list[bytes] = []
        for name, _ in page:
            rec = zone.records.get(name)
            raw = ckks.encode_record(rec) if rec is not None else None
            changes.append(ckks.build_change(name, zone_id, rec.etag if rec else None, raw))
        last = page[-1][1] if page else since
        body = ckks.build_changes_page(changes, str(last).encode(), ckks.STATUS_MORE if more else 3)
        return cloudkit.build_response_operation(
            op.uuid, op.op_type, field=ckks.FIELD_RETRIEVE_CHANGES, payload=body
        )

    def _save(self, ops: list[cloudkit.ParsedRequest], fault: Fault | None) -> list[bytes]:
        errors: list[tuple[int, str] | None] = []
        records: list[ckks.CloudKitRecord] = []
        for i, op in enumerate(ops):
            rec, create, if_match = ckks.parse_save_request(
                op.payload(ckks.FIELD_RECORD_SAVE) or b""
            )
            records.append(rec)
            errors.append(self._check_save(rec, create=create, if_match=if_match))
            if fault is not None and fault.client_error is not None and i == len(ops) - 1:
                errors[-1] = (fault.client_error, "injected")
        if any(errors):
            return _failed_batch(ops, errors)
        out: list[bytes] = []
        for op, rec in zip(ops, records, strict=True):
            assert rec.zone is not None
            tag = self._store(rec.zone, rec)
            out.append(
                cloudkit.build_response_operation(
                    op.uuid,
                    op.op_type,
                    field=ckks.FIELD_RECORD_SAVE,
                    payload=b"" if self.omit_save_etag else ckks.build_save_response(tag),
                )
            )
        return out

    def _check_save(
        self, rec: ckks.CloudKitRecord, *, create: bool, if_match: str | None
    ) -> tuple[int, str] | None:
        """Apple's checks: the tag in the request (never the record's own) guards an update."""
        zone = self._zones.get(rec.zone) if rec.zone is not None else None
        if zone is None:
            return cloudkit.CLIENT_ZONE_NOT_FOUND, "no such zone"
        current = zone.records.get(rec.record_name)
        if create and current is not None:
            return cloudkit.CLIENT_OP_LOCK_FAILURE, "record to insert already exists"
        stale = current is None or (if_match is not None and current.etag != if_match)
        if not create and stale:
            return cloudkit.CLIENT_OP_LOCK_FAILURE, "client oplock error updating record"
        try:
            pipeline.decrypt_item(rec, self.keyring())
        except kc.KeychainCryptoError as e:
            return _INVALID_FIELD_VALUE, f"undecryptable item: {e}"
        return None

    def _delete(self, ops: list[cloudkit.ParsedRequest], fault: Fault | None) -> list[bytes]:
        if fault is not None and fault.client_error is not None:
            return [
                cloudkit.build_response_operation(
                    op.uuid,
                    op.op_type,
                    code=3,
                    client_error=fault.client_error,
                    description="injected",
                )
                for op in ops
            ]
        targets: list[tuple[str, _Zone | None]] = []
        errors: list[tuple[int, str] | None] = []
        for op in ops:
            name, zone_id, if_match = ckks.parse_delete_request(
                op.payload(ckks.FIELD_RECORD_DELETE) or b""
            )
            zone = self._zones.get(zone_id) if zone_id is not None else None
            current = zone.records.get(name) if zone is not None else None
            stale = current is not None and if_match is not None and current.etag != if_match
            errors.append(
                (cloudkit.CLIENT_OP_LOCK_FAILURE, "client oplock error deleting record")
                if stale
                else None
            )
            targets.append((name, zone))
        if any(errors):
            return _failed_batch(ops, errors)
        for name, zone in targets:
            if zone is not None and zone.records.pop(name, None) is not None:
                self._seq += 1
                zone.log.append((self._seq, name))
        return [cloudkit.build_response_operation(op.uuid, op.op_type) for op in ops]

    def _invoke(self, op: cloudkit.ParsedRequest) -> bytes:
        # fetchRecoverableTLKShares: this zone's TLK travels as a plain tlkshare record instead.
        payload = Writer().bytes(1, b"").finish()
        return cloudkit.build_response_operation(
            op.uuid, op.op_type, field=cloudkit.OP_TYPE_FUNCTION_INVOKE, payload=payload
        )


def _failed_batch(
    ops: list[cloudkit.ParsedRequest], errors: list[tuple[int, str] | None]
) -> list[bytes]:
    """A zone-atomic batch that failed: each culprit gets its error, the rest ATOMIC_FAILURE."""
    return [
        cloudkit.build_response_operation(
            op.uuid,
            op.op_type,
            code=3,
            client_error=err[0] if err else cloudkit.CLIENT_ATOMIC_FAILURE,
            description=err[1] if err else "Atomic failure",
        )
        for op, err in zip(ops, errors, strict=True)
    ]


def _handler(fake: FakeCloudKit) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        disable_nagle_algorithm = True  # keep-alive + delayed ACK would add 40 ms per call
        server_version = "FakeCloudKit"

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            headers = {k.lower(): v for k, v in self.headers.items()}
            status, data, ctype = fake.handle(self.path, headers, body)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        @override
        def log_message(self, format: str, *args: object) -> None:
            del format, args

    return Handler


@contextlib.contextmanager
def running() -> Generator[FakeCloudKit]:
    with FakeCloudKit() as fake:
        yield fake


def now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)
