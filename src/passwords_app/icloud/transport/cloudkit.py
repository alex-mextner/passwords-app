# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""CloudKit protobuf transport for the keychain containers.

A request body is gzip(concatenated length-delimited RequestOperations): only the first carries
the header, each has its own operation UUID, and only the last sets `last`. Responses come back
as a stream of ResponseOperations matched to requests by that UUID, not by position. The
cloudKitToken rides in the `x-cloudkit-authtoken` HTTP header, never in the body.
"""

from __future__ import annotations

import base64
import dataclasses
import gzip
import hashlib
import os
import uuid as _uuid
import zlib
from http import HTTPStatus
from typing import TYPE_CHECKING

import requests

from passwords_app.icloud import const, tls
from passwords_app.icloud.errors import AppleError
from passwords_app.icloud.proto import codec as _proto
from passwords_app.icloud.proto.codec import (
    Fields,
    Writer,
    decode_fields,
    first_bytes,
    first_int,
    first_message,
    first_str,
)
from passwords_app.icloud.proto.cuttlefish import encode_function_invoke_request
from passwords_app.icloud.transport import ckks

if TYPE_CHECKING:
    from collections.abc import Sequence

    from passwords_app.icloud.auth.anisette import AnisetteSource

GATEWAY_URL = "https://gateway.icloud.com"
CKCODE_INVOKE_PATH = "/ckcoderouter/api/client/code/invoke"
CKDATABASE_SYNC_PATH = "/ckdatabase/api/client/record/sync"
CKDATABASE_SAVE_PATH = "/ckdatabase/api/client/record/save"
CKDATABASE_DELETE_PATH = "/ckdatabase/api/client/record/delete"
CK_APP_INIT_URL = "https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit"
# CloudKit is told the same platform as every other sign-in endpoint (`const.WINDOWS_PLATFORM`).
# Apple answers ckAppInit with HTTP 401 to a valid token minted as a Windows client when the
# request claims a Mac (checked against Apple on 2026-10-26; the same token was accepted with
# this claim), so a session that passed the code could never reach the device-passcode step.
CK_MME_CLIENT_INFO = (
    f"{const.WINDOWS_PLATFORM} <com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)>"
)
CUTTLEFISH_CONTAINER = "com.apple.security.keychain"
CUTTLEFISH_BUNDLE = "com.apple.security.cuttlefish"  # CKCode (Cuttlefish) requests
SECURITYD_BUNDLE = "com.apple.securityd"  # CKKS record operations
CUTTLEFISH_SERVICE = "Cuttlefish"

ENV_PRODUCTION = 1
DB_PRIVATE = 1
DB_SHARED = 3
ISOLATION_ZONE = 1
IDENTIFIER_TYPE_DEVICE = 2
OP_TYPE_FUNCTION_INVOKE = 1101
RESULT_SUCCESS = 1

# Result.error.clientError.type values a writer reacts to.
CLIENT_EXISTS = 9
CLIENT_OP_LOCK_FAILURE = 15
CLIENT_ATOMIC_FAILURE = 16
CLIENT_FULL_RESET_NEEDED = 40
CLIENT_ZONE_NOT_FOUND = 48
CLIENT_USER_DELETED_ZONE = 59
CLIENT_STALE_RECORD_UPDATE = 60
CONFLICT_CODES = frozenset({CLIENT_EXISTS, CLIENT_OP_LOCK_FAILURE, CLIENT_STALE_RECORD_UPDATE})
ZONE_MISSING_CODES = frozenset({CLIENT_ZONE_NOT_FOUND, CLIENT_USER_DELETED_ZONE})


def maybe_gunzip(payload: bytes) -> bytes:
    """Decompress if the body is gzip."""
    if payload[:2] == b"\x1f\x8b":
        return gzip.decompress(payload)
    return payload


def delimit(message: bytes) -> bytes:
    """CloudKit `delimited=true` framing: a uleb128 length prefix + the message."""
    return _proto.encode_varint(len(message)) + message


def undelimit(buf: bytes) -> list[bytes]:
    """Split a stream of length-delimited messages (the response body)."""
    out: list[bytes] = []
    pos, n = 0, len(buf)
    while pos < n:
        size, pos = _proto.read_varint(buf, pos)
        if pos + size > n:
            msg = "truncated length-delimited message"
            raise _proto.ProtoError(msg)
        out.append(buf[pos : pos + size])
        pos += size
    return out


def _identifier(name: str, type_: int) -> bytes:
    return Writer().string(1, name).uint64(2, type_).finish()


@dataclasses.dataclass(frozen=True, slots=True)
class DeviceConfig:
    """The device fields CloudKit's RequestOperation.Header wants."""

    device_uuid: str  # deviceIdentifier.name + deviceHardwareID (udid)
    serial: str  # deviceSerial
    name: str = "Mac"  # deviceAssignedName
    software_version: str = "Mac OS X;13.4.1;22F8"
    hardware_version: str = "MacBookPro18,3"


def build_header(  # noqa: PLR0913 - one knob per Header field a caller may vary
    config: DeviceConfig,
    *,
    container: str = CUTTLEFISH_CONTAINER,
    bundle: str = CUTTLEFISH_BUNDLE,
    env: int = ENV_PRODUCTION,
    database: int = DB_PRIVATE,
    isolation: int = ISOLATION_ZONE,
) -> bytes:
    """RequestOperation.Header (userToken stays empty: the token travels as an HTTP header)."""
    # nosemgrep: insecure-hash-algorithm-sha1 - CloudKit's Header.deviceHash is SHA-1 by protocol
    device_hash = hashlib.sha1(config.device_uuid.encode(), usedforsecurity=False).hexdigest()
    return (
        Writer()
        .string(2, container)
        .string(3, bundle)
        .message(7, _identifier(config.device_uuid, IDENTIFIER_TYPE_DEVICE))
        .string(8, config.software_version)
        .string(9, config.hardware_version)
        .string(10, "com.apple.cloudkit.CloudKitDaemon")
        .string(11, "1970")
        .string(18, "5.0")  # mmcsProtocolVersion
        .uint64(19, env)  # applicationContainerEnvironment
        .string(21, config.name)  # deviceAssignedName
        .string(22, config.device_uuid)  # deviceHardwareID
        .uint64(23, database)  # targetDatabase
        .uint64(25, isolation)  # isolationLevel: ZONE makes a batch all-or-nothing per zone
        .uint64(29, 0)
        .string(32, device_hash)
        .string(33, config.serial)  # deviceSerial
        .uint64(34, 0)
        .uint64(35, 1)
        .finish()
    )


@dataclasses.dataclass(frozen=True, slots=True)
class Operation:
    """One RequestOperation: its type and the op-specific request in its own field number."""

    op_type: int
    field: int
    payload: bytes
    uuid: str = dataclasses.field(default_factory=lambda: str(_uuid.uuid4()).upper())


def build_batch(header: bytes, ops: Sequence[Operation]) -> bytes:
    """Delimited RequestOperations; the header rides on the first, `last` on the final one."""
    out = bytearray()
    for i, op in enumerate(ops):
        last = i == len(ops) - 1
        operation = Writer().string(1, op.uuid).uint64(2, op.op_type).bool(4, last or None)
        w = Writer()
        if i == 0:
            w.message(1, header)
        out += delimit(w.message(2, operation).message(op.field, op.payload).finish())
    return bytes(out)


@dataclasses.dataclass(frozen=True, slots=True)
class ParsedRequest:
    """A RequestOperation as a server sees it (used by the local fake server)."""

    uuid: str
    op_type: int
    fields: Fields

    def payload(self, field: int) -> bytes | None:
        return first_bytes(self.fields, field)


def parse_request(raw: bytes) -> ParsedRequest:
    f = decode_fields(raw)
    op = first_message(f, 2) or {}
    return ParsedRequest(first_str(op, 1, ""), first_int(op, 2) or 0, f)


def _operation_id() -> str:
    return os.urandom(8).hex().upper()


def _container_headers(
    *,
    bundle: str,
    container: str,
    database_scope: str = "Private",
    mme_client_info: str = CK_MME_CLIENT_INFO,
) -> dict[str, str]:
    """Shared header block for ckAppInit and every CKCode/record op.

    The caller adds auth / userid / authtoken / routing-hint / anisette on top.
    """
    return {
        "accept": "application/x-protobuf",
        "accept-encoding": "gzip",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "no-transform",
        "content-encoding": "gzip",
        "content-type": (
            'application/x-protobuf; desc="https://gateway.icloud.com:443'
            '/static/protobuf/CloudDB/CloudDBClient.desc"; '
            "messageType=RequestOperation; delimited=true"
        ),
        "user-agent": "CloudKit/1970 (19H384)",
        "x-apple-c2-metric-triggers": "0",
        "x-apple-operation-group-id": _operation_id(),
        "x-apple-operation-id": _operation_id(),
        "x-apple-request-uuid": str(_uuid.uuid4()).upper(),
        "x-cloudkit-bundleid": bundle,
        "x-cloudkit-containerid": container,
        "x-cloudkit-databasescope": database_scope,
        "x-cloudkit-duetpreclearedmode": "None",
        "x-cloudkit-environment": "Production",
        "x-mme-client-info": mme_client_info,
    }


def ck_app_init(  # noqa: PLR0913 - the handshake's inputs, plus test seams
    container: str,
    bundle: str,
    dsid: str,
    mme_token: str,
    anisette: AnisetteSource,
    *,
    url: str = CK_APP_INIT_URL,
    http: requests.Session | None = None,
    timeout: int = 30,
) -> str:
    """Run the ckAppInit handshake; return the per-container `cloudKitUserId` (not the dsid)."""
    headers = _container_headers(bundle=bundle, container=container)
    headers["Authorization"] = "Basic " + base64.b64encode(f"{dsid}:{mme_token}".encode()).decode()
    headers.update(anisette.headers())
    try:
        resp = (http or tls.new_session()).post(
            url, params={"container": container}, headers=headers, data="", timeout=timeout
        )
    except requests.RequestException as e:
        msg = f"network error talking to ckAppInit: {e}"
        raise CloudKitError(msg) from e
    if resp.status_code == HTTPStatus.UNAUTHORIZED:
        msg = "ckAppInit rejected the mmeAuthToken (HTTP 401); sign in again"
        raise CloudKitError(msg, http_status=resp.status_code)
    try:
        user_id: object = resp.json()["cloudKitUserId"]
    except (ValueError, KeyError, TypeError) as e:
        msg = f"ckAppInit returned HTTP {resp.status_code} without a cloudKitUserId"
        raise CloudKitError(msg, http_status=resp.status_code) from e
    if not isinstance(user_id, str) or not user_id:
        msg = "ckAppInit returned an empty cloudKitUserId"
        raise CloudKitError(msg, http_status=resp.status_code)
    return user_id


class CloudKitError(AppleError):
    """A CloudKit transport/operation failure (network, HTTP, or a non-success result)."""

    def __init__(
        self,
        message: str,
        *,
        code: int | None = None,
        description: str | None = None,
        http_status: int | None = None,
        client_error: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.description = description
        self.http_status = http_status
        self.client_error = client_error

    @property
    def unauthorized(self) -> bool:
        return self.http_status in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}


@dataclasses.dataclass(frozen=True, slots=True)
class CloudKitResult:
    code: int
    error_description: str | None
    fields: Fields  # decoded ResponseOperation top-level fields
    client_error: int | None = None
    retry_after: int | None = None
    uuid: str | None = None

    @property
    def ok(self) -> bool:
        return self.code == RESULT_SUCCESS

    @property
    def conflict(self) -> bool:
        return self.client_error in CONFLICT_CODES

    @property
    def serialized_result(self) -> bytes:
        """functionInvokeResponse(1101).serializedResult(1): the CKCode op's response proto."""
        fir = first_message(self.fields, 1101)
        return (first_bytes(fir, 1) or b"") if fir is not None else b""

    def field(self, num: int) -> bytes | None:
        """Raw bytes of an operation-specific response field (e.g. retrieveChanges = 213)."""
        return first_bytes(self.fields, num)

    def error(self, what: str) -> CloudKitError:
        msg = f"{what} failed: {self.error_description or 'unknown'}"
        if self.client_error is not None:
            msg += f" (client error {self.client_error})"
        return CloudKitError(
            msg, code=self.code, description=self.error_description, client_error=self.client_error
        )


def _present[T](fields: Fields, num: int, value: T | None, what: str) -> T | None:
    """`value` as read from singular field `num`, refusing one present but unreadable or repeated.

    A damaged field is not an absent one: a reply's missing result or code means success, so
    reading a malformed one as missing could confirm a write the server never acknowledged.
    A repeated one contradicts itself, and picking either copy could do the same.
    """
    occurrences = len(fields.get(num, []))
    if occurrences > 1:
        msg = f"response operation carries {occurrences} copies of its {what}"
        raise _proto.ProtoError(msg)
    if value is None and occurrences:
        msg = f"response operation carries a malformed {what}"
        raise _proto.ProtoError(msg)
    return value


def parse_response_operation(raw: bytes) -> CloudKitResult:
    f = decode_fields(raw)
    op = _present(f, 2, first_message(f, 2), "operation")
    uuid = _present(op, 1, first_str(op, 1), "operation id") if op is not None else None
    rf = _present(f, 3, first_message(f, 3), "result")
    if rf is None and uuid is None:
        # A reply naming neither an operation nor a result acknowledges nothing; reading it as
        # success would let a damaged body confirm a delete or save that never happened.
        msg = "response operation names no operation and carries no result"
        raise _proto.ProtoError(msg)
    code = RESULT_SUCCESS
    err: str | None = None
    client: int | None = None
    retry: int | None = None
    if rf is not None:
        explicit = _present(rf, 1, first_int(rf, 1), "result code")
        code = RESULT_SUCCESS if explicit is None else explicit
        ef = _present(rf, 2, first_message(rf, 2), "result error")
        if ef is not None:
            err = first_str(ef, 4)
            retry = first_int(ef, 3)
            ce = first_message(ef, 1)
            client = first_int(ce, 1) if ce is not None else None
    return CloudKitResult(code, err, f, client_error=client, retry_after=retry, uuid=uuid)


def build_response_operation(  # noqa: PLR0913 - every field the local fake server answers with
    uuid: str,
    op_type: int,
    *,
    code: int = RESULT_SUCCESS,
    client_error: int | None = None,
    description: str | None = None,
    field: int | None = None,
    payload: bytes | None = None,
) -> bytes:
    """Build a ResponseOperation as the gateway would send it (used by the local fake server)."""
    error = None
    if client_error is not None or description is not None:
        error = (
            Writer()
            .message(1, Writer().uint64(1, client_error) if client_error is not None else None)
            .string(4, description)
        )
    w = (
        Writer()
        .message(2, Writer().string(1, uuid).uint64(2, op_type))
        .message(3, Writer().uint64(1, code).message(2, error))
    )
    if field is not None:
        w.message(field, payload or b"")
    return w.finish()


class CloudKitTransport:
    """Performs CloudKit operations for one container over one keep-alive HTTP session."""

    def __init__(  # noqa: PLR0913 - session tokens plus the device identity and test seams
        self,
        ck_token: str,
        user_id: str,
        device: DeviceConfig,
        anisette: AnisetteSource,
        *,
        mme_client_info: str | None = None,
        container: str = CUTTLEFISH_CONTAINER,
        gateway: str = GATEWAY_URL,
        http: requests.Session | None = None,
        timeout: int = 30,
    ) -> None:
        self.ck_token = ck_token
        self.user_id = user_id
        self.device = device
        self.anisette = anisette
        self.container = container
        self.mme_client_info = mme_client_info
        self.gateway = gateway.rstrip("/")
        self.timeout = timeout
        self._http = http or tls.new_session()

    def _headers(
        self, bundle: str, routing_hint: str | None = None, *, database: int = DB_PRIVATE
    ) -> dict[str, str]:
        h = _container_headers(
            bundle=bundle,
            container=self.container,
            database_scope="Shared" if database == DB_SHARED else "Private",
            mme_client_info=self.mme_client_info or CK_MME_CLIENT_INFO,
        )
        h["x-cloudkit-userid"] = self.user_id
        h["x-cloudkit-authtoken"] = self.ck_token
        if routing_hint:
            h["x-cloudkit-functionroutinghint"] = routing_hint
        h.update(self.anisette.headers())
        return h

    def _post(self, path: str, body: bytes, headers: dict[str, str]) -> list[bytes]:
        url = f"{self.gateway}{path}"
        try:
            resp = self._http.post(url, headers=headers, data=body, timeout=self.timeout)
        except requests.RequestException as e:
            msg = f"network error talking to {url}: {e}"
            raise CloudKitError(msg) from e
        if not resp.ok:
            msg = f"{path} returned HTTP {resp.status_code}"
            raise CloudKitError(msg, http_status=resp.status_code)
        try:
            messages = undelimit(maybe_gunzip(resp.content))
        except (_proto.ProtoError, OSError, EOFError, zlib.error) as e:
            msg = f"{path} returned an undecodable body ({len(resp.content)} bytes)"
            raise CloudKitError(msg, http_status=resp.status_code) from e
        if not messages:
            msg = f"{path} returned no response operation"
            raise CloudKitError(msg, http_status=resp.status_code)
        return messages

    def perform_batch(
        self,
        path: str,
        ops: Sequence[Operation],
        *,
        bundle: str,
        routing_hint: str | None = None,
        database: int = DB_PRIVATE,
    ) -> list[CloudKitResult]:
        """POST several operations in one request; return their results in request order."""
        header = build_header(
            self.device, container=self.container, bundle=bundle, database=database
        )
        body = gzip.compress(build_batch(header, ops))
        messages = self._post(path, body, self._headers(bundle, routing_hint, database=database))
        return _in_request_order(path, ops, [_parse_checked(m) for m in messages])

    def _perform(
        self,
        path: str,
        op: Operation,
        *,
        bundle: str,
        routing_hint: str | None = None,
        database: int = DB_PRIVATE,
    ) -> CloudKitResult:
        [result] = self.perform_batch(
            path, [op], bundle=bundle, routing_hint=routing_hint, database=database
        )
        if not result.ok:
            msg = "CloudKit operation"
            raise result.error(msg)
        return result

    def invoke(self, op_name: str, parameters: bytes) -> CloudKitResult:
        """Run a CKCode function (Cuttlefish RPC); return its successful result."""
        fir = encode_function_invoke_request(CUTTLEFISH_SERVICE, op_name, parameters)
        return self._perform(
            CKCODE_INVOKE_PATH,
            Operation(OP_TYPE_FUNCTION_INVOKE, 1101, fir),
            bundle=CUTTLEFISH_BUNDLE,
            routing_hint=f"{CUTTLEFISH_SERVICE}/{op_name}",
        )

    def fetch_records(
        self,
        zone_request_bytes: bytes,
        *,
        bundle: str = SECURITYD_BUNDLE,
        database: int = DB_PRIVATE,
    ) -> bytes:
        """Fetch a page of a zone's changes; return retrieveChangesResponse(213) bytes."""
        result = self._perform(
            CKDATABASE_SYNC_PATH,
            Operation(
                ckks.OP_TYPE_RECORD_RETRIEVE_CHANGES,
                ckks.FIELD_RETRIEVE_CHANGES,
                zone_request_bytes,
            ),
            bundle=bundle,
            database=database,
        )
        return result.field(ckks.FIELD_RETRIEVE_CHANGES) or b""

    def save_records(
        self,
        saves: Sequence[tuple[ckks.CloudKitRecord, bool]],
        *,
        bundle: str = SECURITYD_BUNDLE,
        database: int = DB_PRIVATE,
    ) -> list[CloudKitResult]:
        """Save (record, create?) pairs in one zone-atomic batch; results in request order."""
        ops = [
            Operation(
                ckks.OP_TYPE_RECORD_SAVE,
                ckks.FIELD_RECORD_SAVE,
                ckks.build_save_request(rec, create=create),
            )
            for rec, create in saves
        ]
        return self.perform_batch(CKDATABASE_SAVE_PATH, ops, bundle=bundle, database=database)

    def delete_records(
        self,
        deletes: Sequence[tuple[str, ckks.ZoneId, str | None]],
        *,
        bundle: str = SECURITYD_BUNDLE,
        database: int = DB_PRIVATE,
    ) -> list[CloudKitResult]:
        """Delete (name, zone, tag) records in one zone-atomic batch; results in request order.

        Each delete is conditional on its tag (None: unconditional); a stale one fails the
        batch with client error 15 (oplock), its partners with 16 (atomic failure).
        """
        ops = [
            Operation(
                ckks.OP_TYPE_RECORD_DELETE,
                ckks.FIELD_RECORD_DELETE,
                ckks.build_delete_request(name, zone, etag),
            )
            for name, zone, etag in deletes
        ]
        return self.perform_batch(CKDATABASE_DELETE_PATH, ops, bundle=bundle, database=database)


def _parse_checked(raw: bytes) -> CloudKitResult:
    try:
        return parse_response_operation(raw)
    except _proto.ProtoError as e:
        msg = "CloudKit returned a malformed response operation"
        raise CloudKitError(msg) from e


def _in_request_order(
    path: str, ops: Sequence[Operation], results: list[CloudKitResult]
) -> list[CloudKitResult]:
    """Return a batch's results in the order of its operations, matched by operation id."""
    if len(ops) == 1 and len(results) == 1 and results[0].uuid is None:
        return results  # a lone answer needs no matching
    uuids = [r.uuid for r in results]
    if len(results) != len(ops) or None in uuids or len(set(uuids)) != len(uuids):
        # An extra, unnamed or repeated answer contradicts the others; dropping it could
        # turn a refused write into an acknowledged one.
        msg = f"{path} gave {len(results)} answers that do not match its {len(ops)} operations"
        raise CloudKitError(msg)
    return _by_operation_id(path, ops, results)


def _by_operation_id(
    path: str, ops: Sequence[Operation], results: list[CloudKitResult]
) -> list[CloudKitResult]:
    by_uuid = {r.uuid: r for r in results}
    if any(op.uuid not in by_uuid for op in ops):
        msg = f"{path} answered {len(results)} of {len(ops)} operations"
        raise CloudKitError(msg)
    return [by_uuid[op.uuid] for op in ops]
