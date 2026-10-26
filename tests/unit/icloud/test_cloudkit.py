# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
# These tests poke the transport's framing helpers and fake raw response bodies.
# pyright: reportPrivateUsage=false
"""CloudKit framing: batches, headers, response matching, result errors (no network)."""

from __future__ import annotations

import base64
import gzip
from typing import TYPE_CHECKING, Any, override

import pytest
import requests

from passwords_app.icloud import const
from passwords_app.icloud.proto import codec as pb
from passwords_app.icloud.proto import cuttlefish as cf
from passwords_app.icloud.transport import ckks
from passwords_app.icloud.transport import cloudkit as ck

if TYPE_CHECKING:
    from collections.abc import Callable

DEV = ck.DeviceConfig(device_uuid="UUID-DEV", serial="C02ABC")
EXPECTED_CONTENT_TYPE = (
    'application/x-protobuf; desc="https://gateway.icloud.com:443'
    '/static/protobuf/CloudDB/CloudDBClient.desc"; '
    "messageType=RequestOperation; delimited=true"
)
ZONE = ckks.ZoneId("Passwords", "_u")


class _Anisette:
    def __init__(self, extra: dict[str, str] | None = None) -> None:
        self.extra = extra or {}

    def headers(self) -> dict[str, str]:
        return dict(self.extra)


def _response(content: bytes, status: int = 200) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status
    resp._content = content
    return resp


class _Http(requests.Session):
    """Answers each POST from `answer(body)`, recording what was sent."""

    def __init__(self, answer: Callable[[bytes], requests.Response]) -> None:
        super().__init__()
        self.answer = answer
        self.sent: list[dict[str, Any]] = []

    @override
    def post(self, url: Any, data: Any = None, **kwargs: Any) -> requests.Response:  # type: ignore[override]
        self.sent.append({"url": url, "data": data, **kwargs})
        return self.answer(data)


def _ops_of(body: bytes) -> list[ck.ParsedRequest]:
    return [ck.parse_request(m) for m in ck.undelimit(gzip.decompress(body))]


def _echo_ok(body: bytes, *, reverse: bool = False, drop: int = 0) -> requests.Response:
    ops = _ops_of(body)
    answers = [ck.build_response_operation(op.uuid, op.op_type) for op in ops]
    answers = answers[drop:]
    if reverse:
        answers.reverse()
    return _response(gzip.compress(b"".join(ck.delimit(a) for a in answers)))


def _transport(http: requests.Session, **kw: Any) -> ck.CloudKitTransport:
    return ck.CloudKitTransport("CKTOKEN", "USERID", DEV, _Anisette(), http=http, **kw)


# --- framing ---------------------------------------------------------------------------------


@pytest.mark.parametrize("msgs", [[b""], [b"a", b"x" * 200], [bytes(range(50)), b"", b"z" * 300]])
def test_delimit_round_trip(msgs: list[bytes]) -> None:
    assert ck.undelimit(b"".join(ck.delimit(m) for m in msgs)) == msgs


def test_undelimit_rejects_a_short_final_message() -> None:
    with pytest.raises(pb.ProtoError):
        ck.undelimit(ck.delimit(b"abcdef")[:-2])


def test_real_gzip_is_decompressed() -> None:
    original = b"\x0a\x05hello-protobuf-body"
    assert ck.maybe_gunzip(gzip.compress(original)) == original


@pytest.mark.parametrize("plain", [b"\x9eK\x01\x02\x03", b"\x0a\x02hi", b"", b"\x1f"])
def test_plain_body_is_untouched(plain: bytes) -> None:
    assert ck.maybe_gunzip(plain) == plain


def test_header_fields() -> None:
    f = pb.decode_fields(ck.build_header(DEV))
    assert pb.first_str(f, 2) == ck.CUTTLEFISH_CONTAINER
    assert pb.first_str(f, 3) == ck.CUTTLEFISH_BUNDLE
    assert pb.first_int(f, 19) == ck.ENV_PRODUCTION
    assert pb.first_int(f, 23) == ck.DB_PRIVATE
    assert pb.first_int(f, 25) == ck.ISOLATION_ZONE
    assert pb.first_str(f, 33) == "C02ABC"
    ident = pb.first_message(f, 7) or {}
    assert (pb.first_str(ident, 1), pb.first_int(ident, 2)) == (
        "UUID-DEV",
        ck.IDENTIFIER_TYPE_DEVICE,
    )


def test_header_targets_the_shared_database_when_asked() -> None:
    f = pb.decode_fields(ck.build_header(DEV, database=ck.DB_SHARED))
    assert pb.first_int(f, 23) == ck.DB_SHARED


def test_batch_puts_header_on_first_op_and_last_on_final_op() -> None:
    ops = [ck.Operation(210, 210, b"a"), ck.Operation(210, 210, b"b"), ck.Operation(210, 210, b"c")]
    parsed = [pb.decode_fields(m) for m in ck.undelimit(ck.build_batch(b"HEADER", ops))]
    assert [pb.first_bytes(f, 1) for f in parsed] == [b"HEADER", None, None]
    assert [pb.first_bytes(f, 210) for f in parsed] == [b"a", b"b", b"c"]
    lasts = [pb.first_int(pb.first_message(f, 2) or {}, 4) for f in parsed]
    assert lasts == [None, None, 1]


def test_batch_ops_have_distinct_uppercase_uuids() -> None:
    ops = [ck.Operation(214, 214, b"") for _ in range(5)]
    uuids = [ck.parse_request(m).uuid for m in ck.undelimit(ck.build_batch(b"H", ops))]
    assert uuids == [op.uuid for op in ops]
    assert len(set(uuids)) == 5
    assert all(u == u.upper() for u in uuids)


def test_single_op_is_marked_last() -> None:
    [raw] = ck.undelimit(ck.build_batch(b"H", [ck.Operation(1101, 1101, b"x", uuid="OP-1")]))
    req = ck.parse_request(raw)
    assert (req.uuid, req.op_type, req.payload(1101)) == ("OP-1", 1101, b"x")
    assert pb.first_int(pb.first_message(req.fields, 2) or {}, 4) == 1


# --- headers ---------------------------------------------------------------------------------


def test_container_headers_match_upstream() -> None:
    h = ck._container_headers(bundle=ck.CUTTLEFISH_BUNDLE, container=ck.CUTTLEFISH_CONTAINER)
    assert h["accept"] == "application/x-protobuf"
    assert h["accept-encoding"] == "gzip"
    assert h["content-encoding"] == "gzip"
    assert h["content-type"] == EXPECTED_CONTENT_TYPE
    assert h["user-agent"] == "CloudKit/1970 (19H384)"
    assert h["x-cloudkit-databasescope"] == "Private"
    assert h["x-cloudkit-environment"] == "Production"
    assert h["x-cloudkit-bundleid"] == ck.CUTTLEFISH_BUNDLE
    assert h["x-cloudkit-containerid"] == ck.CUTTLEFISH_CONTAINER


def test_operation_ids_are_16_uppercase_hex_and_differ() -> None:
    h = ck._container_headers(bundle="b", container="c")
    for key in ("x-apple-operation-group-id", "x-apple-operation-id"):
        assert len(h[key]) == 16
        assert h[key] == h[key].upper()
        int(h[key], 16)
    assert h["x-apple-operation-group-id"] != h["x-apple-operation-id"]
    assert h["x-apple-request-uuid"] == h["x-apple-request-uuid"].upper()


def test_transport_headers_carry_auth_and_anisette() -> None:
    t = ck.CloudKitTransport("CKTOKEN", "USERID", DEV, _Anisette({"X-Apple-I-MD-M": "m"}))
    h = t._headers(ck.CUTTLEFISH_BUNDLE, routing_hint="Cuttlefish/joinWithVoucher")
    assert h["x-cloudkit-authtoken"] == "CKTOKEN"
    assert h["x-cloudkit-userid"] == "USERID"
    assert h["x-cloudkit-functionroutinghint"] == "Cuttlefish/joinWithVoucher"
    assert h["X-Apple-I-MD-M"] == "m"
    h2 = t._headers(ck.SECURITYD_BUNDLE)
    assert h2["x-cloudkit-bundleid"] == ck.SECURITYD_BUNDLE
    assert "x-cloudkit-functionroutinghint" not in h2


def test_shared_database_scope_header() -> None:
    t = ck.CloudKitTransport("t", "u", DEV, _Anisette())
    assert t._headers("b", database=ck.DB_SHARED)["x-cloudkit-databasescope"] == "Shared"


def test_ck_app_init_auth_and_shape() -> None:
    http = _Http(lambda _: _response(b'{"cloudKitUserId": "_ckuser123"}'))
    uid = ck.ck_app_init(
        ck.CUTTLEFISH_CONTAINER,
        ck.CUTTLEFISH_BUNDLE,
        "163",
        "MME",
        _Anisette({"X-Apple-I-MD": "md"}),
        http=http,
    )
    assert uid == "_ckuser123"
    [sent] = http.sent
    assert sent["url"] == ck.CK_APP_INIT_URL
    assert sent["params"] == {"container": ck.CUTTLEFISH_CONTAINER}
    assert sent["data"] == ""
    assert sent["headers"]["Authorization"] == "Basic " + base64.b64encode(b"163:MME").decode()
    assert sent["headers"]["X-Apple-I-MD"] == "md"


def test_ck_app_init_claims_the_anisette_platform() -> None:
    http = _Http(lambda _: _response(b'{"cloudKitUserId": "_ckuser123"}'))
    ck.ck_app_init(
        ck.CUTTLEFISH_CONTAINER, ck.CUTTLEFISH_BUNDLE, "163", "MME", _Anisette(), http=http
    )
    [sent] = http.sent
    assert sent["headers"]["x-mme-client-info"].startswith(const.WINDOWS_PLATFORM)


# --- responses -------------------------------------------------------------------------------


def test_success_result_exposes_serialized_function_result() -> None:
    fir = pb.Writer().bytes(1, b"cuttlefish-response").finish()
    out = ck.parse_response_operation(
        ck.build_response_operation("U", 1101, field=1101, payload=fir)
    )
    assert out.ok
    assert out.uuid == "U"
    assert out.serialized_result == b"cuttlefish-response"


def test_failure_surfaces_description_client_error_and_retry() -> None:
    err = pb.Writer().message(1, pb.Writer().uint64(1, 15)).uint64(3, 30).string(4, "changed")
    raw = pb.Writer().message(3, pb.Writer().uint64(1, 3).message(2, err)).finish()
    out = ck.parse_response_operation(raw)
    assert not out.ok
    assert (out.error_description, out.client_error, out.retry_after) == ("changed", 15, 30)
    assert out.conflict


@pytest.mark.parametrize(
    ("client_error", "conflict"),
    [
        (ck.CLIENT_EXISTS, True),
        (ck.CLIENT_OP_LOCK_FAILURE, True),
        (ck.CLIENT_STALE_RECORD_UPDATE, True),
        (ck.CLIENT_ATOMIC_FAILURE, False),
        (ck.CLIENT_ZONE_NOT_FOUND, False),
        (None, False),
    ],
)
def test_conflict_codes(client_error: int | None, conflict: bool) -> None:
    raw = ck.build_response_operation("U", 210, code=3, client_error=client_error, description="x")
    assert ck.parse_response_operation(raw).conflict is conflict


def test_result_error_carries_the_codes() -> None:
    raw = ck.build_response_operation("U", 210, code=3, client_error=24, description="bad field")
    err = ck.parse_response_operation(raw).error("saving")
    assert isinstance(err, ck.CloudKitError)
    assert (err.code, err.client_error, err.description) == (3, 24, "bad field")
    assert "saving failed: bad field (client error 24)" in str(err)


def test_missing_result_on_a_named_operation_means_success() -> None:
    raw = pb.Writer().message(2, pb.Writer().string(1, "U")).finish()
    assert ck.parse_response_operation(raw).ok


def test_reply_without_operation_or_result_is_no_acknowledgement() -> None:
    with pytest.raises(pb.ProtoError, match="no operation"):
        ck.parse_response_operation(b"")


_NAMED = pb.Writer().message(2, pb.Writer().string(1, "U"))
_ERR = pb.Writer().message(1, pb.Writer().uint64(1, 60))


@pytest.mark.parametrize(
    ("raw", "what"),
    [
        (pb.Writer().uint64(3, 3).finish(), "malformed result"),
        (pb.Writer().uint64(2, 3).message(3, pb.Writer()).finish(), "malformed operation"),
        (_NAMED.finish() + pb.Writer().uint64(3, 3).finish(), "malformed result"),
        (
            _NAMED.finish()
            + pb.Writer().message(3, pb.Writer().bytes(1, b"\x03").message(2, _ERR)).finish(),
            "malformed result code",
        ),
        (
            _NAMED.finish() + pb.Writer().message(3, pb.Writer().uint64(2, 1)).finish(),
            "malformed result error",
        ),
    ],
)
def test_a_present_but_malformed_field_is_rejected(raw: bytes, what: str) -> None:
    with pytest.raises(pb.ProtoError, match=what):
        ck.parse_response_operation(raw)


def test_named_operation_with_malformed_result_fails_the_batch() -> None:
    raw = _NAMED.finish() + pb.Writer().uint64(3, 3).finish()
    http = _Http(lambda _: _response(ck.delimit(raw)))
    with pytest.raises(ck.CloudKitError):
        _transport(http).perform_batch("/p", [ck.Operation(1, 1, b"")], bundle="b")


@pytest.mark.parametrize(
    "op",
    [pb.Writer().uint64(1, 7), pb.Writer().bytes(1, b"\xff")],
    ids=["int-id", "non-utf8-id"],
)
def test_damaged_operation_id_fails_the_lone_answer(op: pb.Writer) -> None:
    ok = pb.Writer().message(3, pb.Writer().uint64(1, ck.RESULT_SUCCESS))
    raw = pb.Writer().message(2, op).finish() + ok.finish()
    http = _Http(lambda _: _response(ck.delimit(raw)))
    with pytest.raises(ck.CloudKitError, match="malformed"):
        _transport(http).perform_batch("/p", [ck.Operation(1, 1, b"")], bundle="b")


def test_two_answers_for_one_operation_fail_the_batch() -> None:
    op = ck.Operation(210, 210, b"x")
    failed = ck.build_response_operation(op.uuid, 210, code=3, client_error=60)
    ok = ck.build_response_operation(op.uuid, 210)
    http = _Http(lambda _: _response(ck.delimit(failed) + ck.delimit(ok)))
    with pytest.raises(ck.CloudKitError, match="do not match"):
        _transport(http).perform_batch("/p", [op], bundle="b")


def test_unnamed_failure_beside_a_named_success_fails_the_batch() -> None:
    op = ck.Operation(210, 210, b"x")
    ok = ck.build_response_operation(op.uuid, 210)
    failed = pb.Writer().message(3, pb.Writer().uint64(1, 3)).finish()
    http = _Http(lambda _: _response(ck.delimit(ok) + ck.delimit(failed)))
    with pytest.raises(ck.CloudKitError, match="do not match"):
        _transport(http).perform_batch("/p", [op], bundle="b")


def test_answer_to_an_unknown_operation_fails_the_batch() -> None:
    op = ck.Operation(210, 210, b"x")
    http = _Http(lambda _: _response(ck.delimit(ck.build_response_operation("other", 210))))
    with pytest.raises(ck.CloudKitError, match="answered 1 of 1"):
        _transport(http).perform_batch("/p", [op], bundle="b")


def test_contradicting_result_codes_fail_the_delete() -> None:
    op = ck.Operation(210, 210, b"x")
    error = pb.Writer().message(1, pb.Writer().uint64(1, 60))
    result = pb.Writer().uint64(1, ck.RESULT_SUCCESS).uint64(1, 3).message(2, error)
    raw = pb.Writer().message(2, pb.Writer().string(1, op.uuid)).message(3, result).finish()
    http = _Http(lambda _: _response(ck.delimit(raw)))
    with pytest.raises(ck.CloudKitError, match="malformed"):
        _transport(http).perform_batch("/p", [op], bundle="b")


def test_empty_lone_answer_does_not_confirm_a_delete() -> None:
    http = _Http(lambda _: _response(ck.delimit(b"")))
    with pytest.raises(ck.CloudKitError):
        _transport(http).perform_batch("/p", [ck.Operation(1, 1, b"")], bundle="b")


def test_corrupt_deflate_body_is_a_cloudkit_error() -> None:
    bad = bytes.fromhex("1f8b08000000000000ff07000000000000000000")
    http = _Http(lambda _: _response(bad))
    with pytest.raises(ck.CloudKitError, match="undecodable"):
        _transport(http).perform_batch("/p", [ck.Operation(1, 1, b"")], bundle="b")


def test_function_invoke_result_feeds_cuttlefish_parser() -> None:
    peer = cf.encode_cuttlefish_peer(
        "SHA256:p", cf.SignedBlob(b"i", b"s"), cf.SignedBlob(b"i", b"s"), cf.SignedBlob(b"i", b"s")
    )
    changes = pb.Writer().string(1, "tok").message(2, pb.Writer().message(3, peer))
    fir = pb.Writer().bytes(1, pb.Writer().message(1, changes).finish()).finish()
    out = ck.parse_response_operation(
        ck.build_response_operation("U", 1101, field=1101, payload=fir)
    )
    parsed = cf.parse_fetch_changes_response(out.serialized_result)
    assert parsed.sync_token == "tok"
    assert [p.hash for p in parsed.peers] == ["SHA256:p"]


# --- batches over HTTP ---------------------------------------------------------------------------


def test_batch_results_are_matched_by_uuid_not_position() -> None:
    http = _Http(lambda body: _echo_ok(body, reverse=True))
    ops = [ck.Operation(210, 210, bytes([i])) for i in range(4)]
    results = _transport(http).perform_batch("/p", ops, bundle="b")
    assert [r.uuid for r in results] == [op.uuid for op in ops]


def test_batch_with_an_unanswered_op_raises() -> None:
    http = _Http(lambda body: _echo_ok(body, drop=1))
    ops = [ck.Operation(210, 210, b"a"), ck.Operation(210, 210, b"b")]
    with pytest.raises(ck.CloudKitError, match="1 answers that do not match its 2"):
        _transport(http).perform_batch("/p", ops, bundle="b")


def test_lone_answer_without_uuid_is_accepted() -> None:
    op = pb.Writer().message(3, pb.Writer().uint64(1, 1)).finish()
    http = _Http(lambda _: _response(gzip.compress(ck.delimit(op))))
    [result] = _transport(http).perform_batch("/p", [ck.Operation(1, 1, b"")], bundle="b")
    assert result.ok


def test_batch_body_is_gzipped_and_goes_to_the_gateway() -> None:
    http = _Http(_echo_ok)
    _transport(http, gateway="https://gw.example/").perform_batch(
        "/ckdatabase/x", [ck.Operation(214, 214, b"q")], bundle=ck.SECURITYD_BUNDLE
    )
    [sent] = http.sent
    assert sent["url"] == "https://gw.example/ckdatabase/x"
    [req] = _ops_of(sent["data"])
    assert req.payload(214) == b"q"
    assert sent["headers"]["x-cloudkit-bundleid"] == ck.SECURITYD_BUNDLE


def test_save_records_sends_one_conditional_op_per_record() -> None:
    http = _Http(_echo_ok)
    recs = [
        (ckks.CloudKitRecord("A", "item", {}, etag="e1", zone=ZONE), False),
        (ckks.CloudKitRecord("B", "item", {}, zone=ZONE), True),
    ]
    results = _transport(http).save_records(recs)
    assert all(r.ok for r in results)
    [sent] = http.sent
    assert sent["url"].endswith(ck.CKDATABASE_SAVE_PATH)
    saved = [ckks.parse_save_request(op.payload(210) or b"") for op in _ops_of(sent["data"])]
    assert saved == [(recs[0][0], False, "e1"), (recs[1][0], True, None)]


def test_delete_records_sends_each_record_conditional_on_its_tag() -> None:
    http = _Http(_echo_ok)
    _transport(http).delete_records([("A", ZONE, "e1"), ("B", ZONE, None)])
    [sent] = http.sent
    assert sent["url"].endswith(ck.CKDATABASE_DELETE_PATH)
    names = [ckks.parse_delete_request(op.payload(214) or b"") for op in _ops_of(sent["data"])]
    assert names == [("A", ZONE, "e1"), ("B", ZONE, None)]


def test_failed_single_operation_raises_with_client_error() -> None:
    def answer(body: bytes) -> requests.Response:
        [op] = _ops_of(body)
        raw = ck.build_response_operation(
            op.uuid, op.op_type, code=3, client_error=40, description="reset"
        )
        return _response(gzip.compress(ck.delimit(raw)))

    with pytest.raises(ck.CloudKitError) as info:
        _transport(_Http(answer)).fetch_records(b"")
    assert info.value.client_error == ck.CLIENT_FULL_RESET_NEEDED


@pytest.mark.parametrize(("status", "unauthorized"), [(401, True), (403, True), (500, False)])
def test_http_status_marks_unauthorized(status: int, unauthorized: bool) -> None:
    with pytest.raises(ck.CloudKitError) as info:
        _transport(_Http(lambda _: _response(b"", status))).fetch_records(b"")
    assert info.value.http_status == status
    assert info.value.unauthorized is unauthorized
