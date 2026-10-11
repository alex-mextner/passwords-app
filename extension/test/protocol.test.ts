// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import {
  ERROR_CODES,
  ProtocolError,
  parseCandidate,
  parseResponse,
  responseId,
} from "../src/shared/protocol";

const candidate = {
  id: "A1",
  title: "Northwind",
  username: "alex@example.com",
  url: "https://northwind.example",
  alt_urls: ["https://login.northwind.example"],
  has_code: true,
};

describe("parseResponse", () => {
  test("accepts every documented result shape", () => {
    expect(
      parseResponse("status", {
        id: 1,
        ok: true,
        result: { state: "idle", message: "", item_count: 3, protocol: 1 },
      }),
    ).toEqual({
      ok: true,
      result: { state: "idle", message: "", item_count: 3, protocol: 1 },
    });
    expect(parseResponse("match", { id: 1, ok: true, result: { items: [candidate] } })).toEqual({
      ok: true,
      result: { items: [candidate] },
    });
    expect(
      parseResponse("fill", { id: 1, ok: true, result: { username: "u", password: "p" } }),
    ).toEqual({
      ok: true,
      result: { username: "u", password: "p" },
    });
    expect(
      parseResponse("code", { id: 1, ok: true, result: { code: "123456", seconds_left: 9 } }),
    ).toEqual({
      ok: true,
      result: { code: "123456", seconds_left: 9 },
    });
    expect(
      parseResponse("save", {
        id: 1,
        ok: true,
        result: { action: "create", id: null, saved: false },
      }),
    ).toEqual({
      ok: true,
      result: { action: "create", id: null, saved: false },
    });
  });

  test("drops fields the protocol does not define", () => {
    const outcome = parseResponse("fill", {
      id: 1,
      ok: true,
      result: { username: "u", password: "p", otpauth: "otpauth://totp/x?secret=AAAA" },
    });
    expect(outcome).toEqual({ ok: true, result: { username: "u", password: "p" } });
  });

  test("keeps candidates free of anything but the documented fields", () => {
    const outcome = parseResponse("match", {
      id: 1,
      ok: true,
      result: { items: [{ ...candidate, password: "leak", notes: "x" }] },
    });
    expect(outcome.ok && Object.keys(outcome.result.items[0] ?? {}).sort()).toEqual([
      "alt_urls",
      "has_code",
      "id",
      "title",
      "url",
      "username",
    ]);
  });

  test.each(ERROR_CODES.filter((c) => c !== "host-unavailable" && c !== "timeout"))(
    "maps host error %s",
    (code) => {
      expect(parseResponse("match", { id: 2, ok: false, error: { code, message: "m" } })).toEqual({
        ok: false,
        error: { code, message: "m" },
      });
    },
  );

  test("unknown error codes become internal, missing messages become empty", () => {
    expect(parseResponse("fill", { id: 2, ok: false, error: { code: "boom" } })).toEqual({
      ok: false,
      error: { code: "internal", message: "" },
    });
  });

  test.each([
    ["not an object", "match", "nope"],
    ["ok missing", "match", { id: 1, result: {} }],
    ["items not an array", "match", { id: 1, ok: true, result: { items: {} } }],
    [
      "candidate without alt_urls",
      "match",
      { id: 1, ok: true, result: { items: [{ ...candidate, alt_urls: undefined }] } },
    ],
    [
      "alt_urls with a number",
      "match",
      { id: 1, ok: true, result: { items: [{ ...candidate, alt_urls: [1] }] } },
    ],
    [
      "has_code as string",
      "match",
      { id: 1, ok: true, result: { items: [{ ...candidate, has_code: "yes" }] } },
    ],
    [
      "unknown state",
      "status",
      { id: 1, ok: true, result: { state: "dancing", message: "", item_count: 0, protocol: 1 } },
    ],
    [
      "negative count",
      "status",
      { id: 1, ok: true, result: { state: "idle", message: "", item_count: -1, protocol: 1 } },
    ],
    ["fractional seconds", "code", { id: 1, ok: true, result: { code: "1", seconds_left: 1.5 } }],
    ["password as number", "fill", { id: 1, ok: true, result: { username: "u", password: 5 } }],
    [
      "unknown save action",
      "save",
      { id: 1, ok: true, result: { action: "delete", id: null, saved: true } },
    ],
    [
      "save id as number",
      "save",
      { id: 1, ok: true, result: { action: "update", id: 7, saved: true } },
    ],
    ["error not an object", "fill", { id: 1, ok: false, error: "x" }],
  ] as const)("rejects %s", (_name, cmd, value) => {
    expect(() => parseResponse(cmd, value)).toThrow(ProtocolError);
  });
});

describe("parseCandidate", () => {
  test("rejects a candidate that is an array", () => {
    expect(() => parseCandidate([candidate])).toThrow(ProtocolError);
  });
});

describe("responseId", () => {
  test.each([
    [{ id: 3 }, 3],
    [{ id: 0 }, 0],
    [{ id: null }, undefined],
    [{ id: "3" }, undefined],
    [{ id: -1 }, undefined],
    [{ id: 1.5 }, undefined],
    [{ id: 2 ** 53 }, undefined],
    [null, undefined],
    [[1], undefined],
  ] as const)("%j → %p", (value, expected) => {
    expect(responseId(value)).toBe(expected);
  });
});

test("ProtocolError carries its code", () => {
  const error = new ProtocolError("locked", "collection locked");
  expect(error.code).toBe("locked");
  expect(error.message).toBe("collection locked");
  expect(error).toBeInstanceOf(Error);
});
