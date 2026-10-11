// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Shapes of the native messaging protocol (extension/PROTOCOL.md) and strict validators for
// what comes back: the host is trusted, but a validator turns any drift into a clear error
// instead of `undefined` reaching the page.

export const HOST_NAME = "io.github.alex_mextner.passwords";
export const MAX_FRAME_BYTES = 1024 * 1024;

export type ErrorCode =
  | "malformed"
  | "too-large"
  | "bad-request"
  | "not-allowed"
  | "not-found"
  | "daemon-unavailable"
  | "unavailable"
  | "auth-required"
  | "locked"
  | "invalid"
  | "internal"
  // Produced by the extension itself, never by the host.
  | "host-unavailable"
  | "timeout";

export const ERROR_CODES: readonly ErrorCode[] = [
  "malformed",
  "too-large",
  "bad-request",
  "not-allowed",
  "not-found",
  "daemon-unavailable",
  "unavailable",
  "auth-required",
  "locked",
  "invalid",
  "internal",
  "host-unavailable",
  "timeout",
];

export type DaemonState =
  "signed-out" | "syncing" | "idle" | "paused" | "offline" | "signin-required" | "error";

export const DAEMON_STATES: readonly DaemonState[] = [
  "signed-out",
  "syncing",
  "idle",
  "paused",
  "offline",
  "signin-required",
  "error",
];

export interface Candidate {
  readonly id: string;
  readonly title: string;
  readonly username: string;
  readonly url: string;
  readonly alt_urls: readonly string[];
  readonly has_code: boolean;
}

export interface StatusResult {
  readonly state: DaemonState;
  readonly message: string;
  readonly item_count: number;
  readonly protocol: number;
}

export interface MatchResult {
  readonly items: readonly Candidate[];
}

export interface FillResult {
  readonly username: string;
  readonly password: string;
}

export interface CodeResult {
  readonly code: string;
  readonly seconds_left: number;
}

export type SaveAction = "create" | "update" | "none";

export interface SaveResult {
  readonly action: SaveAction;
  readonly id: string | null;
  readonly saved: boolean;
}

export type Request =
  | { readonly cmd: "status" }
  | { readonly cmd: "match"; readonly url: string }
  | { readonly cmd: "fill"; readonly item_id: string; readonly url: string }
  | { readonly cmd: "code"; readonly item_id: string; readonly url: string }
  | {
      readonly cmd: "save";
      readonly url: string;
      readonly username: string;
      readonly password: string;
      readonly title?: string;
      readonly item_id?: string;
      readonly dry_run?: boolean;
    };

export interface ResultFor {
  readonly status: StatusResult;
  readonly match: MatchResult;
  readonly fill: FillResult;
  readonly code: CodeResult;
  readonly save: SaveResult;
}

export type Command = Request["cmd"];

export interface HostError {
  readonly code: ErrorCode;
  readonly message: string;
}

export type Outcome<T> =
  { readonly ok: true; readonly result: T } | { readonly ok: false; readonly error: HostError };

/** Thrown inside the extension when the host answers with an error or cannot be reached. */
export class ProtocolError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
  }
}

type Json = Record<string, unknown>;

function isObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function str(obj: Json, key: string): string {
  const value = obj[key];
  if (typeof value !== "string") throw new ProtocolError("malformed", `${key} must be a string`);
  return value;
}

function bool(obj: Json, key: string): boolean {
  const value = obj[key];
  if (typeof value !== "boolean") throw new ProtocolError("malformed", `${key} must be a boolean`);
  return value;
}

function uint(obj: Json, key: string): number {
  const value = obj[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new ProtocolError("malformed", `${key} must be a non-negative integer`);
  }
  return value;
}

function object(value: unknown, what: string): Json {
  if (!isObject(value)) throw new ProtocolError("malformed", `${what} must be an object`);
  return value;
}

export function parseCandidate(value: unknown): Candidate {
  const obj = object(value, "candidate");
  const altUrls: unknown = obj["alt_urls"];
  if (!Array.isArray(altUrls) || !altUrls.every((u): u is string => typeof u === "string")) {
    throw new ProtocolError("malformed", "alt_urls must be an array of strings");
  }
  return {
    id: str(obj, "id"),
    title: str(obj, "title"),
    username: str(obj, "username"),
    url: str(obj, "url"),
    alt_urls: altUrls,
    has_code: bool(obj, "has_code"),
  };
}

function parseState(value: string): DaemonState {
  const state = DAEMON_STATES.find((s) => s === value);
  if (state === undefined) throw new ProtocolError("malformed", "unknown daemon state");
  return state;
}

const PARSERS: { readonly [C in Command]: (value: unknown) => ResultFor[C] } = {
  status: (value) => {
    const obj = object(value, "status");
    return {
      state: parseState(str(obj, "state")),
      message: str(obj, "message"),
      item_count: uint(obj, "item_count"),
      protocol: uint(obj, "protocol"),
    };
  },
  match: (value) => {
    const items = object(value, "match")["items"];
    if (!Array.isArray(items)) throw new ProtocolError("malformed", "items must be an array");
    return { items: items.map(parseCandidate) };
  },
  fill: (value) => {
    const obj = object(value, "fill");
    return { username: str(obj, "username"), password: str(obj, "password") };
  },
  code: (value) => {
    const obj = object(value, "code");
    return { code: str(obj, "code"), seconds_left: uint(obj, "seconds_left") };
  },
  save: (value) => {
    const obj = object(value, "save");
    const action = str(obj, "action");
    if (action !== "create" && action !== "update" && action !== "none") {
      throw new ProtocolError("malformed", "unknown save action");
    }
    const id = obj["id"];
    if (id !== null && typeof id !== "string") {
      throw new ProtocolError("malformed", "id must be a string or null");
    }
    return { action, id, saved: bool(obj, "saved") };
  },
};

function parseError(value: unknown): HostError {
  const obj = object(value, "error");
  const code = ERROR_CODES.find((c) => c === obj["code"]) ?? "internal";
  const message = typeof obj["message"] === "string" ? obj["message"] : "";
  return { code, message };
}

/** Validate a host response for `cmd`; the id is checked by the caller that matched it. */
export function parseResponse<C extends Command>(cmd: C, value: unknown): Outcome<ResultFor[C]> {
  const obj = object(value, "response");
  if (obj["ok"] === true) return { ok: true, result: PARSERS[cmd](obj["result"]) };
  if (obj["ok"] === false) return { ok: false, error: parseError(obj["error"]) };
  throw new ProtocolError("malformed", "ok must be a boolean");
}

/** The id of a response, or undefined when it has none we could have sent. */
export function responseId(value: unknown): number | undefined {
  if (!isObject(value)) return undefined;
  const id = value["id"];
  return typeof id === "number" && Number.isSafeInteger(id) && id >= 0 ? id : undefined;
}
