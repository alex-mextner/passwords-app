// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// One long-lived native port per background lifetime: starting the Python host costs far more
// than a request, and an open port also keeps Chrome's service worker alive while in use.

import {
  type Command,
  HOST_NAME,
  ProtocolError,
  type Request,
  type ResultFor,
  parseResponse,
  responseId,
} from "../shared/protocol";

/** The subset of chrome.runtime.Port the client uses; tests pass a fake. */
export interface NativePort {
  postMessage(message: unknown): void;
  disconnect(): void;
  readonly onMessage: { addListener(listener: (message: unknown) => void): void };
  readonly onDisconnect: { addListener(listener: () => void): void };
}

export type PortFactory = () => NativePort;

type Timer = number | NodeJS.Timeout; // setTimeout's handle: number in browsers, an object in bun

interface Pending {
  readonly cmd: Command;
  readonly resolve: (value: unknown) => void;
  readonly reject: (error: ProtocolError) => void;
  /** Running only while this is the oldest outstanding request (see armHead). */
  timer: Timer | null;
}

export const DEFAULT_TIMEOUT_MS = 15_000;

export function connectHost(): NativePort {
  return chrome.runtime.connectNative(HOST_NAME);
}

export class NativeClient {
  private port: NativePort | null = null;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();

  constructor(
    private readonly connect: PortFactory = connectHost,
    private readonly timeoutMs: number = DEFAULT_TIMEOUT_MS,
    // Firefox and Chrome report why a port closed only through runtime.lastError.
    private readonly lastError: () => string | undefined = () => chrome.runtime.lastError?.message,
  ) {}

  /** Send one request; resolves with the validated result or rejects with ProtocolError. */
  request<C extends Command>(request: Extract<Request, { cmd: C }>): Promise<ResultFor[C]> {
    const port = this.ensurePort();
    const id = this.nextId;
    this.nextId = id >= Number.MAX_SAFE_INTEGER ? 1 : id + 1;
    return new Promise<ResultFor[C]>((resolve, reject) => {
      this.pending.set(id, {
        cmd: request.cmd,
        resolve: resolve as (value: unknown) => void,
        reject,
        timer: null,
      });
      this.armHead();
      try {
        port.postMessage({ id, ...request });
      } catch (error) {
        this.settle(id)?.reject(
          new ProtocolError(
            "host-unavailable",
            error instanceof Error ? error.message : "post failed",
          ),
        );
        this.drop(port);
      }
    });
  }

  /** Close the port; outstanding requests fail with host-unavailable. */
  close(): void {
    const port = this.port;
    if (port !== null) {
      this.drop(port);
      port.disconnect();
    }
  }

  private ensurePort(): NativePort {
    if (this.port !== null) return this.port;
    const port = this.connect();
    port.onMessage.addListener((message) => {
      this.onMessage(message);
    });
    port.onDisconnect.addListener(() => {
      if (this.port === port) this.drop(port, this.lastError());
    });
    this.port = port;
    return port;
  }

  private settle(id: number): Pending | undefined {
    const entry = this.pending.get(id);
    if (entry === undefined) return undefined;
    clearTimeout(entry.timer ?? undefined);
    this.pending.delete(id);
    this.armHead();
    return entry;
  }

  /**
   * Start the timeout of the oldest outstanding request. The host answers one request at a
   * time, in order (PROTOCOL.md), so only the oldest one is being worked on; the rest wait in
   * line and must not spend their time there.
   */
  private armHead(): void {
    const head = this.pending.entries().next();
    if (head.done === true) return;
    const [id, entry] = head.value;
    if (entry.timer !== null) return;
    entry.timer = setTimeout(() => {
      this.settle(id)?.reject(
        new ProtocolError("timeout", `no answer to ${entry.cmd} in ${this.timeoutMs} ms`),
      );
    }, this.timeoutMs);
  }

  private onMessage(message: unknown): void {
    const id = responseId(message);
    if (id === undefined) {
      // A response without our id answers a frame the host could not read at all: every
      // request is well-formed JSON from us, so this means the two sides disagree on framing.
      this.failAll(new ProtocolError("malformed", "response without a request id"));
      return;
    }
    const entry = this.settle(id);
    if (entry === undefined) return;
    try {
      const outcome = parseResponse(entry.cmd, message);
      if (outcome.ok) entry.resolve(outcome.result);
      else entry.reject(new ProtocolError(outcome.error.code, outcome.error.message));
    } catch (error) {
      entry.reject(
        error instanceof ProtocolError ? error : new ProtocolError("malformed", "bad response"),
      );
    }
  }

  private drop(port: NativePort, reason?: string): void {
    if (this.port === port) this.port = null;
    this.failAll(new ProtocolError("host-unavailable", reason ?? "native host disconnected"));
  }

  private failAll(error: ProtocolError): void {
    for (const id of [...this.pending.keys()]) this.settle(id)?.reject(error);
  }
}
