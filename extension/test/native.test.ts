// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
import { afterEach, beforeEach, describe, expect, test, vi } from "bun:test";
import { NativeClient, type NativePort } from "../src/background/native";
import { ProtocolError } from "../src/shared/protocol";

/** An in-memory port: records what the client posts, lets the test answer or hang up. */
class FakePort implements NativePort {
  readonly posted: Record<string, unknown>[] = [];
  disconnected = false;
  private messageListeners: ((message: unknown) => void)[] = [];
  private disconnectListeners: (() => void)[] = [];
  readonly onMessage = {
    addListener: (listener: (message: unknown) => void) => {
      this.messageListeners.push(listener);
    },
  };
  readonly onDisconnect = {
    addListener: (listener: () => void) => {
      this.disconnectListeners.push(listener);
    },
  };
  postMessage(message: unknown): void {
    if (this.disconnected) throw new Error("Attempt to postMessage on disconnected port");
    this.posted.push(message as Record<string, unknown>);
  }
  disconnect(): void {
    this.disconnected = true;
  }
  answer(message: unknown): void {
    for (const listener of this.messageListeners) listener(message);
  }
  hangUp(): void {
    this.disconnected = true;
    for (const listener of this.disconnectListeners) listener();
  }
}

function setup(timeoutMs = 1000, lastError?: string) {
  const ports: FakePort[] = [];
  const client = new NativeClient(
    () => {
      const port = new FakePort();
      ports.push(port);
      return port;
    },
    timeoutMs,
    () => lastError,
  );
  return { client, ports };
}

async function rejection(promise: Promise<unknown>): Promise<ProtocolError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ProtocolError) return error;
    throw error;
  }
  throw new Error("expected a rejection");
}

describe("NativeClient", () => {
  test("sends the request with a fresh id and resolves the validated result", async () => {
    const { client, ports } = setup();
    const pending = client.request({ cmd: "match", url: "https://example.com/" });
    expect(ports[0]?.posted).toEqual([{ id: 1, cmd: "match", url: "https://example.com/" }]);
    ports[0]?.answer({ id: 1, ok: true, result: { items: [] } });
    expect(await pending).toEqual({ items: [] });
  });

  test("connects lazily and reuses one port for many requests", async () => {
    const { client, ports } = setup();
    expect(ports).toHaveLength(0);
    const a = client.request({ cmd: "status" });
    const b = client.request({ cmd: "status" });
    expect(ports).toHaveLength(1);
    expect(ports[0]?.posted.map((m) => m["id"])).toEqual([1, 2]);
    const status = { state: "idle", message: "", item_count: 1, protocol: 1 };
    ports[0]?.answer({ id: 2, ok: true, result: status });
    ports[0]?.answer({ id: 1, ok: true, result: { ...status, item_count: 9 } });
    expect((await a).item_count).toBe(9);
    expect((await b).item_count).toBe(1);
  });

  test("an error response rejects with the host's code", async () => {
    const { client, ports } = setup();
    const pending = client.request({ cmd: "fill", item_id: "X", url: "https://example.com/" });
    ports[0]?.answer({ id: 1, ok: false, error: { code: "not-allowed", message: "nope" } });
    const error = await rejection(pending);
    expect(error.code).toBe("not-allowed");
  });

  test("a malformed result rejects as malformed instead of resolving garbage", async () => {
    const { client, ports } = setup();
    const pending = client.request({ cmd: "fill", item_id: "X", url: "https://example.com/" });
    ports[0]?.answer({ id: 1, ok: true, result: { username: "u" } });
    expect((await rejection(pending)).code).toBe("malformed");
  });

  test("answers for unknown ids are ignored", async () => {
    const { client, ports } = setup();
    const pending = client.request({ cmd: "status" });
    ports[0]?.answer({ id: 99, ok: true, result: {} });
    ports[0]?.answer({
      id: 1,
      ok: true,
      result: { state: "idle", message: "", item_count: 0, protocol: 1 },
    });
    expect((await pending).state).toBe("idle");
  });

  test("a response with a null id fails every outstanding request", async () => {
    const { client, ports } = setup();
    const a = client.request({ cmd: "status" });
    const b = client.request({ cmd: "status" });
    ports[0]?.answer({ id: null, ok: false, error: { code: "malformed", message: "" } });
    expect((await rejection(a)).code).toBe("malformed");
    expect((await rejection(b)).code).toBe("malformed");
  });

  test("a disconnect fails pending requests with the browser's reason and reconnects next time", async () => {
    const { client, ports } = setup(1000, "Specified native messaging host not found.");
    const pending = client.request({ cmd: "status" });
    ports[0]?.hangUp();
    const error = await rejection(pending);
    expect(error.code).toBe("host-unavailable");
    expect(error.message).toBe("Specified native messaging host not found.");
    const next = client.request({ cmd: "status" });
    expect(ports).toHaveLength(2);
    ports[1]?.answer({
      id: 2,
      ok: true,
      result: { state: "idle", message: "", item_count: 0, protocol: 1 },
    });
    expect((await next).state).toBe("idle");
  });

  test("a request that is never answered times out and later answers are dropped", async () => {
    const { client, ports } = setup(20);
    const pending = client.request({ cmd: "status" });
    const error = await rejection(pending);
    expect(error.code).toBe("timeout");
    ports[0]?.answer({
      id: 1,
      ok: true,
      result: { state: "idle", message: "", item_count: 0, protocol: 1 },
    });
  });

  describe("timers follow the host's one-at-a-time order (PROTOCOL.md)", () => {
    const status = { state: "idle", message: "", item_count: 0, protocol: 1 };
    beforeEach(() => {
      vi.useFakeTimers();
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    test("a request's timer starts when the host reaches it, not while it waits in line", async () => {
      const { client, ports } = setup(60);
      const first = client.request({ cmd: "status" });
      const second = client.request({ cmd: "status" });
      vi.advanceTimersByTime(45);
      ports[0]?.answer({ id: 1, ok: true, result: status });
      await first;
      vi.advanceTimersByTime(45); // 90 ms after sending, 45 ms of it in the host
      ports[0]?.answer({ id: 2, ok: true, result: status });
      expect((await second).state).toBe("idle");
    });

    test("a request waiting behind one that timed out gets its own full time", async () => {
      const { client, ports } = setup(40);
      const first = client.request({ cmd: "status" });
      const second = client.request({ cmd: "status" });
      vi.advanceTimersByTime(40);
      expect((await rejection(first)).code).toBe("timeout");
      vi.advanceTimersByTime(25);
      ports[0]?.answer({ id: 2, ok: true, result: status });
      expect((await second).state).toBe("idle");
    });

    test("the next request still times out on its own", async () => {
      const { client, ports } = setup(40);
      const first = client.request({ cmd: "status" });
      const second = client.request({ cmd: "status" });
      ports[0]?.answer({ id: 1, ok: true, result: status });
      await first;
      vi.advanceTimersByTime(40);
      expect((await rejection(second)).code).toBe("timeout");
    });
  });

  test("posting on a dead port fails the request and drops the port", async () => {
    const { client, ports } = setup();
    void client.request({ cmd: "status" }).catch(() => undefined);
    if (ports[0] !== undefined) ports[0].disconnected = true;
    const error = await rejection(client.request({ cmd: "status" }));
    expect(error.code).toBe("host-unavailable");
    void client.request({ cmd: "status" }).catch(() => undefined);
    expect(ports).toHaveLength(2);
  });

  test("close disconnects and fails outstanding requests", async () => {
    const { client, ports } = setup();
    const pending = client.request({ cmd: "status" });
    client.close();
    expect(ports[0]?.disconnected).toBe(true);
    expect((await rejection(pending)).code).toBe("host-unavailable");
  });
});
