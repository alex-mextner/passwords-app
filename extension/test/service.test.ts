// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
import { beforeEach, describe, expect, test } from "bun:test";
import {
  Background,
  type Browser,
  type Host,
  type KeyValueStore,
  PENDING_TTL_MS,
  type Sender,
} from "../src/background/service";
import type { ContentRequest, PromptAnswer, TabCommand } from "../src/shared/messages";
import {
  type Candidate,
  type Command,
  ProtocolError,
  type Request,
  type ResultFor,
} from "../src/shared/protocol";

const NORTHWIND: Candidate = {
  id: "NW",
  title: "Northwind",
  username: "alex@example.com",
  url: "https://northwind.example.com",
  alt_urls: ["https://northwind-mail.example.net"],
  has_code: true,
};
const NO_TITLE: Candidate = {
  id: "NT",
  title: " ",
  username: "",
  url: "https://www.northwind.example.com/login",
  alt_urls: [],
  has_code: false,
};
const FOREIGN: Candidate = {
  id: "EV",
  title: "Evil",
  username: "victim",
  url: "https://evil.example.org",
  alt_urls: [],
  has_code: false,
};

/** A daemon stand-in that answers `match` with a fixed list, whatever the URL. */
class FakeHost implements Host {
  readonly requests: Request[] = [];
  candidates: Candidate[] = [NORTHWIND, NO_TITLE];
  saveAction: "create" | "update" | "none" = "create";
  failWith: ProtocolError | null = null;
  /** While set, `match` answers only once this settles (to order concurrent captures). */
  matchGate: Promise<unknown> | null = null;

  request<C extends Command>(request: Extract<Request, { cmd: C }>): Promise<ResultFor[C]> {
    this.requests.push(request);
    if (this.failWith !== null) return Promise.reject(this.failWith);
    const answer = this.answer(request) as ResultFor[C];
    if (request.cmd === "match" && this.matchGate !== null) {
      return this.matchGate.then(() => answer);
    }
    return Promise.resolve(answer);
  }

  private answer(request: Request): ResultFor[Command] {
    switch (request.cmd) {
      case "status":
        return { state: "idle", message: "", item_count: 2, protocol: 1 };
      case "match":
        return { items: this.candidates };
      case "fill":
        return { username: "alex@example.com", password: "hunter2-hunter2" };
      case "code":
        return { code: "492039", seconds_left: 17 };
      case "save":
        return {
          action: this.saveAction,
          id:
            this.saveAction === "create" && request.dry_run === true
              ? null
              : (request.item_id ?? "NEW"),
          saved: request.dry_run !== true && this.saveAction !== "none",
        };
    }
  }

  commands(): string[] {
    return this.requests.map((r) => r.cmd);
  }
}

class MemoryStore implements KeyValueStore {
  readonly data = new Map<string, unknown>();
  get(key: string): Promise<unknown> {
    return Promise.resolve(this.data.get(key));
  }
  set(key: string, value: unknown): Promise<void> {
    this.data.set(key, value);
    return Promise.resolve();
  }
  remove(key: string): Promise<void> {
    this.data.delete(key);
    return Promise.resolve();
  }
}

class FakeBrowser implements Browser {
  readonly session = new MemoryStore();
  readonly local = new MemoryStore();
  readonly sent: { tabId: number; frameId: number; command: TabCommand }[] = [];
  tops = new Map<number, string>([[1, "https://northwind.example.com/login"]]);
  activeId: number | null = 1;
  clock = 1_000_000;
  applied: unknown = true;

  targetTabId(popupTabId: number | null): Promise<number | null> {
    return Promise.resolve(this.activeId === popupTabId ? null : this.activeId);
  }
  topUrl(tabId: number): Promise<string | null> {
    return Promise.resolve(this.tops.get(tabId) ?? null);
  }
  sendToTab(tabId: number, frameId: number, command: TabCommand): Promise<unknown> {
    this.sent.push({ tabId, frameId, command });
    return Promise.resolve(this.applied);
  }
  now(): number {
    return this.clock;
  }
}

const TOP: Sender = { tabId: 1, frameId: 0, url: "https://northwind.example.com/login" };

let host: FakeHost;
let browser: FakeBrowser;
let bg: Background;

beforeEach(() => {
  host = new FakeHost();
  browser = new FakeBrowser();
  bg = new Background(host, browser);
});

describe("candidates", () => {
  test("asks the daemon for the sender's own URL and returns secret-free views", async () => {
    const reply = await bg.handleContent({ type: "candidates" }, TOP);
    expect(host.requests).toEqual([{ cmd: "match", url: TOP.url }]);
    expect(reply).toEqual({
      ok: true,
      items: [
        {
          id: "NW",
          title: "Northwind",
          username: "alex@example.com",
          host: "northwind.example.com",
          site: "example.com",
          hasCode: true,
        },
        {
          id: "NT",
          title: "northwind.example.com",
          username: "",
          host: "northwind.example.com",
          site: "example.com",
          hasCode: false,
        },
      ],
    });
  });

  test("drops candidates the daemon returned for another site", async () => {
    host.candidates = [NORTHWIND, FOREIGN];
    const reply = await bg.handleContent({ type: "candidates" }, TOP);
    expect(reply.ok && reply.items.map((c) => c.id)).toEqual(["NW"]);
  });

  test("accepts a candidate through one of its additional websites", async () => {
    const sender = { ...TOP, url: "https://northwind-mail.example.net/" };
    const reply = await bg.handleContent({ type: "candidates" }, sender);
    expect(reply.ok && reply.items.map((c) => c.id)).toEqual(["NW"]);
  });

  test("a plain-http page gets nothing from https credentials", async () => {
    const reply = await bg.handleContent(
      { type: "candidates" },
      { ...TOP, url: "http://northwind.example.com/login" },
    );
    expect(reply).toEqual({ ok: true, items: [] });
  });

  test.each([
    ["same-site subframe", "https://auth.northwind.example.com/frame", 2],
    ["third-party subframe", "https://widgets.example.org/frame", 0],
    ["lookalike subframe", "https://northwind.example.com.evil.example/frame", 0],
  ] as const)("%s", async (_name, frameUrl, expected) => {
    host.candidates = [
      NORTHWIND,
      { ...NORTHWIND, id: "W", url: "https://widgets.example.org" },
      { ...NORTHWIND, id: "L", url: "https://northwind.example.com.evil.example" },
    ];
    const reply = await bg.handleContent(
      { type: "candidates" },
      { tabId: 1, frameId: 7, url: frameUrl },
    );
    expect(reply.ok && reply.items.length).toBe(expected === 0 ? 0 : 1);
    if (expected === 0) expect(host.commands()).not.toContain("match");
  });

  test("a subframe whose top page has no content script gets nothing", async () => {
    browser.tops.clear();
    const reply = await bg.handleContent(
      { type: "candidates" },
      { tabId: 1, frameId: 3, url: TOP.url },
    );
    expect(reply).toEqual({ ok: true, items: [] });
  });

  test.each(["daemon-unavailable", "host-unavailable", "locked", "timeout"] as const)(
    "host failure %s is reported, not thrown",
    async (code) => {
      host.failWith = new ProtocolError(code, "x");
      expect(await bg.handleContent({ type: "candidates" }, TOP)).toEqual({
        ok: false,
        error: code,
      });
    },
  );

  test("unexpected exceptions become internal", async () => {
    host.request = () => Promise.reject(new TypeError("boom"));
    expect(await bg.handleContent({ type: "candidates" }, TOP)).toEqual({
      ok: false,
      error: "internal",
    });
  });
});

describe("fill and code", () => {
  test("releases the secret for the sender's origin after re-checking the match", async () => {
    const reply = await bg.handleContent({ type: "fill", id: "NW" }, TOP);
    expect(reply).toEqual({
      ok: true,
      origin: "https://northwind.example.com",
      username: "alex@example.com",
      password: "hunter2-hunter2",
    });
    expect(host.requests).toEqual([
      { cmd: "match", url: TOP.url },
      { cmd: "fill", item_id: "NW", url: TOP.url },
    ]);
  });

  test("never asks for a password of an item that is not a candidate", async () => {
    const reply = await bg.handleContent({ type: "fill", id: "NOPE" }, TOP);
    expect(reply).toEqual({ ok: false, error: "not-allowed" });
    expect(host.commands()).not.toContain("fill");
  });

  test("never asks for a password the daemon matched to another site", async () => {
    host.candidates = [FOREIGN];
    expect(await bg.handleContent({ type: "fill", id: "EV" }, TOP)).toEqual({
      ok: false,
      error: "not-allowed",
    });
    expect(host.commands()).not.toContain("fill");
  });

  test("never fills into a third-party subframe", async () => {
    const reply = await bg.handleContent(
      { type: "fill", id: "NW" },
      { tabId: 1, frameId: 4, url: "https://ads.example.org/" },
    );
    expect(reply).toEqual({ ok: false, error: "not-allowed" });
    expect(host.requests).toEqual([]);
  });

  test.each(["about:blank", "file:///home/alex/login.html", "data:text/html,x"])(
    "never fills into %s",
    async (url) => {
      expect(await bg.handleContent({ type: "fill", id: "NW" }, { ...TOP, url })).toEqual({
        ok: false,
        error: "not-allowed",
      });
    },
  );

  test("codes go through the same checks and carry the origin", async () => {
    expect(await bg.handleContent({ type: "code", id: "NW" }, TOP)).toEqual({
      ok: true,
      origin: "https://northwind.example.com",
      code: "492039",
      secondsLeft: 17,
    });
    expect(await bg.handleContent({ type: "code", id: "EV" }, TOP)).toEqual({
      ok: false,
      error: "not-allowed",
    });
  });
});

describe("saving", () => {
  const captured = {
    type: "captured" as const,
    kind: "login" as const,
    username: "new@example.com",
    password: "correct-horse-battery",
    filledId: null,
  };

  /** Captures `message` and returns the prompt's capture id. */
  async function capture(
    message: Extract<ContentRequest, { type: "captured" }> = captured,
    sender: Sender = TOP,
  ): Promise<string> {
    const reply = (await bg.handleContent(message, sender)) as {
      prompt?: { captureId: string } | null;
    };
    if (reply.prompt == null) throw new Error("no prompt");
    return reply.prompt.captureId;
  }

  function answer(value: PromptAnswer, captureId: string, sender: Sender = TOP) {
    return bg.handleContent({ type: "prompt-answer", answer: value, captureId }, sender);
  }

  test("a new login is probed with dry_run and becomes a save prompt", async () => {
    const reply = await bg.handleContent(captured, TOP);
    expect(reply).toEqual({
      ok: true,
      prompt: {
        captureId: expect.any(String) as string,
        action: "create",
        host: "northwind.example.com",
        site: "example.com",
        username: "new@example.com",
      },
    });
    expect(host.requests).toEqual([
      {
        cmd: "save",
        url: TOP.url,
        username: "new@example.com",
        password: "correct-horse-battery",
        dry_run: true,
      },
    ]);
    expect(browser.session.data.has("pending:1")).toBe(true);
  });

  test("the prompt never carries the password", async () => {
    const reply = await bg.handleContent(captured, TOP);
    expect(JSON.stringify(reply)).not.toContain("correct-horse-battery");
  });

  test("nothing changed means no prompt and no pending save", async () => {
    host.saveAction = "none";
    expect(await bg.handleContent(captured, TOP)).toEqual({ ok: true, prompt: null });
    expect(browser.session.data.size).toBe(0);
  });

  test("a change-password form without a username updates the item it was filled from", async () => {
    host.saveAction = "update";
    const reply = await bg.handleContent(
      { ...captured, kind: "change-password", username: "", filledId: "NW" },
      TOP,
    );
    expect(reply).toEqual({
      ok: true,
      prompt: {
        captureId: expect.any(String) as string,
        action: "update",
        host: "northwind.example.com",
        site: "example.com",
        username: "alex@example.com",
      },
    });
    expect(host.requests.at(-1)).toMatchObject({
      cmd: "save",
      item_id: "NW",
      username: "alex@example.com",
      dry_run: true,
    });
  });

  test("a different username than the filled item is treated as its own login", async () => {
    await bg.handleContent({ ...captured, filledId: "NW" }, TOP);
    expect(host.requests.at(-1)).not.toHaveProperty("item_id");
  });

  test("Save writes exactly the captured login once", async () => {
    const id = await capture();
    expect(await answer("save", id)).toEqual({ ok: true, saved: true });
    expect(host.requests.at(-1)).toEqual({
      cmd: "save",
      url: TOP.url,
      username: "new@example.com",
      password: captured.password,
    });
    expect(await answer("save", id)).toEqual({ ok: true, saved: false });
  });

  test("an answer from the prompt of a replaced capture saves nothing", async () => {
    // The top frame shows Alice's prompt; a same-site frame then captures Bob's login.
    const alice = await capture({ ...captured, username: "alice@example.com" });
    const frame = { ...TOP, frameId: 3, url: "https://login.northwind.example.com/" };
    const bob = await capture({ ...captured, username: "bob@example.com" }, frame);
    expect(await answer("save", alice)).toEqual({ ok: true, saved: false });
    expect(host.requests.filter((r) => r.cmd === "save" && !("dry_run" in r))).toEqual([]);
    expect(await answer("save", bob, frame)).toEqual({ ok: true, saved: true });
    expect(host.requests.at(-1)).toMatchObject({ username: "bob@example.com" });
  });

  test("the same-site frame that showed the prompt can answer it", async () => {
    const frame = { ...TOP, frameId: 3, url: "https://login.northwind.example.com/" };
    const id = await capture(captured, frame);
    expect(await answer("save", id, frame)).toEqual({ ok: true, saved: true });
    expect(host.requests.at(-1)).toEqual({
      cmd: "save",
      url: frame.url,
      username: "new@example.com",
      password: captured.password,
    });
  });

  test("an older capture that finishes last does not replace the newer prompt", async () => {
    const gate = Promise.withResolvers<undefined>();
    host.matchGate = gate.promise;
    // Alice's capture needs a match (filled item) and stalls; Bob's newer one completes first.
    const alice = bg.handleContent(
      { ...captured, username: "alex@example.com", filledId: "NW" },
      TOP,
    );
    const bob = await capture({ ...captured, username: "bob@example.com" });
    gate.resolve(undefined);
    expect(await alice).toEqual({ ok: true, prompt: null });
    expect(await answer("save", bob)).toEqual({ ok: true, saved: true });
    expect(host.requests.at(-1)).toMatchObject({ username: "bob@example.com" });
  });

  test("another frame cannot answer a frame's prompt", async () => {
    const frame = { ...TOP, frameId: 3, url: "https://login.northwind.example.com/" };
    const id = await capture(captured, frame);
    const other = { ...frame, frameId: 4 };
    expect(await answer("save", id, other)).toEqual({ ok: true, saved: false });
  });

  test("Update targets the probed item", async () => {
    host.saveAction = "update";
    const id = await capture({ ...captured, username: "alex@example.com", filledId: "NW" });
    await answer("save", id);
    expect(host.requests.at(-1)).toMatchObject({ cmd: "save", item_id: "NW" });
    expect(host.requests.at(-1)).not.toHaveProperty("dry_run");
  });

  test("Not Now forgets the capture without writing", async () => {
    const id = await capture();
    expect(await answer("not-now", id)).toEqual({ ok: true, saved: false });
    expect(host.requests.filter((r) => r.cmd === "save")).toHaveLength(1);
    expect(browser.session.data.size).toBe(0);
  });

  test("Never remembers the origin and suppresses later prompts there", async () => {
    await answer("never", await capture());
    expect(browser.local.data.get("never-save")).toEqual(["https://northwind.example.com"]);
    host.requests.length = 0;
    expect(await bg.handleContent(captured, TOP)).toEqual({ ok: true, prompt: null });
    expect(host.requests).toEqual([]);
  });

  test("Never answered in two tabs at once keeps both origins", async () => {
    const other: Sender = { tabId: 2, frameId: 0, url: "https://fabrikam.example.org/login" };
    const first = await capture();
    const second = await capture(captured, other);
    await Promise.all([answer("never", first), answer("never", second, other)]);
    expect(browser.local.data.get("never-save")).toEqual([
      "https://northwind.example.com",
      "https://fabrikam.example.org",
    ]);
  });

  test("the prompt survives the redirect after login within the same site", async () => {
    await bg.handleContent(captured, TOP);
    const next = { ...TOP, url: "https://www.northwind.example.com/inbox" };
    expect(await bg.handleContent({ type: "pending-prompt" }, next)).toEqual({
      ok: true,
      prompt: {
        captureId: expect.any(String) as string,
        action: "create",
        host: "northwind.example.com",
        site: "example.com",
        username: "new@example.com",
      },
    });
  });

  test("the next page asking while the capture is still being checked gets the prompt", async () => {
    // The form page unloads right after submit; the landing page's content script can ask
    // before the host has answered the dry-run save.
    const capture = bg.handleContent(captured, TOP);
    const next = { ...TOP, url: "https://www.northwind.example.com/inbox" };
    const asked = bg.handleContent({ type: "pending-prompt" }, next);
    expect(await asked).toMatchObject({ ok: true, prompt: { action: "create" } });
    await capture;
  });

  test("the prompt is not shown on another site or in a subframe", async () => {
    const id = await capture();
    expect(
      await bg.handleContent(
        { type: "pending-prompt" },
        { ...TOP, url: "https://evil.example.org/" },
      ),
    ).toEqual({ ok: true, prompt: null });
    expect(await bg.handleContent({ type: "pending-prompt" }, { ...TOP, frameId: 2 })).toEqual({
      ok: true,
      prompt: null,
    });
    expect(await answer("save", id, { ...TOP, url: "https://evil.example.org/" })).toEqual({
      ok: true,
      saved: false,
    });
  });

  test("a stale capture expires", async () => {
    await bg.handleContent(captured, TOP);
    browser.clock += PENDING_TTL_MS + 1;
    expect(await bg.handleContent({ type: "pending-prompt" }, TOP)).toEqual({
      ok: true,
      prompt: null,
    });
    expect(browser.session.data.size).toBe(0);
  });

  test("captures in other tabs do not mix", async () => {
    await bg.handleContent(captured, TOP);
    browser.tops.set(2, TOP.url);
    expect(await bg.handleContent({ type: "pending-prompt" }, { ...TOP, tabId: 2 })).toEqual({
      ok: true,
      prompt: null,
    });
  });

  test("garbage in session storage is ignored", async () => {
    await browser.session.set("pending:1", { url: TOP.url, password: 5 });
    expect(await bg.handleContent({ type: "pending-prompt" }, TOP)).toEqual({
      ok: true,
      prompt: null,
    });
  });

  test("captures from a third-party frame are refused", async () => {
    expect(
      await bg.handleContent(captured, { tabId: 1, frameId: 5, url: "https://ads.example.org/" }),
    ).toEqual({
      ok: false,
      error: "not-allowed",
    });
  });
});

describe("popup", () => {
  test("shows the active tab's candidates and the daemon state", async () => {
    expect(await bg.handlePopup({ type: "popup-state" }, null)).toEqual({
      ok: true,
      host: "northwind.example.com",
      state: "idle",
      items: [
        {
          id: "NW",
          title: "Northwind",
          username: "alex@example.com",
          host: "northwind.example.com",
          site: "example.com",
          hasCode: true,
        },
        {
          id: "NT",
          title: "northwind.example.com",
          username: "",
          host: "northwind.example.com",
          site: "example.com",
          hasCode: false,
        },
      ],
      error: null,
    });
  });

  test("a tab that is not a web page shows no host and no items", async () => {
    browser.tops.clear();
    expect(await bg.handlePopup({ type: "popup-state" }, null)).toEqual({
      ok: true,
      host: null,
      state: "idle",
      items: [],
      error: null,
    });
  });

  test("an unreachable host is reported with its code", async () => {
    host.failWith = new ProtocolError("host-unavailable", "not found");
    expect(await bg.handlePopup({ type: "popup-state" }, null)).toEqual({
      ok: true,
      host: "northwind.example.com",
      state: null,
      items: [],
      error: "host-unavailable",
    });
  });

  test("fill sends the secret to the tab's top frame with its origin", async () => {
    expect(await bg.handlePopup({ type: "popup-fill", id: "NW" }, null)).toEqual({
      ok: true,
      filled: true,
    });
    expect(browser.sent).toEqual([
      {
        tabId: 1,
        frameId: 0,
        command: {
          type: "apply-fill",
          origin: "https://northwind.example.com",
          id: "NW",
          username: "alex@example.com",
          password: "hunter2-hunter2",
        },
      },
    ]);
  });

  test("fill reports false when the page had no form to fill", async () => {
    browser.applied = false;
    expect(await bg.handlePopup({ type: "popup-fill", id: "NW" }, null)).toEqual({
      ok: true,
      filled: false,
    });
  });

  test("fill of a non-candidate is refused before any secret is fetched", async () => {
    expect(await bg.handlePopup({ type: "popup-fill", id: "EV" }, null)).toEqual({
      ok: false,
      error: "not-allowed",
    });
    expect(host.commands()).not.toContain("fill");
    expect(browser.sent).toEqual([]);
  });

  test("code fills the page and returns the code for display", async () => {
    expect(await bg.handlePopup({ type: "popup-code", id: "NW" }, null)).toEqual({
      ok: true,
      code: "492039",
      secondsLeft: 17,
    });
    expect(browser.sent[0]?.command).toEqual({
      type: "apply-code",
      origin: "https://northwind.example.com",
      code: "492039",
    });
  });

  test("with no target tab, fill is refused", async () => {
    browser.activeId = null;
    expect(await bg.handlePopup({ type: "popup-fill", id: "NW" }, null)).toEqual({
      ok: false,
      error: "not-allowed",
    });
  });
});
