// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
import { beforeEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { CandidateView, PopupState } from "../src/shared/messages";
import { filterItems, renderPopup, statusLine } from "../src/popup/view";

const ITEMS: CandidateView[] = [
  {
    id: "1",
    title: "Northwind Mail",
    username: "alex@example.com",
    host: "mail.northwind.example",
    site: "northwind.example",
    hasCode: true,
  },
  {
    id: "2",
    title: "Northwind Admin",
    username: "root",
    host: "admin.northwind.example",
    site: "northwind.example",
    hasCode: false,
  },
  {
    id: "3",
    title: "Café Crème",
    username: "",
    host: "cafe.example",
    site: "cafe.example",
    hasCode: false,
  },
];

const HTML = readFileSync(join(import.meta.dir, "..", "static", "popup.html"), "utf8");

function loadSkeleton(): void {
  const parsed = new DOMParser().parseFromString(HTML, "text/html");
  // The skeleton without its <script>: the test drives the view module directly.
  const nodes = [...parsed.body.children].filter((n) => n.tagName !== "SCRIPT");
  document.body.replaceChildren(...nodes.map((n) => document.importNode(n, true)));
}

function state(overrides: Partial<PopupState> = {}): PopupState {
  return { host: "northwind.example", state: "idle", items: ITEMS, error: null, ...overrides };
}

function shownIds(): string[] {
  return [...document.querySelectorAll<HTMLElement>("#list li")].map(
    (li) => li.dataset["id"] ?? "",
  );
}

const search = (): HTMLInputElement => document.getElementById("search") as HTMLInputElement;

let fills: string[];
let codes: string[];
const handlers = {
  onFill: (id: string) => fills.push(id),
  onCode: (id: string) => codes.push(id),
};

beforeEach(() => {
  loadSkeleton();
  fills = [];
  codes = [];
});

describe("filterItems", () => {
  test.each([
    ["", ["1", "2", "3"]],
    ["mail", ["1"]],
    ["NORTHWIND", ["1", "2"]],
    ["root", ["2"]],
    ["northwind admin", ["2"]],
    ["admin northwind", ["2"]],
    ["cafe creme", ["3"]],
    ["  ", ["1", "2", "3"]],
    ["zzz", []],
    ["alex@", ["1"]],
  ] as const)("%j → %j", (query, expected) => {
    expect(filterItems(ITEMS, query).map((i) => i.id)).toEqual([...expected]);
  });
});

describe("statusLine", () => {
  test.each([
    [null, "host-unavailable", "error"],
    [null, "daemon-unavailable", "error"],
    [null, "timeout", "error"],
    [null, "locked", "warn"],
    [null, "auth-required", "warn"],
    [null, "internal", "error"],
    ["idle", null, "ok"],
    ["syncing", null, "busy"],
    ["paused", null, "warn"],
    ["offline", null, "warn"],
    ["signed-out", null, "warn"],
    ["signin-required", null, "warn"],
    ["error", null, "error"],
    // Status answered but matching failed: never a healthy-looking line.
    ["idle", "internal", "error"],
  ] as const)("state %s, error %s → %s", (s, error, tone) => {
    const line = statusLine(s, error);
    expect(line.tone).toBe(tone);
    expect(line.text.length).toBeGreaterThan(0);
  });
});

describe("renderPopup", () => {
  test("lists the site's logins with titles, usernames and code buttons", () => {
    renderPopup(document, state(), handlers);
    expect(shownIds()).toEqual(["1", "2", "3"]);
    expect(document.getElementById("site")?.textContent).toBe("northwind.example");
    expect(document.querySelectorAll(".code")).toHaveLength(1);
    expect(document.querySelector('li[data-id="3"] .username')?.textContent).toBe("No username");
    expect(document.getElementById("empty")?.hidden).toBe(true);
    expect(document.getElementById("status")?.dataset["tone"]).toBe("ok");
  });

  test("typing filters the list and Enter fills the first result", () => {
    renderPopup(document, state(), handlers);
    search().value = "admin";
    search().dispatchEvent(new Event("input"));
    expect(shownIds()).toEqual(["2"]);
    search().dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    expect(fills).toEqual(["2"]);
  });

  test("the clear button shows only with a query, clears it and refocuses search", () => {
    renderPopup(document, state(), handlers);
    const clear = document.getElementById("clear") as HTMLButtonElement;
    expect(clear.hidden).toBe(true);
    expect(clear.getAttribute("aria-label")).toBe("Clear search");
    search().value = "admin";
    search().dispatchEvent(new Event("input"));
    expect(clear.hidden).toBe(false);
    clear.click();
    expect(search().value).toBe("");
    expect(shownIds()).toEqual(["1", "2", "3"]);
    expect(clear.hidden).toBe(true);
    expect(document.activeElement).toBe(search());
  });

  test("Escape clears a query", () => {
    renderPopup(document, state(), handlers);
    search().value = "admin";
    search().dispatchEvent(new Event("input"));
    search().dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", cancelable: true }));
    expect(search().value).toBe("");
    expect(shownIds()).toEqual(["1", "2", "3"]);
  });

  test("no results shows an explanation instead of an empty box", () => {
    renderPopup(document, state(), handlers);
    search().value = "nothing like this";
    search().dispatchEvent(new Event("input"));
    expect(document.getElementById("list")?.hidden).toBe(true);
    expect(document.getElementById("empty")?.textContent).toBe("No results");
    search().dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    expect(fills).toEqual([]);
  });

  test("clicking a row fills it; the code button asks for the code", () => {
    renderPopup(document, state(), handlers);
    document.querySelector<HTMLElement>('li[data-id="2"] .fill')?.click();
    document.querySelector<HTMLElement>('li[data-id="1"] .code')?.click();
    expect(fills).toEqual(["2"]);
    expect(codes).toEqual(["1"]);
  });

  test("rows have accessible names with title and username", () => {
    renderPopup(document, state(), handlers);
    expect(document.querySelector('li[data-id="1"] .fill')?.getAttribute("aria-label")).toBe(
      "Fill: Northwind Mail — alex@example.com",
    );
  });

  test("a site without logins says so and disables search", () => {
    renderPopup(document, state({ items: [] }), handlers);
    expect(document.getElementById("empty")?.textContent).toBe(
      "No saved passwords for this website",
    );
    expect(search().disabled).toBe(true);
  });

  test("a non-web tab asks to open a website", () => {
    renderPopup(document, state({ host: null, items: [] }), handlers);
    expect(document.getElementById("empty")?.textContent).toBe(
      "Open a website to see its passwords",
    );
  });

  test("a missing native host is explained in the status line", () => {
    renderPopup(document, state({ state: null, items: [], error: "host-unavailable" }), handlers);
    expect(document.getElementById("status")?.textContent).toBe(
      "The Passwords app is not installed for this browser",
    );
    expect(document.getElementById("status")?.dataset["tone"]).toBe("error");
  });

  test("item text is rendered as text, never markup", () => {
    const evil = { ...ITEMS[0], id: "x", title: "<img src=x onerror=alert(1)>" } as CandidateView;
    renderPopup(document, state({ items: [evil] }), handlers);
    expect(document.querySelector("#list img")).toBeNull();
  });
});

describe("popup.html", () => {
  test("loads only its own script and stylesheet", () => {
    const parsed = new DOMParser().parseFromString(HTML, "text/html");
    expect([...parsed.querySelectorAll("script")].map((s) => s.getAttribute("src"))).toEqual([
      "popup.js",
    ]);
    expect(parsed.querySelectorAll("script:not([src])")).toHaveLength(0);
    expect(HTML).not.toMatch(/\son[a-z]+=/i);
  });
});
