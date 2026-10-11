// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Dropdown, type DropdownEntry } from "../src/content/dropdown";
import type { CandidateView } from "../src/shared/messages";

// What the generator would offer; fictional, shaped like its output.
const PREVIEW = "abcdef-ghijkm-n0pQrs";

const ALEX: CandidateView = {
  id: "A",
  title: "Northwind",
  username: "alex@example.com",
  host: "northwind.example",
  site: "northwind.example",
  hasCode: true,
};
const SAM: CandidateView = {
  id: "S",
  title: "Northwind (work)",
  username: "",
  host: "northwind.example",
  site: "northwind.example",
  hasCode: false,
};

let input: HTMLInputElement;
let picks: DropdownEntry[];
let closes: number;
let dropdown: Dropdown | null;
const trusted = (): boolean => true;

function open(entries: DropdownEntry[], isTrusted: (e: Event) => boolean = trusted): Dropdown {
  dropdown = new Dropdown(input, entries, {
    onPick: (entry) => picks.push(entry),
    onClose: () => {
      closes += 1;
    },
    isTrusted,
  });
  return dropdown;
}

function key(name: string): KeyboardEvent {
  const event = new KeyboardEvent("keydown", { key: name, bubbles: true, cancelable: true });
  input.dispatchEvent(event);
  return event;
}

beforeEach(() => {
  document.body.replaceChildren();
  input = document.createElement("input");
  input.type = "email";
  document.body.append(input);
  input.focus();
  picks = [];
  closes = 0;
  dropdown = null;
});

afterEach(() => {
  dropdown?.close();
});

describe("rendering", () => {
  test("one row per entry with title and username, the first highlighted", () => {
    const d = open([
      { kind: "login", candidate: ALEX },
      { kind: "login", candidate: SAM },
    ]);
    const rows = d.rows();
    expect(rows.map((r) => r.querySelector(".title")?.textContent)).toEqual([
      "Northwind",
      "Northwind (work)",
    ]);
    expect(rows.map((r) => r.querySelector(".subtitle")?.textContent)).toEqual([
      "alex@example.com",
      "No username",
    ]);
    expect(rows.map((r) => r.getAttribute("aria-selected"))).toEqual(["true", "false"]);
    expect(rows[0]?.querySelector(".monogram")?.textContent).toBe("N");
  });

  test("the menu lives in a closed shadow root the page cannot open", () => {
    const d = open([{ kind: "login", candidate: ALEX }]);
    expect(d.overlay.host.shadowRoot).toBeNull();
    expect(d.overlay.host.parentElement).toBe(document.documentElement);
    expect(document.body.textContent).not.toContain("alex@example.com");
  });

  test("page-controlled text is rendered as text, never as markup", () => {
    const evil = { ...ALEX, title: '<img src=x onerror="alert(1)">', username: "<b>x</b>" };
    const d = open([{ kind: "login", candidate: evil }]);
    expect(d.overlay.root.querySelector("img")).toBeNull();
    expect(d.overlay.root.querySelector("b")).toBeNull();
    expect(d.rows()[0]?.querySelector(".title")?.textContent).toBe(evil.title);
  });

  test("a code entry names the item it comes from", () => {
    const d = open([{ kind: "code", candidate: ALEX }]);
    expect(d.rows()[0]?.querySelector(".title")?.textContent).toBe("Verification Code");
    expect(d.rows()[0]?.querySelector(".subtitle")?.textContent).toBe("From Northwind");
  });

  test("a generator entry previews the password", () => {
    const d = open([{ kind: "generate", password: PREVIEW }]);
    expect(d.rows()[0]?.querySelector(".title")?.textContent).toBe("Use Strong Password");
    expect(d.rows()[0]?.querySelector(".subtitle")?.textContent).toBe(PREVIEW);
  });

  test("the listbox has an accessible name and options", () => {
    const d = open([{ kind: "login", candidate: ALEX }]);
    const listbox = d.overlay.root.querySelector('[role="listbox"]');
    expect(listbox?.getAttribute("aria-label")).toBe("Saved passwords");
    expect(d.rows()[0]?.getAttribute("role")).toBe("option");
  });
});

describe("keyboard", () => {
  test("arrows move the highlight and wrap around", () => {
    const d = open([
      { kind: "login", candidate: ALEX },
      { kind: "login", candidate: SAM },
    ]);
    key("ArrowDown");
    expect(d.activeIndex).toBe(1);
    key("ArrowDown");
    expect(d.activeIndex).toBe(0);
    key("ArrowUp");
    expect(d.activeIndex).toBe(1);
    key("Home");
    expect(d.activeIndex).toBe(0);
    key("End");
    expect(d.activeIndex).toBe(1);
  });

  test("Enter picks the highlighted entry, closes the menu and is not passed to the page", () => {
    const d = open([
      { kind: "login", candidate: ALEX },
      { kind: "login", candidate: SAM },
    ]);
    let pageSaw = false;
    input.addEventListener("keydown", () => {
      pageSaw = true;
    });
    key("ArrowDown");
    const event = key("Enter");
    expect(picks).toEqual([{ kind: "login", candidate: SAM }]);
    expect(event.defaultPrevented).toBe(true);
    expect(pageSaw).toBe(false);
    expect(d.isOpen).toBe(false);
    expect(closes).toBe(1);
  });

  test("an untrusted Enter (page script) picks nothing", () => {
    open([{ kind: "login", candidate: ALEX }], () => false);
    key("Enter");
    expect(picks).toEqual([]);
  });

  test("Escape closes without picking", () => {
    const d = open([{ kind: "login", candidate: ALEX }]);
    key("Escape");
    expect(d.isOpen).toBe(false);
    expect(picks).toEqual([]);
  });

  test("a field inside a shadow root drives and dismisses the menu", () => {
    const host = document.createElement("div");
    document.body.append(host);
    input = document.createElement("input");
    host.attachShadow({ mode: "open" }).append(input);
    const d = open([
      { kind: "login", candidate: ALEX },
      { kind: "login", candidate: SAM },
    ]);
    const press = (name: string): void => {
      input.dispatchEvent(
        new KeyboardEvent("keydown", { key: name, bubbles: true, composed: true }),
      );
    };
    press("ArrowDown");
    press("Enter");
    expect(picks).toEqual([{ kind: "login", candidate: SAM }]);
    const again = open([{ kind: "login", candidate: ALEX }]);
    input.dispatchEvent(new FocusEvent("focusout", { bubbles: true, composed: true }));
    expect(again.isOpen).toBe(false);
    expect(d.isOpen).toBe(false);
  });

  test("Enter in the anchor belongs to the open menu, not to the page's form", () => {
    const d = open([{ kind: "login", candidate: ALEX }]);
    expect(d.consumesEnter(input)).toBe(true);
    expect(d.consumesEnter(document.body)).toBe(false);
    d.close();
    expect(d.consumesEnter(input)).toBe(false);
  });

  test("Tab closes and lets focus move on", () => {
    const d = open([{ kind: "login", candidate: ALEX }]);
    const event = key("Tab");
    expect(d.isOpen).toBe(false);
    expect(event.defaultPrevented).toBe(false);
  });

  test("other keys reach the page untouched", () => {
    const d = open([{ kind: "login", candidate: ALEX }]);
    const event = key("a");
    expect(event.defaultPrevented).toBe(false);
    expect(d.isOpen).toBe(true);
  });

  test("keys typed in another field are ignored", () => {
    const d = open([
      { kind: "login", candidate: ALEX },
      { kind: "login", candidate: SAM },
    ]);
    const other = document.createElement("input");
    document.body.append(other);
    other.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    expect(d.activeIndex).toBe(0);
  });
});

describe("mouse", () => {
  test("a trusted click picks that row", () => {
    const d = open([
      { kind: "login", candidate: ALEX },
      { kind: "login", candidate: SAM },
    ]);
    d.rows()[1]?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(picks).toEqual([{ kind: "login", candidate: SAM }]);
  });

  test("a synthetic click from the page picks nothing", () => {
    const d = open([{ kind: "login", candidate: ALEX }], (e) => e.isTrusted);
    d.rows()[0]?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(picks).toEqual([]);
    expect(d.isOpen).toBe(true);
  });

  test("mousedown on a row keeps focus in the field", () => {
    const d = open([{ kind: "login", candidate: ALEX }]);
    const event = new MouseEvent("mousedown", { bubbles: true, cancelable: true });
    d.rows()[0]?.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(true);
  });

  test("hover moves the highlight", () => {
    const d = open([
      { kind: "login", candidate: ALEX },
      { kind: "login", candidate: SAM },
    ]);
    d.rows()[1]?.dispatchEvent(new MouseEvent("mousemove", { bubbles: true }));
    expect(d.activeIndex).toBe(1);
  });

  test("pressing elsewhere on the page closes the menu", () => {
    const d = open([{ kind: "login", candidate: ALEX }]);
    document.body.dispatchEvent(new Event("pointerdown", { bubbles: true, composed: true }));
    expect(d.isOpen).toBe(false);
  });

  test("leaving the field closes the menu and removes it from the page", () => {
    const d = open([{ kind: "login", candidate: ALEX }]);
    input.dispatchEvent(new FocusEvent("focusout", { bubbles: true }));
    expect(d.isOpen).toBe(false);
    expect(document.querySelector("[data-passwords-app]")).toBeNull();
  });

  test("close is idempotent and stops listening", () => {
    const d = open([{ kind: "login", candidate: ALEX }]);
    d.close();
    d.close();
    expect(closes).toBe(1);
    const event = key("Enter");
    expect(event.defaultPrevented).toBe(false);
    expect(picks).toEqual([]);
  });
});

describe("anchoring", () => {
  test("the generator row draws its key glyph as SVG, not an emoji or markup", () => {
    const d = open([{ kind: "generate", password: PREVIEW }]);
    const key = d.rows()[0]?.querySelector(".key");
    expect(key?.querySelector("svg circle")).not.toBeNull();
    expect(key?.textContent).toBe("");
  });

  test("an explicit anchor box (split code row) decides width and position", () => {
    const d = new Dropdown(input, [{ kind: "code", candidate: ALEX }], {
      onPick: () => undefined,
      isTrusted: trusted,
      anchorRect: () => new DOMRect(40, 100, 330, 50),
    });
    dropdown = d;
    expect(d.overlay.host.style.width).toBe("330px");
    expect(d.overlay.host.style.left).toBe("40px");
    expect(d.overlay.host.style.top).toBe("154px");
  });

  test("narrow fields still get a readable menu", () => {
    const d = new Dropdown(input, [{ kind: "login", candidate: ALEX }], {
      onPick: () => undefined,
      isTrusted: trusted,
      anchorRect: () => new DOMRect(10, 10, 40, 40),
    });
    dropdown = d;
    expect(d.overlay.host.style.width).toBe("280px");
  });

  test("typing into the field by hand closes the menu", () => {
    const d = open([{ kind: "login", candidate: ALEX }]);
    input.dispatchEvent(new InputEvent("input", { bubbles: true }));
    expect(d.isOpen).toBe(false);
  });

  test("the tile colour and letter come from the site", () => {
    const d = open([
      { kind: "login", candidate: { ...ALEX, title: "", site: "fabrikam.example" } },
    ]);
    expect(d.rows()[0]?.querySelector(".monogram")?.textContent).toBe("F");
  });
});
