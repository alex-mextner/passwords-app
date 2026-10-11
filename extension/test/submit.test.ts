// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Save-prompt heuristics: what a submitted form yields, when saving is worth offering, and how
// submissions are noticed. happy-dom marks every event untrusted, so the observer tests inject
// `isTrusted: () => true` and one test checks that the default really ignores untrusted events.

import { afterEach, beforeAll, describe, expect, test } from "bun:test";

import { detectForms, isStyleVisible } from "../src/content/detect";
import { captureFromForm, observeSubmissions, shouldOffer } from "../src/content/submit";
import type { CapturedLogin, LastFill, LoginForm } from "../src/content/types";
import { loadBody } from "./fixtures/load";

beforeAll(() => {
  // Tests never navigate: a real form submission would make happy-dom load the action URL.
  document.addEventListener("submit", (event) => {
    event.preventDefault();
  });
});

function input(id: string): HTMLInputElement {
  const found = document.getElementById(id);
  if (!(found instanceof HTMLInputElement)) throw new Error(`no input#${id}`);
  return found;
}

function fields(values: Record<string, string>): void {
  loadBody(
    Object.keys(values)
      .map((id) => `<input id="${id}">`)
      .join(""),
  );
  for (const [id, value] of Object.entries(values)) input(id).value = value;
}

function form(parts: {
  kind: LoginForm["kind"];
  username?: string;
  password?: string;
  newPasswords?: readonly string[];
}): LoginForm {
  return {
    form: null,
    kind: parts.kind,
    username: parts.username === undefined ? null : input(parts.username),
    password: parts.password === undefined ? null : input(parts.password),
    newPasswords: (parts.newPasswords ?? []).map(input),
    otp: null,
  };
}

const longPassword = "a".repeat(4096);

describe("captureFromForm", () => {
  test.each([
    [
      "a login",
      { u: "alex@example.com", p: "example-pass-1" },
      { kind: "login", username: "u", password: "p" },
      { kind: "login", username: "alex@example.com", password: "example-pass-1" },
    ],
    [
      "the username is trimmed",
      { u: "  alex@example.com ", p: "example-pass-1" },
      { kind: "login", username: "u", password: "p" },
      { kind: "login", username: "alex@example.com", password: "example-pass-1" },
    ],
    [
      "the password is not trimmed",
      { u: "alex", p: " spaced pass " },
      { kind: "login", username: "u", password: "p" },
      { kind: "login", username: "alex", password: " spaced pass " },
    ],
    [
      "a login without a username field",
      { p: "example-pass-1" },
      { kind: "login", password: "p" },
      { kind: "login", username: "", password: "example-pass-1" },
    ],
    [
      "nine digits are a password, not a code",
      { u: "alex", p: "123456789" },
      { kind: "login", username: "u", password: "p" },
      { kind: "login", username: "alex", password: "123456789" },
    ],
    [
      "digits with letters",
      { u: "alex", p: "1234abcd" },
      { kind: "login", username: "u", password: "p" },
      { kind: "login", username: "alex", password: "1234abcd" },
    ],
    [
      "exactly 4096 characters",
      { u: "alex", p: longPassword },
      { kind: "login", username: "u", password: "p" },
      { kind: "login", username: "alex", password: longPassword },
    ],
    [
      "a signup with a matching confirmation",
      { e: "new@example.com", n: "abcdef-ghijkm-npqrs7", c: "abcdef-ghijkm-npqrs7" },
      { kind: "signup", username: "e", newPasswords: ["n", "c"] },
      { kind: "signup", username: "new@example.com", password: "abcdef-ghijkm-npqrs7" },
    ],
    [
      "a signup whose confirmation is still empty",
      { e: "new@example.com", n: "abcdef-ghijkm-npqrs7", c: "" },
      { kind: "signup", username: "e", newPasswords: ["n", "c"] },
      { kind: "signup", username: "new@example.com", password: "abcdef-ghijkm-npqrs7" },
    ],
    [
      "a change keeps the new password, not the current one",
      { cur: "old-pass-1", n: "new-pass-2", c: "new-pass-2" },
      { kind: "change-password", password: "cur", newPasswords: ["n", "c"] },
      { kind: "change-password", username: "", password: "new-pass-2" },
    ],
    [
      "a reset without a current password",
      { n: "new-pass-2", c: "new-pass-2" },
      { kind: "change-password", newPasswords: ["n", "c"] },
      { kind: "change-password", username: "", password: "new-pass-2" },
    ],
  ] as const)("%s", (_name, values, shape, expected) => {
    fields(values);
    expect(captureFromForm(form(shape))).toEqual(expected);
  });

  test.each([
    ["an empty password", { u: "alex", p: "" }, { kind: "login", username: "u", password: "p" }],
    ["a blank password", { u: "alex", p: "   " }, { kind: "login", username: "u", password: "p" }],
    [
      "password equal to the username",
      { u: "alex", p: "alex" },
      { kind: "login", username: "u", password: "p" },
    ],
    [
      "a six-digit code",
      { u: "alex", p: "123456" },
      { kind: "login", username: "u", password: "p" },
    ],
    [
      "an eight-digit code",
      { u: "alex", p: "12345678" },
      { kind: "login", username: "u", password: "p" },
    ],
    ["a four-digit PIN", { u: "alex", p: "0000" }, { kind: "login", username: "u", password: "p" }],
    [
      "4097 characters",
      { u: "alex", p: `${longPassword}b` },
      { kind: "login", username: "u", password: "p" },
    ],
    [
      "an absurd username",
      { u: "u".repeat(4097), p: "example-pass-1" },
      { kind: "login", username: "u", password: "p" },
    ],
    ["a login form without a password field", { u: "alex" }, { kind: "login", username: "u" }],
    ["a username-only step", { u: "alex" }, { kind: "username-only", username: "u" }],
    ["a one-time code form", { c: "123456" }, { kind: "otp" }],
    [
      "a mistyped confirmation",
      { e: "new@example.com", n: "abcdef-1", c: "abcdef-2" },
      { kind: "signup", username: "e", newPasswords: ["n", "c"] },
    ],
    [
      "a mistyped new password on a change",
      { cur: "old-pass", n: "new-pass-1", c: "new-pass-2" },
      { kind: "change-password", password: "cur", newPasswords: ["n", "c"] },
    ],
    [
      "a signup without password fields",
      { e: "new@example.com" },
      { kind: "signup", username: "e" },
    ],
  ] as const)("nothing from %s", (_name, values, shape) => {
    fields(values);
    expect(captureFromForm(form(shape))).toBeNull();
  });
});

describe("shouldOffer", () => {
  const filled: LastFill = {
    id: "item-1",
    username: "alex@example.com",
    password: "example-pass-1",
  };
  const captured = (username: string, password: string): CapturedLogin => ({
    kind: "login",
    username,
    password,
  });

  test.each([
    ["nothing was filled", captured("alex@example.com", "example-pass-1"), null, true],
    ["exactly what was filled", captured("alex@example.com", "example-pass-1"), filled, false],
    ["a changed password", captured("alex@example.com", "example-pass-2"), filled, true],
    ["another account, same password", captured("sam@example.com", "example-pass-1"), filled, true],
    ["no username shown, same password", captured("", "example-pass-1"), filled, false],
    ["no username shown, new password", captured("", "example-pass-2"), filled, true],
    [
      "username differing in case is another username",
      captured("Alex@example.com", "example-pass-1"),
      filled,
      true,
    ],
  ] as const)("%s → %p", (_name, capture, last, offer) => {
    expect(shouldOffer(capture, last)).toBe(offer);
  });

  test("a change-password capture equal to the filled password is not offered", () => {
    expect(
      shouldOffer({ kind: "change-password", username: "", password: "example-pass-1" }, filled),
    ).toBe(false);
  });
});

// --- observeSubmissions -------------------------------------------------------------------------

const getForms = (): LoginForm[] => detectForms(document, { isVisible: isStyleVisible });

let dispose: (() => void) | null = null;
afterEach(() => {
  dispose?.();
  dispose = null;
});

function observe(clock?: { now: number }): CapturedLogin[] {
  const captured: CapturedLogin[] = [];
  dispose = observeSubmissions(document, getForms, (c) => captured.push(c), {
    isTrusted: () => true,
    ...(clock === undefined ? {} : { now: () => clock.now }),
  });
  return captured;
}

const LOGIN_PAGE = `<form id="f" action="/login"><input id="u" name="username"><input id="p" type="password"><button id="b" type="submit"><span id="label">Sign in</span></button><button id="show" type="button">Show</button></form>`;

function type(id: string, value: string): void {
  input(id).value = value;
  input(id).dispatchEvent(new InputEvent("input", { bubbles: true, composed: true }));
}

function submit(id = "f"): void {
  const target = document.getElementById(id);
  if (target === null) throw new Error(`no #${id}`);
  target.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
}

function click(id: string): void {
  const target = document.getElementById(id);
  if (target === null) throw new Error(`no #${id}`);
  target.dispatchEvent(
    new MouseEvent("click", { bubbles: true, composed: true, cancelable: true }),
  );
}

function enter(id: string, init: KeyboardEventInit = {}): void {
  input(id).dispatchEvent(
    new KeyboardEvent("keydown", { key: "Enter", bubbles: true, composed: true, ...init }),
  );
}

const ALEX: CapturedLogin = {
  kind: "login",
  username: "alex@example.com",
  password: "example-pass-1",
};

describe("observeSubmissions", () => {
  test("a submit event reports the login", () => {
    loadBody(LOGIN_PAGE);
    const captured = observe();
    type("u", "alex@example.com");
    type("p", "example-pass-1");
    submit();
    expect(captured).toEqual([ALEX]);
  });

  test("untrusted events are ignored by default", () => {
    loadBody(LOGIN_PAGE);
    const captured: CapturedLogin[] = [];
    dispose = observeSubmissions(document, getForms, (c) => captured.push(c));
    input("u").value = "alex@example.com";
    input("p").value = "example-pass-1";
    submit();
    click("b");
    enter("p");
    expect(captured).toEqual([]);
  });

  test("the trust check sees every kind of event", () => {
    loadBody(LOGIN_PAGE);
    const asked: string[] = [];
    dispose = observeSubmissions(document, getForms, () => undefined, {
      isTrusted: (event) => {
        asked.push(event.type);
        return false;
      },
    });
    type("u", "x");
    submit();
    click("b");
    enter("p");
    // The click on a submit button also makes happy-dom fire a submit of its own.
    expect(new Set(asked)).toEqual(new Set(["input", "submit", "click", "keydown"]));
  });

  test("a click on the submit button's label reports once even if a submit follows", () => {
    loadBody(LOGIN_PAGE);
    const captured = observe();
    type("u", "alex@example.com");
    type("p", "example-pass-1");
    click("label");
    submit();
    expect(captured).toEqual([ALEX]);
  });

  test("a click on a non-submit button reports nothing", () => {
    loadBody(LOGIN_PAGE);
    const captured = observe();
    type("u", "alex@example.com");
    type("p", "example-pass-1");
    click("show");
    expect(captured).toEqual([]);
  });

  test.each([
    ["role=button saying Sign in", `<div role="button" id="go">Sign in</div>`, 1],
    ["a plain button saying Войти", `<button id="go">Войти</button>`, 1],
    ["a plain button saying Continue", `<button id="go">Continue</button>`, 1],
    ["a plain button saying Далее", `<button id="go">Далее</button>`, 1],
    ["input type=submit outside any form", `<input type="submit" id="go" value="Go">`, 1],
    ["a button saying Cancel", `<button id="go">Cancel</button>`, 0],
    ["a plain div", `<div id="go">Sign in</div>`, 0],
  ])("formless page: click on %s", (_name, control, count) => {
    loadBody(`<div><input id="u" name="username"><input id="p" type="password">${control}</div>`);
    const captured = observe();
    type("u", "alex@example.com");
    type("p", "example-pass-1");
    click("go");
    expect(captured).toHaveLength(count);
  });

  test("a click picks the formless group nearest to the button", () => {
    loadBody(
      `<div><input id="u1" name="username"><input id="p1" type="password"><button id="b1">Sign in</button></div>` +
        `<div><input id="u2" name="username"><input id="p2" type="password"><button id="b2">Sign in</button></div>`,
    );
    const captured = observe();
    type("u1", "first@example.com");
    type("p1", "first-pass-1");
    type("u2", "second@example.com");
    type("p2", "second-pass-2");
    click("b2");
    expect(captured).toEqual([
      { kind: "login", username: "second@example.com", password: "second-pass-2" },
    ]);
  });

  test("Enter in the password field reports the login", () => {
    loadBody(LOGIN_PAGE);
    const captured = observe();
    type("u", "alex@example.com");
    type("p", "example-pass-1");
    enter("p");
    expect(captured).toEqual([ALEX]);
  });

  test("Enter the open dropdown consumes is not a submission", () => {
    loadBody(LOGIN_PAGE);
    const captured: CapturedLogin[] = [];
    dispose = observeSubmissions(document, getForms, (c) => captured.push(c), {
      isTrusted: () => true,
      enterConsumed: (field) => field.id === "p",
    });
    type("u", "alex@example.com");
    type("p", "mistyped-pass-1");
    enter("p");
    expect(captured).toEqual([]);
  });

  test.each([
    ["Enter in the username field", "u", { key: "Enter" }],
    ["another key in the password field", "p", { key: "a" }],
    ["Enter while an IME is composing", "p", { key: "Enter", isComposing: true }],
  ])("%s reports nothing", (_name, id, init) => {
    loadBody(LOGIN_PAGE);
    const captured = observe();
    type("u", "alex@example.com");
    type("p", "example-pass-1");
    enter(id, init);
    expect(captured).toEqual([]);
  });

  test("values typed before the page cleared the fields are still reported", () => {
    loadBody(LOGIN_PAGE);
    const captured = observe();
    type("u", "alex@example.com");
    type("p", "example-pass-1");
    input("u").value = "";
    input("p").value = "";
    submit();
    expect(captured).toEqual([ALEX]);
  });

  test("a page clearing fields in its own submit handler is too late", () => {
    loadBody(LOGIN_PAGE);
    const captured = observe();
    (document.getElementById("f") as HTMLFormElement).addEventListener("submit", () => {
      input("u").value = "";
      input("p").value = "";
    });
    input("u").value = "alex@example.com";
    input("p").value = "example-pass-1";
    submit();
    expect(captured).toEqual([ALEX]);
  });

  test("the current value wins over an older typed one", () => {
    loadBody(LOGIN_PAGE);
    const captured = observe();
    type("u", "alex@example.com");
    type("p", "typo-pass");
    input("p").value = "example-pass-1";
    submit();
    expect(captured).toEqual([ALEX]);
  });

  test("the same values within two seconds are reported once, later again", () => {
    loadBody(LOGIN_PAGE);
    const clock = { now: 1_000 };
    const captured = observe(clock);
    type("u", "alex@example.com");
    type("p", "example-pass-1");
    submit();
    clock.now += 1_999;
    submit();
    clock.now += 2_000;
    submit();
    expect(captured).toHaveLength(2);
  });

  test("different values within two seconds are both reported", () => {
    loadBody(LOGIN_PAGE);
    const clock = { now: 0 };
    const captured = observe(clock);
    type("u", "alex@example.com");
    type("p", "wrong-pass-1");
    submit();
    clock.now += 500;
    type("p", "example-pass-1");
    submit();
    expect(captured.map((c) => c.password)).toEqual(["wrong-pass-1", "example-pass-1"]);
  });

  test("implausible values are not reported", () => {
    loadBody(LOGIN_PAGE);
    const captured = observe();
    type("u", "alex@example.com");
    type("p", "123456");
    submit();
    expect(captured).toEqual([]);
  });

  test("a signup reports the new password", () => {
    loadBody(
      `<form id="f"><input id="e" type="email" name="email"><input id="n" type="password" autocomplete="new-password"><input id="c" type="password" autocomplete="new-password"><button type="submit">Create account</button></form>`,
    );
    const captured = observe();
    type("e", "new@example.com");
    type("n", "abcdef-ghijkm-npqrs7");
    type("c", "abcdef-ghijkm-npqrs7");
    submit();
    expect(captured).toEqual([
      { kind: "signup", username: "new@example.com", password: "abcdef-ghijkm-npqrs7" },
    ]);
  });

  test("forms that appear after observing starts are found at submit time", () => {
    loadBody(`<div id="slot"></div>`);
    const captured = observe();
    loadBody(LOGIN_PAGE);
    type("u", "alex@example.com");
    type("p", "example-pass-1");
    submit();
    expect(captured).toEqual([ALEX]);
  });

  test("a submit-like button inside an open shadow root is noticed", () => {
    loadBody("");
    const host = document.createElement("div");
    document.body.append(host);
    const shadow = host.attachShadow({ mode: "open" });
    const user = document.createElement("input");
    user.name = "username";
    const pass = document.createElement("input");
    pass.type = "password";
    const button = document.createElement("div");
    button.setAttribute("role", "button");
    button.textContent = "Log in";
    shadow.append(user, pass, button);
    const captured = observe();
    for (const [field, value] of [
      [user, "alex@example.com"],
      [pass, "example-pass-1"],
    ] as const) {
      field.value = value;
      field.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true }));
    }
    button.dispatchEvent(new MouseEvent("click", { bubbles: true, composed: true }));
    expect(captured).toEqual([ALEX]);
  });

  test("the disposer removes every listener", () => {
    loadBody(LOGIN_PAGE);
    const captured = observe();
    dispose?.();
    dispose = null;
    type("u", "alex@example.com");
    type("p", "example-pass-1");
    submit();
    click("b");
    enter("p");
    expect(captured).toEqual([]);
  });
});
