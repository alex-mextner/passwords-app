// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Filling must look like typing to page scripts: the right events in the right order, values
// that framework-controlled inputs actually notice, and one-time codes spread over split boxes.

import { describe, expect, test } from "bun:test";

import { fillLogin, fillNewPassword, fillOtp, setInputValue } from "../src/content/fill";
import type { LoginForm, OtpGroup } from "../src/content/types";
import { loadBody } from "./fixtures/load";

/** The value the browser holds, read past any instance-level `value` override. */
function nativeValue(element: HTMLInputElement): string {
  return Reflect.get(HTMLInputElement.prototype, "value", element);
}

function input(id: string): HTMLInputElement {
  const found = document.getElementById(id);
  if (!(found instanceof HTMLInputElement)) throw new Error(`no input#${id}`);
  return found;
}

function record(element: EventTarget, types: readonly string[]): Event[] {
  const seen: Event[] = [];
  for (const type of types) element.addEventListener(type, (event) => seen.push(event));
  return seen;
}

/**
 * React's value tracker in miniature: it shadows `value` on the instance to remember what
 * scripts assigned, and on `input` only reports a change when the real value differs from
 * the remembered one. A plain `.value =` assignment therefore never reaches onChange.
 */
function trackLikeReact(element: HTMLInputElement): string[] {
  let tracked = nativeValue(element);
  Object.defineProperty(element, "value", {
    configurable: true,
    get(this: HTMLInputElement): unknown {
      return nativeValue(this);
    },
    set(this: HTMLInputElement, next: string) {
      tracked = next;
      Reflect.set(HTMLInputElement.prototype, "value", next, this);
    },
  });
  const changes: string[] = [];
  element.addEventListener("input", () => {
    const actual = nativeValue(element);
    if (actual !== tracked) {
      tracked = actual;
      changes.push(actual);
    }
  });
  return changes;
}

function loginForm(parts: Partial<LoginForm>): LoginForm {
  return {
    form: null,
    kind: "login",
    username: null,
    password: null,
    newPasswords: [],
    otp: null,
    ...parts,
  };
}

const SEQUENCE = ["focus", "input", "change", "blur"];

describe("setInputValue", () => {
  test("an unfocused field gets focus, input, change, blur in that order", () => {
    loadBody(`<input id="u">`);
    const seen = record(input("u"), SEQUENCE);
    setInputValue(input("u"), "alex@example.com");
    expect(seen.map((event) => event.type)).toEqual(SEQUENCE);
    expect(input("u").value).toBe("alex@example.com");
  });

  test("the input event looks like an autofill replacement", () => {
    loadBody(`<input id="u">`);
    const seen = record(input("u"), ["input"]);
    setInputValue(input("u"), "x");
    const [fired] = seen;
    expect(fired).toBeInstanceOf(InputEvent);
    expect((fired as InputEvent).inputType).toBe("insertReplacementText");
    expect(fired?.bubbles).toBe(true);
    expect(fired?.composed).toBe(true);
  });

  test("input and change bubble to the document", () => {
    loadBody(`<form><input id="u"></form>`);
    const seen = record(document, ["input", "change"]);
    setInputValue(input("u"), "x");
    expect(seen.map((event) => event.type)).toEqual(["input", "change"]);
  });

  test("a field the user is in keeps focus and gets no focus/blur", () => {
    loadBody(`<input id="u">`);
    input("u").focus();
    const seen = record(input("u"), SEQUENCE);
    setInputValue(input("u"), "x");
    expect(seen.map((event) => event.type)).toEqual(["input", "change"]);
    expect(document.activeElement).toBe(input("u"));
  });

  test("focus returns to nowhere after filling an unfocused field", () => {
    loadBody(`<input id="u"><input id="other">`);
    setInputValue(input("u"), "x");
    expect(document.activeElement).not.toBe(input("u"));
  });

  test.each([
    ["disabled", `<input id="u" value="kept" disabled>`],
    ["readonly", `<input id="u" value="kept" readonly>`],
  ])("a %s field is left alone", (_kind, body) => {
    loadBody(body);
    const seen = record(input("u"), SEQUENCE);
    setInputValue(input("u"), "changed");
    expect(input("u").value).toBe("kept");
    expect(seen).toEqual([]);
  });

  test("a React-style controlled input notices the fill", () => {
    loadBody(`<input id="u">`);
    const changes = trackLikeReact(input("u"));
    setInputValue(input("u"), "alex@example.com");
    expect(changes).toEqual(["alex@example.com"]);
  });

  test("a plain .value assignment is what React would miss", () => {
    loadBody(`<input id="u">`);
    const changes = trackLikeReact(input("u"));
    input("u").value = "alex@example.com";
    input("u").dispatchEvent(new Event("input", { bubbles: true }));
    expect(changes).toEqual([]);
  });

  test("a page that hijacks the instance setter cannot swallow the value", () => {
    loadBody(`<input id="u">`);
    Object.defineProperty(input("u"), "value", {
      configurable: true,
      get: () => "",
      set: () => undefined,
    });
    setInputValue(input("u"), "secret-example");
    expect(nativeValue(input("u"))).toBe("secret-example");
  });

  test("events from inside an open shadow root reach the document", () => {
    loadBody("");
    const host = document.createElement("div");
    document.body.append(host);
    const inner = document.createElement("input");
    host.attachShadow({ mode: "open" }).append(inner);
    const seen = record(document, ["input"]);
    setInputValue(inner, "x");
    expect(seen).toHaveLength(1);
    expect(inner.value).toBe("x");
  });

  test("focus and blur are dispatched when the browser fires none", () => {
    loadBody(`<input id="u">`);
    const field = input("u");
    // An unfocused window: focus() and blur() run without firing events.
    field.focus = () => undefined;
    field.blur = () => undefined;
    const seen = record(field, [...SEQUENCE, "focusin", "focusout"]);
    setInputValue(field, "x");
    expect(seen.map((event) => event.type)).toEqual([
      "focus",
      "focusin",
      "input",
      "change",
      "blur",
      "focusout",
    ]);
  });

  test("non-ASCII values survive", () => {
    loadBody(`<input id="u">`);
    setInputValue(input("u"), "пароль-密码-🔑");
    expect(input("u").value).toBe("пароль-密码-🔑");
  });
});

describe("fillLogin", () => {
  test("fills username and password", () => {
    loadBody(`<input id="u"><input id="p" type="password">`);
    fillLogin(loginForm({ username: input("u"), password: input("p") }), {
      username: "alex@example.com",
      password: "example-pass-1",
    });
    expect([input("u").value, input("p").value]).toEqual(["alex@example.com", "example-pass-1"]);
  });

  test("an empty username leaves the username field untouched", () => {
    loadBody(`<input id="u" value="typed"><input id="p" type="password">`);
    const seen = record(input("u"), SEQUENCE);
    fillLogin(loginForm({ username: input("u"), password: input("p") }), {
      username: "",
      password: "example-pass-1",
    });
    expect(input("u").value).toBe("typed");
    expect(seen).toEqual([]);
    expect(input("p").value).toBe("example-pass-1");
  });

  test("a form without a username field still gets the password", () => {
    loadBody(`<input id="p" type="password">`);
    fillLogin(loginForm({ password: input("p") }), {
      username: "alex@example.com",
      password: "example-pass-1",
    });
    expect(input("p").value).toBe("example-pass-1");
  });

  test("a username-only step gets just the username", () => {
    loadBody(`<input id="u">`);
    fillLogin(loginForm({ kind: "username-only", username: input("u") }), {
      username: "alex@example.com",
      password: "example-pass-1",
    });
    expect(input("u").value).toBe("alex@example.com");
  });

  test("filling replaces what the user typed", () => {
    loadBody(`<input id="u" value="alx"><input id="p" type="password" value="wrong">`);
    fillLogin(loginForm({ username: input("u"), password: input("p") }), {
      username: "alex@example.com",
      password: "example-pass-1",
    });
    expect([input("u").value, input("p").value]).toEqual(["alex@example.com", "example-pass-1"]);
  });
});

describe("fillNewPassword", () => {
  test("fills the new password and its confirmation", () => {
    loadBody(`<input id="n" type="password"><input id="c" type="password">`);
    fillNewPassword(
      loginForm({ kind: "signup", newPasswords: [input("n"), input("c")] }),
      "abcdef-ghijkm-npqrs7",
    );
    expect([input("n").value, input("c").value]).toEqual([
      "abcdef-ghijkm-npqrs7",
      "abcdef-ghijkm-npqrs7",
    ]);
  });

  test("leaves the current password of a change form alone", () => {
    loadBody(`<input id="cur" type="password" value="old"><input id="n" type="password">`);
    fillNewPassword(
      loginForm({ kind: "change-password", password: input("cur"), newPasswords: [input("n")] }),
      "abcdef-ghijkm-npqrs7",
    );
    expect(input("cur").value).toBe("old");
    expect(input("n").value).toBe("abcdef-ghijkm-npqrs7");
  });

  test("a form without new-password fields is a no-op", () => {
    loadBody(`<input id="p" type="password">`);
    fillNewPassword(loginForm({ password: input("p") }), "abcdef-ghijkm-npqrs7");
    expect(input("p").value).toBe("");
  });
});

function boxes(count: number, maxlength = 1): OtpGroup {
  loadBody(
    Array.from(
      { length: count },
      (_, i) => `<input id="b${i}" maxlength="${maxlength}" inputmode="numeric">`,
    ).join(""),
  );
  return { inputs: Array.from(document.querySelectorAll("input")) };
}

const values = (group: OtpGroup): string[] => group.inputs.map((box) => box.value);

describe("fillOtp", () => {
  test.each([
    ["six boxes, six digits", 6, 1, "123456", ["1", "2", "3", "4", "5", "6"]],
    ["separators are dropped", 6, 1, "123-456", ["1", "2", "3", "4", "5", "6"]],
    ["spaces are dropped", 6, 1, "123 456", ["1", "2", "3", "4", "5", "6"]],
    ["four boxes", 4, 1, "4821", ["4", "8", "2", "1"]],
    ["eight boxes", 8, 1, "90817263", ["9", "0", "8", "1", "7", "2", "6", "3"]],
    ["two-character boxes", 4, 2, "12345678", ["12", "34", "56", "78"]],
    ["a short code fills the leading boxes", 6, 1, "123", ["1", "2", "3", "", "", ""]],
    ["a long code stops at the last box", 6, 1, "12345678", ["1", "2", "3", "4", "5", "6"]],
    ["letters are kept", 6, 1, "AB12CD", ["A", "B", "1", "2", "C", "D"]],
    ["an empty code changes nothing", 6, 1, "", ["", "", "", "", "", ""]],
  ] as const)("%s", (_name, count, maxlength, code, expected) => {
    const group = boxes(count, maxlength);
    fillOtp(group, code);
    expect(values(group)).toEqual([...expected]);
  });

  test("a single field gets the whole code", () => {
    loadBody(`<input id="c" autocomplete="one-time-code">`);
    fillOtp({ inputs: [input("c")] }, "123456");
    expect(input("c").value).toBe("123456");
  });

  test("a single field gets the code without spaces", () => {
    loadBody(`<input id="c">`);
    fillOtp({ inputs: [input("c")] }, " 123 456 ");
    expect(input("c").value).toBe("123456");
  });

  test("focus walks the boxes in order and stays on the last one filled", () => {
    const group = boxes(6);
    const order: string[] = [];
    for (const box of group.inputs) box.addEventListener("focus", () => order.push(box.id));
    fillOtp(group, "123456");
    expect(order).toEqual(["b0", "b1", "b2", "b3", "b4", "b5"]);
    expect(document.activeElement).toBe(group.inputs.at(-1) ?? null);
  });

  test("each box sees input and change, none sees an extra blur from the fill itself", () => {
    const group = boxes(4);
    const seen = record(input("b0"), SEQUENCE);
    fillOtp(group, "1234");
    // The blur comes from focus moving on to the next box, as when typing.
    expect(seen.map((event) => event.type)).toEqual(SEQUENCE);
  });

  test("a disabled box is skipped but keeps its position", () => {
    const group = boxes(4);
    input("b1").disabled = true;
    fillOtp(group, "1234");
    expect(values(group)).toEqual(["1", "", "3", "4"]);
  });

  test("pages that auto-advance focus on input still get the right digits", () => {
    const group = boxes(6);
    group.inputs.forEach((box, index) => {
      box.addEventListener("input", () => group.inputs.at(index + 1)?.focus());
    });
    fillOtp(group, "654321");
    expect(values(group)).toEqual(["6", "5", "4", "3", "2", "1"]);
  });

  test("an empty group is a no-op", () => {
    expect(() => {
      fillOtp({ inputs: [] }, "123456");
    }).not.toThrow();
  });

  test("React-style boxes notice every digit", () => {
    const group = boxes(4);
    const changes = group.inputs.map((box) => trackLikeReact(box));
    fillOtp(group, "1234");
    expect(changes).toEqual([["1"], ["2"], ["3"], ["4"]]);
  });
});
