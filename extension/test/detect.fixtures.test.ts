// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Field detection on realistic pages: which element plays each role, what kind of form it is,
// and that every other input on the page (honeypots, search, payment, newsletter) is ignored.

import { describe, expect, test } from "bun:test";

import { classifyField, detectForms, isStyleVisible } from "../src/content/detect";
import type { FieldRole, FormKind, LoginForm } from "../src/content/types";
import { deepQueryAll, loadFixture } from "./fixtures/load";

interface Expected {
  readonly kind: FormKind;
  /** id of the owning <form>, or null for formless groups. */
  readonly form: string | null;
  readonly username: string | null;
  readonly password: string | null;
  readonly newPasswords: readonly string[];
  readonly otp: readonly string[] | null;
}

const login = (form: string | null, username: string | null, password: string): Expected => ({
  kind: "login",
  form,
  username,
  password,
  newPasswords: [],
  otp: null,
});

const otpOnly = (form: string | null, otp: readonly string[]): Expected => ({
  kind: "otp",
  form,
  username: null,
  password: null,
  newPasswords: [],
  otp,
});

const EXPECTED: Record<string, readonly Expected[]> = {
  "classic-login": [login("login", "email", "password")],
  "email-first-step": [
    {
      kind: "username-only",
      form: "identify",
      username: "identifier",
      password: null,
      newPasswords: [],
      otp: null,
    },
  ],
  "password-second-step": [login("verify", null, "passwd")],
  "spa-formless-login": [login(null, "user", "pass")],
  "react-controlled": [login(null, "r-email", "r-pass")],
  "shadow-login": [login("sf", "su", "sp")],
  "shadow-nested-formless": [login(null, "nu", "np")],
  "signup-confirm": [
    {
      kind: "signup",
      form: "signup",
      username: "email",
      password: null,
      newPasswords: ["pw", "pw2"],
      otp: null,
    },
  ],
  "change-password": [
    {
      kind: "change-password",
      form: "pwform",
      username: null,
      password: "cur",
      newPasswords: ["new", "conf"],
      otp: null,
    },
  ],
  "reset-password": [
    {
      kind: "change-password",
      form: "reset",
      username: null,
      password: null,
      newPasswords: ["new1", "new2"],
      otp: null,
    },
  ],
  "otp-single": [otpOnly("otp-form", ["code"])],
  "otp-single-named": [otpOnly(null, ["totp"])],
  "otp-split-6": [otpOnly("verify", ["d1", "d2", "d3", "d4", "d5", "d6"])],
  "otp-split-4": [otpOnly(null, ["c1", "c2", "c3", "c4"])],
  "otp-split-8": [otpOnly("eight", ["e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8"])],
  "otp-split-separator": [otpOnly("sep", ["s1", "s2", "s3", "s4", "s5", "s6"])],
  "otp-split-2char": [otpOnly(null, ["p1", "p2", "p3", "p4"])],
  "newsletter-footer-login": [login("login", "m-email", "m-pass")],
  "newsletter-formless": [login(null, "le", "lp")],
  "search-and-login": [login("login", "login-user", "login-pass")],
  "credit-card": [],
  "russian-login": [login("vhod", "rl-login", "rl-pass")],
  "russian-signup": [
    {
      kind: "signup",
      form: "reg",
      username: "rs-mail",
      password: null,
      newPasswords: ["rs-p1", "rs-p2"],
      otp: null,
    },
  ],
  "russian-change": [
    {
      kind: "change-password",
      form: "smena",
      username: null,
      password: "rc-cur",
      newPasswords: ["rc-new", "rc-conf"],
      otp: null,
    },
  ],
  "autocomplete-off-login": [login("j", "ju", "jp")],
  "anti-autofill-login": [login("bank", "aa-user", "aa-pass")],
  "honeypot-login": [login("hpf", "hu", "hpw")],
  "tel-username-login": [login("tel", "phone", "tpw")],
  "login-and-register": [
    login("lf", "l-email", "l-pass"),
    {
      kind: "signup",
      form: "rf",
      username: "r-email",
      password: null,
      newPasswords: ["r-pass"],
      otp: null,
    },
  ],
  "login-register-formless": [
    login(null, "si-user", "si-pass"),
    {
      kind: "signup",
      form: null,
      username: "su-email",
      password: null,
      newPasswords: ["su-pass", "su-confirm"],
      otp: null,
    },
  ],
  "show-hide-toggle": [login("toggle-form", "tg-email", "tg-pass")],
  "password-revealed": [login("revealed", "rv-user", "rv-pass")],
  "modal-login": [login(null, "m-user", "m-pass")],
  "login-with-2fa-field": [{ ...login("admin", "a-user", "a-pass"), otp: ["a-otp"] }],
  "contact-form": [],
  "pin-pad": [],
  "login-with-captcha": [login("forum", "f-user", "f-pass")],
  "aspnet-wrapper-form": [login("aspnetForm", "ctl00_user", "ctl00_pass")],
  "disabled-form": [],
  "signup-new-password-only": [
    {
      kind: "signup",
      form: "join",
      username: "j-email",
      password: null,
      newPasswords: ["j-pass"],
      otp: null,
    },
  ],
  "tenant-login": [login("tenant", "t-email", "t-pass")],
};

const options = { isVisible: isStyleVisible };

function describeForm(form: LoginForm): Expected {
  return {
    kind: form.kind,
    form: form.form === null ? null : form.form.id,
    username: form.username?.id ?? null,
    password: form.password?.id ?? null,
    newPasswords: form.newPasswords.map((input) => input.id),
    otp: form.otp === null ? null : form.otp.inputs.map((input) => input.id),
  };
}

function expectedRoles(expected: readonly Expected[]): Map<string, FieldRole> {
  const roles = new Map<string, FieldRole>();
  for (const form of expected) {
    if (form.username !== null) roles.set(form.username, "username");
    if (form.password !== null) roles.set(form.password, "current-password");
    for (const id of form.newPasswords) roles.set(id, "new-password");
    for (const id of form.otp ?? []) roles.set(id, "otp");
  }
  return roles;
}

const fixtures = Object.keys(EXPECTED);

describe("detectForms on fixture pages", () => {
  test("covers at least thirty pages", () => {
    expect(fixtures.length).toBeGreaterThanOrEqual(30);
  });

  test.each(fixtures)("%s", (name) => {
    const doc = loadFixture(name);
    expect(detectForms(doc, options).map(describeForm)).toEqual([...(EXPECTED[name] ?? [])]);
  });
});

// Every input on every page, including the ones that must be ignored, gets its own row. Inputs
// without an id (hidden tokens, checkboxes, submit buttons) are named by type and position.
const fieldRows: [string, string, number, FieldRole | null][] = fixtures.flatMap((name) => {
  const doc = loadFixture(name);
  const roles = expectedRoles(EXPECTED[name] ?? []);
  return deepQueryAll(doc, "input").map(
    (input, index): [string, string, number, FieldRole | null] => {
      const label =
        input.id === "" ? `${input.getAttribute("type") ?? "text"}[${index}]` : `#${input.id}`;
      return [name, label, index, input.id === "" ? null : (roles.get(input.id) ?? null)];
    },
  );
});

describe("classifyField agrees with the page's forms", () => {
  test.each(fieldRows)("%s %s → %p", (name, _label, index, role) => {
    const doc = loadFixture(name);
    const input = deepQueryAll(doc, "input").at(index);
    if (!(input instanceof HTMLInputElement)) throw new Error(`input ${index} missing`);
    expect(classifyField(input, options)).toBe(role);
  });
});

describe("detectForms scope", () => {
  test("a subtree root only sees forms inside it", () => {
    const doc = loadFixture("login-and-register");
    const register = doc.getElementById("rf");
    if (register === null) throw new Error("fixture changed");
    expect(detectForms(register, options).map((form) => form.kind)).toEqual(["signup"]);
  });

  test("a shadow root can be scanned on its own", () => {
    const doc = loadFixture("shadow-login");
    const host = doc.querySelector("contoso-login");
    if (host?.shadowRoot == null) throw new Error("fixture changed");
    expect(detectForms(host.shadowRoot, options).map(describeForm)).toEqual([
      login("sf", "su", "sp"),
    ]);
  });

  test("closed shadow roots stay closed", () => {
    const doc = loadFixture("shadow-login");
    const host = doc.createElement("closed-login");
    const shadow = host.attachShadow({ mode: "closed" });
    const user = doc.createElement("input");
    const pass = doc.createElement("input");
    pass.type = "password";
    shadow.append(user, pass);
    doc.body.append(host);
    expect(detectForms(doc, options)).toHaveLength(1);
  });

  test("a field hidden by the injected visibility check is skipped", () => {
    const doc = loadFixture("classic-login");
    const hideEmail = (element: HTMLElement): boolean => element.id !== "email";
    const forms = detectForms(doc, { isVisible: hideEmail });
    expect(forms.map(describeForm)).toEqual([login("login", null, "password")]);
  });
});
