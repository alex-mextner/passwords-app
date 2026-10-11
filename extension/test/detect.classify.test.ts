// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// classifyField on small hand-made snippets: one signal at a time (autocomplete tokens, input
// types, English and Russian wording, page context), plus the page-wording classifier.

import { describe, expect, test } from "bun:test";

import { classifyField, detectForms, isStyleVisible, textIntent } from "../src/content/detect";
import type { FieldRole } from "../src/content/types";
import { loadBody } from "./fixtures/load";

const PW = `<input type="password" name="password">`;
const form = (inner: string, button = "Sign in"): string =>
  `<form id="f" action="/x">${inner}<button type="submit">${button}</button></form>`;
const boxes = (count: number, attributes: string): string =>
  Array.from({ length: count }, (_, i) =>
    i === 0 ? `<input id="t" ${attributes}>` : `<input ${attributes}>`,
  ).join("");

// [description, page body, expected role of #t]
const ROWS: [string, string, FieldRole | null][] = [
  // autocomplete tokens
  ["autocomplete=username", form(`<input id="t" autocomplete="username">${PW}`), "username"],
  ["autocomplete=email", form(`<input id="t" type="email" autocomplete="email">${PW}`), "username"],
  [
    "section-* is skipped",
    form(`<input id="t" autocomplete="section-login username">${PW}`),
    "username",
  ],
  [
    "billing modifier is skipped",
    form(`<input id="t" autocomplete="billing email">${PW}`),
    "username",
  ],
  ["webauthn suffix", form(`<input id="t" autocomplete="username webauthn">`, "Next"), "username"],
  [
    "autocomplete=current-password",
    form(`<input id="t" type="password" autocomplete="current-password">`),
    "current-password",
  ],
  [
    "autocomplete=new-password in a signup",
    form(
      `<input type="email" autocomplete="username"><input id="t" type="password" autocomplete="new-password">`,
      "Create account",
    ),
    "new-password",
  ],
  [
    "autocomplete=one-time-code",
    form(`<input id="t" autocomplete="one-time-code">`, "Verify"),
    "otp",
  ],
  ["autocomplete=cc-number", form(`<input id="t" autocomplete="cc-number">${PW}`), null],
  [
    "autocomplete=cc-csc on a password",
    form(`<input id="t" type="password" autocomplete="cc-csc">`),
    null,
  ],
  ["autocomplete=postal-code", form(`<input id="t" autocomplete="postal-code">${PW}`), null],
  ["autocomplete=given-name", form(`<input id="t" autocomplete="given-name">${PW}`), null],
  [
    "autocomplete=tel before a password",
    form(`<input id="t" type="tel" autocomplete="tel">${PW}`),
    "username",
  ],
  [
    "autocomplete=off keeps wording",
    form(`<input id="t" autocomplete="off" name="login">${PW}`),
    "username",
  ],
  [
    "password with autocomplete=off",
    form(`<input id="t" type="password" autocomplete="off">`),
    "current-password",
  ],
  [
    "revealed password (type=text)",
    form(
      `<input autocomplete="username"><input id="t" type="text" autocomplete="current-password">`,
    ),
    "current-password",
  ],
  [
    "revealed password named so",
    form(`<input name="username"><input id="t" type="text" name="password">`),
    "current-password",
  ],
  // input types and states
  ["type=search", form(`<input id="t" type="search" name="user">${PW}`), null],
  ["type=hidden", form(`<input id="t" type="hidden" name="username" value="a">${PW}`), null],
  ["type=url", form(`<input id="t" type="url">${PW}`), null],
  [
    "type=number is never a username",
    form(`<input id="t" type="number" name="account">${PW}`),
    null,
  ],
  ["type=checkbox", form(`<input id="t" type="checkbox">${PW}`), null],
  [
    "phone field before a password",
    form(`<input id="t" type="tel" name="phone">${PW}`),
    "username",
  ],
  ["unnamed text before a password", form(`<input id="t" type="text">${PW}`), "username"],
  ["unnamed text alone", form(`<input id="t" type="text">`), null],
  [
    "named username wins over a nearer unnamed field",
    form(`<input name="username"><input id="t" type="text">${PW}`),
    null,
  ],
  ["text after the password", form(`${PW}<input id="t" name="x">`), null],
  ["disabled", form(`<input id="t" name="username" disabled>${PW}`), null],
  ["readonly", form(`<input id="t" name="username" readonly>${PW}`), null],
  [
    "inside a disabled fieldset",
    form(`<fieldset disabled><input id="t" name="username">${PW}</fieldset>`),
    null,
  ],
  [
    "aria-hidden ancestor",
    form(`<div aria-hidden="true"><input id="t" name="username"></div>${PW}`),
    null,
  ],
  ["inert ancestor", form(`<div inert><input id="t" name="username"></div>${PW}`), null],
  ["display:none", form(`<input id="t" name="username" style="display:none">${PW}`), null],
  // English wording
  ["j_username", form(`<input id="t" name="j_username">${PW}`), "username"],
  [
    "placeholder Email or phone",
    form(`<input id="t" placeholder="Email or phone">${PW}`),
    "username",
  ],
  [
    "placeholder with an address",
    form(`<input id="t" placeholder="you@example.com">${PW}`),
    "username",
  ],
  ["label Login ID", form(`<label for="t">Login ID</label><input id="t">${PW}`), "username"],
  [
    "aria-labelledby Account name",
    form(`<span id="l">Account name</span><input id="t" aria-labelledby="l">${PW}`),
    "username",
  ],
  ["bare caption before the field", form(`<span>Username</span><input id="t">${PW}`), "username"],
  [
    "confirm password in a signup",
    form(
      `<input type="email" name="email"><input type="password" name="password"><label for="t">Confirm password</label><input id="t" type="password">`,
      "Sign up",
    ),
    "new-password",
  ],
  [
    "old password in a change form",
    form(
      `<input id="t" type="password" name="old_password"><input type="password" name="new_password">`,
      "Save",
    ),
    "current-password",
  ],
  [
    "new password in a change form",
    form(
      `<input type="password" name="old_password"><input id="t" type="password" name="new_password">`,
      "Save",
    ),
    "new-password",
  ],
  [
    "placeholder Create a password",
    form(
      `<input name="username"><input id="t" type="password" placeholder="Create a password">`,
      "Sign up",
    ),
    "new-password",
  ],
  [
    "generic password, Log in",
    form(`<input name="email"><input id="t" type="password">`, "Log in"),
    "current-password",
  ],
  [
    "generic password, Create account",
    form(`<input type="email" name="email"><input id="t" type="password">`, "Create account"),
    "new-password",
  ],
  [
    "generic password, Reset password",
    form(`<h2>Reset your password</h2><input id="t" type="password">`, "Reset password"),
    "new-password",
  ],
  [
    "Forgot password button does not make it a reset",
    form(
      `<input name="email"><input id="t" type="password"><button type="button">Forgot password?</button>`,
      "Log in",
    ),
    "current-password",
  ],
  ["password named pin", form(`<input id="t" type="password" name="pin">`), null],
  ["password named cvv", form(`<input id="t" type="password" name="cvv">`), null],
  ["captcha", form(`<input id="t" name="captcha">${PW}`), null],
  ["promo code", form(`<input id="t" name="promo_code">${PW}`), null],
  ["zip", form(`<input id="t" name="zip">${PW}`), null],
  ["first name", form(`<input id="t" name="first_name">${PW}`), null],
  ["company", form(`<input id="t" name="company">${PW}`), null],
  ["otp next to a password", form(`<input name="username">${PW}<input id="t" name="otp">`), "otp"],
  [
    "verification_code numeric",
    form(`<input id="t" name="verification_code" inputmode="numeric">`, "Verify"),
    "otp",
  ],
  ["code without numeric hints", form(`<input id="t" name="code">`, "Verify"), null],
  ["code with maxlength 6", form(`<input id="t" name="code" maxlength="6">`, "Verify"), "otp"],
  ["mfa token", form(`<input id="t" name="mfa_token">`, "Verify"), "otp"],
  [
    "6-digit code aria-label",
    form(`<input id="t" aria-label="6-digit code" inputmode="numeric">`, "Verify"),
    "otp",
  ],
  ["code typed as a password", form(`<input id="t" type="password" name="otp">`, "Verify"), "otp"],
  ["totp camelCase", form(`<input id="t" name="totpCode">`, "Verify"), "otp"],
  ["2FA in the label", form(`<label for="t">2FA code</label><input id="t">`, "Verify"), "otp"],
  [
    "newsletter form email",
    `<form><h3>Newsletter</h3><input id="t" type="email" name="email"><button>Subscribe</button></form>`,
    null,
  ],
  ["newsletter-named field", form(`<input id="t" type="email" name="newsletter_email">`), null],
  [
    "lone email, Continue",
    form(`<input id="t" type="email" name="email">`, "Continue"),
    "username",
  ],
  ["lone email, Send", form(`<input id="t" type="email" name="email">`, "Send"), null],
  ["lone username, Send", form(`<input id="t" name="username">`, "Send"), "username"],
  ["name=q", form(`<input id="t" name="q">${PW}`), null],
  ["placeholder Search", form(`<input id="t" placeholder="Search">${PW}`), null],
  // Russian wording
  ["Логин", form(`<label for="t">Логин</label><input id="t">${PW}`, "Войти"), "username"],
  [
    "Пароль",
    form(
      `<input name="login"><label for="t">Пароль</label><input id="t" type="password">`,
      "Войти",
    ),
    "current-password",
  ],
  [
    "Новый пароль",
    form(
      `<label>Текущий пароль <input type="password"></label><label for="t">Новый пароль</label><input id="t" type="password">`,
      "Сохранить",
    ),
    "new-password",
  ],
  [
    "Текущий пароль",
    form(
      `<label for="t">Текущий пароль</label><input id="t" type="password"><label>Новый пароль <input type="password"></label>`,
      "Сохранить",
    ),
    "current-password",
  ],
  [
    "Повторите пароль",
    form(
      `<input type="email" name="email"><input type="password"><label for="t">Повторите пароль</label><input id="t" type="password">`,
      "Зарегистрироваться",
    ),
    "new-password",
  ],
  [
    "Код подтверждения",
    form(`<label for="t">Код подтверждения</label><input id="t">`, "Подтвердить"),
    "otp",
  ],
  [
    "Электронная почта",
    form(`<label for="t">Электронная почта</label><input id="t">${PW}`, "Войти"),
    "username",
  ],
  [
    "Имя пользователя",
    form(`<label for="t">Имя пользователя</label><input id="t">${PW}`, "Войти"),
    "username",
  ],
  ["Номер карты", form(`<label for="t">Номер карты</label><input id="t">${PW}`, "Оплатить"), null],
  ["Фамилия", form(`<label for="t">Фамилия</label><input id="t">${PW}`, "Войти"), null],
  ["Промокод", form(`<label for="t">Промокод</label><input id="t">${PW}`, "Войти"), null],
  [
    "Телефон",
    form(`<label for="t">Телефон</label><input id="t" type="tel">${PW}`, "Войти"),
    "username",
  ],
  ["Поиск", form(`<input id="t" placeholder="Поиск по сайту">${PW}`, "Войти"), null],
  [
    "generic password, Зарегистрироваться",
    form(`<input type="email" name="email"><input id="t" type="password">`, "Зарегистрироваться"),
    "new-password",
  ],
  // split code boxes
  ["6 numeric boxes", form(boxes(6, `inputmode="numeric" maxlength="1"`), "Verify"), "otp"],
  ["4 tel boxes", form(boxes(4, `type="tel" maxlength="1"`), "Verify"), "otp"],
  ["3 boxes are too few", form(boxes(3, `inputmode="numeric" maxlength="1"`), "Verify"), null],
  ["9 boxes are too many", form(boxes(9, `inputmode="numeric" maxlength="1"`), "Verify"), null],
  [
    "6 boxes named pin",
    form(boxes(6, `name="pin" inputmode="numeric" maxlength="1"`), "Unlock"),
    null,
  ],
  [
    "boxes too far apart are not one code",
    form(
      Array.from(
        { length: 6 },
        (_, i) =>
          `<div><div><div><div><input ${i === 0 ? 'id="t" ' : ""}inputmode="numeric" maxlength="1"></div></div></div></div>`,
      ).join(""),
      "Verify",
    ),
    null,
  ],
];

const options = { isVisible: isStyleVisible };

describe("classifyField", () => {
  test("has at least sixty rows", () => {
    expect(ROWS.length).toBeGreaterThanOrEqual(60);
  });

  test.each(ROWS)("%s", (_description, body, role) => {
    const doc = loadBody(body);
    const target = doc.getElementById("t");
    if (!(target instanceof HTMLInputElement)) throw new Error("row needs an input#t");
    expect(classifyField(target, options)).toBe(role);
  });

  test("uses the default visibility check when none is injected", () => {
    // happy-dom has no layout, so the real-browser check sees every field as invisible.
    const doc = loadBody(form(`<input id="t" name="username">${PW}`));
    const target = doc.getElementById("t") as HTMLInputElement;
    expect(classifyField(target)).toBeNull();
  });

  test("a detached input is classified within its own subtree", () => {
    loadBody("");
    const box = document.createElement("form");
    const user = document.createElement("input");
    user.name = "username";
    const pass = document.createElement("input");
    pass.type = "password";
    box.append(user, pass);
    expect(classifyField(user, { isVisible: () => true })).toBe("username");
  });
});

describe("detectForms grouping details", () => {
  test("a split code keeps document order across wrappers", () => {
    const doc = loadBody(
      form(
        `<div><input id="a" maxlength="1" inputmode="numeric"><input id="b" maxlength="1" inputmode="numeric"></div><span>-</span><div><input id="c" maxlength="1" inputmode="numeric"><input id="d" maxlength="1" inputmode="numeric"></div>`,
        "Verify",
      ),
    );
    const [found] = detectForms(doc, options);
    expect(found?.otp?.inputs.map((input) => input.id)).toEqual(["a", "b", "c", "d"]);
  });

  test("form= attribute joins a field outside the form element", () => {
    const doc = loadBody(
      `<input id="u" name="username" form="lf"><form id="lf"><input id="p" type="password"><button>Sign in</button></form>`,
    );
    const [found] = detectForms(doc, options);
    expect(found?.username?.id).toBe("u");
    expect(found?.form?.id).toBe("lf");
  });

  test("two formless logins in sibling containers stay apart", () => {
    const doc = loadBody(
      `<div><input id="u1" name="username"><input id="p1" type="password"><button>Sign in</button></div><div><input id="u2" name="username"><input id="p2" type="password"><button>Sign in</button></div>`,
    );
    expect(detectForms(doc, options).map((f) => [f.username?.id, f.password?.id])).toEqual([
      ["u1", "p1"],
      ["u2", "p2"],
    ]);
  });

  test("a password wrapped with its confirmation still finds the username above", () => {
    const doc = loadBody(
      `<div class="signup"><input id="e" type="email" name="email"><div class="pw"><input id="p1" type="password"><input id="p2" type="password" placeholder="Repeat password"></div><button>Sign up</button></div>`,
    );
    const [found] = detectForms(doc, options);
    expect(found?.kind).toBe("signup");
    expect(found?.username?.id).toBe("e");
    expect(found?.newPasswords.map((input) => input.id)).toEqual(["p1", "p2"]);
  });

  test("login and registration in one flat container split at the next text field", () => {
    const doc = loadBody(
      `<input id="u" name="username"><input id="p" type="password"><input id="e" type="email" name="email"><input id="n" type="password" autocomplete="new-password"><button>Sign in</button>`,
    );
    expect(detectForms(doc, options).map((f) => f.username?.id)).toEqual(["u", "e"]);
  });

  test("two unhinted passwords without a username are a reset", () => {
    const doc = loadBody(
      form(`<input id="a" type="password"><input id="b" type="password">`, "Save"),
    );
    const [found] = detectForms(doc, options);
    expect(found?.kind).toBe("change-password");
    expect(found?.password).toBeNull();
  });

  test("two unhinted passwords on a change page are current and new", () => {
    const doc = loadBody(
      form(`<input id="a" type="password"><input id="b" type="password">`, "Change password"),
    );
    const [found] = detectForms(doc, options);
    expect(found?.password?.id).toBe("a");
    expect(found?.newPasswords.map((input) => input.id)).toEqual(["b"]);
  });

  test("new-password autocomplete on a plain login form stays a login", () => {
    const doc = loadBody(
      form(
        `<input name="username"><input id="p" type="password" autocomplete="new-password">`,
        "Log in",
      ),
    );
    expect(detectForms(doc, options).at(0)?.kind).toBe("login");
  });

  test("a set-password page without a username is a change", () => {
    const doc = loadBody(
      form(`<input id="p" type="password" autocomplete="new-password">`, "Continue"),
    );
    const [found] = detectForms(doc, options);
    expect(found?.kind).toBe("change-password");
    expect(found?.newPasswords.map((input) => input.id)).toEqual(["p"]);
  });

  test("an e-mail field before a one-time code becomes that form's username", () => {
    const doc = loadBody(
      form(
        `<input id="e" type="email" name="email"><input id="c" autocomplete="one-time-code">`,
        "Verify",
      ),
    );
    const [found] = detectForms(doc, options);
    expect(found?.kind).toBe("otp");
    expect(found?.username?.id).toBe("e");
  });

  test("an empty page has no forms", () => {
    expect(detectForms(loadBody("<p>Nothing here</p>"), options)).toEqual([]);
  });

  test("absurdly long captions are clipped, not scanned", () => {
    const filler = "x".repeat(100_000);
    const doc = loadBody(form(`<label for="t">${filler} Username</label><input id="t">${PW}`));
    // Clipped wording no longer says "username", but position still makes it one.
    expect(classifyField(doc.getElementById("t") as HTMLInputElement, options)).toBe("username");
  });
});

describe("textIntent", () => {
  test.each([
    ["Sign in", "login"],
    ["Log In", "login"],
    ["SignIn", "login"],
    ["Войти", "login"],
    ["Continue", "login"],
    ["Далее", "login"],
    ["Sign up", "signup"],
    ["Create an account", "signup"],
    ["Register", "signup"],
    ["Зарегистрироваться", "signup"],
    ["Создать аккаунт", "signup"],
    ["Change password", "change"],
    ["Reset your password", "change"],
    ["Сменить пароль", "change"],
    ["Восстановить пароль", "change"],
    ["Forgot password?", null],
    ["Subscribe", null],
    ["Send message", null],
    ["", null],
  ] as const)("%p → %p", (text, intent) => {
    expect(textIntent(text)).toBe(intent);
  });
});
