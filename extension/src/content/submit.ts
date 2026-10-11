// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Notices when the user submits credentials so the extension can offer to save them. Pages
// submit in many ways (a real submit, a click on a scripted button, Enter) and often clear
// their fields before navigating, so values are also remembered as the user types them.

import { buttonText, composedParent, isInputElement, textIntent } from "./detect";
import type { CapturedLogin, LastFill, LoginForm } from "./types";

const MAX_LENGTH = 4096;
const DEDUPE_MS = 2000;
const CLICKABLE_SELECTOR = "button, input[type=submit], input[type=image], [role=button]";

type ValueReader = (input: HTMLInputElement) => string;

function isPlausible(password: string, username: string): boolean {
  if (password.trim() === "" || password.length > MAX_LENGTH || username.length > MAX_LENGTH) {
    return false;
  }
  // Short all-digit values are one-time codes or PINs typed into a password-looking field.
  return password !== username && !/^\d{1,8}$/.test(password);
}

function capture(form: LoginForm, read: ValueReader): CapturedLogin | null {
  let kind: CapturedLogin["kind"];
  let password: string;
  if (form.kind === "login") {
    if (form.password === null) return null;
    kind = "login";
    password = read(form.password);
  } else if (form.kind === "signup" || form.kind === "change-password") {
    const [fresh, confirmation] = form.newPasswords;
    if (fresh === undefined) return null;
    kind = form.kind;
    password = read(fresh);
    // A mistyped confirmation means the page will refuse the submit: nothing worth saving.
    if (confirmation !== undefined) {
      const repeated = read(confirmation);
      if (repeated !== "" && repeated !== password) return null;
    }
  } else {
    return null;
  }
  const username = form.username === null ? "" : read(form.username).trim();
  return isPlausible(password, username) ? { kind, username, password } : null;
}

/** What the form holds right now, or null unless it holds a plausible password to save. */
export function captureFromForm(form: LoginForm): CapturedLogin | null {
  return capture(form, (input) => input.value);
}

/**
 * Whether to offer saving: not when the user submitted exactly what was filled. A capture with
 * no username (a change-password page without one) is compared on the password alone.
 */
export function shouldOffer(captured: CapturedLogin, lastFill: LastFill | null): boolean {
  if (lastFill === null) return true;
  const sameUser = captured.username === "" || captured.username === lastFill.username;
  return !(sameUser && captured.password === lastFill.password);
}

export interface ObserveOptions {
  /**
   * Decides whether an event came from the user; defaults to `event.isTrusted`, so pages cannot
   * fake submissions. Tests pass `() => true` because happy-dom marks every event untrusted.
   */
  readonly isTrusted?: (event: Event) => boolean;
  /** Milliseconds clock used for de-duplication; tests inject a fake one. */
  readonly now?: () => number;
}

function eventTarget(event: Event): EventTarget | null {
  return event.composedPath().at(0) ?? event.target;
}

/** The submit-like control a click landed on, looking through open shadow roots. */
function submitControl(event: Event): Element | null {
  for (const node of event.composedPath().slice(0, 8)) {
    if (!(node instanceof Element) || !node.matches(CLICKABLE_SELECTOR)) continue;
    const type = (node.getAttribute("type") ?? "").toLowerCase();
    if (type === "submit" || type === "image") return node;
    if (node.localName === "button" && type === "" && (node as HTMLButtonElement).form !== null) {
      return node;
    }
    return textIntent(buttonText(node)) === null ? null : node;
  }
  return null;
}

function depthOfShared(ancestors: readonly Element[], input: HTMLInputElement | null): number {
  if (input === null) return -1;
  const own = new Set<Element>();
  for (let node = composedParent(input); node !== null; node = composedParent(node)) own.add(node);
  const shared = ancestors.findIndex((element) => own.has(element));
  return shared === -1 ? -1 : ancestors.length - shared;
}

/** The form a clicked control submits: its own `<form>`, else the nearest formless group. */
function formFor(control: Element, forms: readonly LoginForm[]): LoginForm | null {
  const owner =
    "form" in control && control.form instanceof HTMLFormElement
      ? control.form
      : control.closest("form");
  const candidates = forms.filter((form) => form.form === owner);
  const ancestors: Element[] = [];
  for (let node = composedParent(control); node !== null; node = composedParent(node)) {
    ancestors.push(node);
  }
  let best: LoginForm | null = null;
  let bestDepth = -1;
  for (const form of candidates) {
    const anchor = form.password ?? form.newPasswords.at(0) ?? form.username;
    const depth = depthOfShared(ancestors, anchor);
    if (depth > bestDepth) {
      best = form;
      bestDepth = depth;
    }
  }
  return best;
}

/**
 * Watches `doc` for credential submissions and reports each plausible one once. Signals:
 * `submit` events, clicks on submit-like buttons (including scripted sign-in buttons), and Enter
 * in a password field, all in the capture phase so they run before page handlers clear fields.
 * `input` events keep the last typed value of every field as a fallback for pages that clear
 * fields before navigating. Identical captures within two seconds are reported once. Only
 * trusted events count; see `ObserveOptions.isTrusted`. Returns a disposer that removes every
 * listener and forgets the remembered values.
 */
export function observeSubmissions(
  doc: Document,
  getForms: () => LoginForm[],
  onCapture: (captured: CapturedLogin) => void,
  options: ObserveOptions = {},
): () => void {
  const isTrusted = options.isTrusted ?? ((event: Event) => event.isTrusted);
  const now = options.now ?? (() => Date.now());
  let typed = new WeakMap<HTMLInputElement, string>();
  let last: { readonly key: string; readonly at: number } | null = null;
  const read: ValueReader = (input) =>
    input.value === "" ? (typed.get(input) ?? "") : input.value;

  const report = (form: LoginForm | null | undefined): void => {
    if (form === null || form === undefined) return;
    const captured = capture(form, read);
    if (captured === null) return;
    const key = JSON.stringify([captured.kind, captured.username, captured.password]);
    const at = now();
    if (last !== null && last.key === key && at - last.at < DEDUPE_MS) return;
    last = { key, at };
    onCapture(captured);
  };

  const onInput = (event: Event): void => {
    const target = eventTarget(event);
    if (isTrusted(event) && isInputElement(target)) typed.set(target, target.value);
  };
  const onSubmit = (event: Event): void => {
    if (!isTrusted(event)) return;
    const target = eventTarget(event);
    for (const form of getForms()) if (form.form !== null && form.form === target) report(form);
  };
  const onClick = (event: Event): void => {
    if (!isTrusted(event)) return;
    const control = submitControl(event);
    if (control !== null) report(formFor(control, getForms()));
  };
  const onKeydown = (event: Event): void => {
    if (!isTrusted(event) || !(event instanceof KeyboardEvent)) return;
    if (event.key !== "Enter" || event.isComposing) return;
    const target = eventTarget(event);
    if (!isInputElement(target)) return;
    report(
      getForms().find((form) => form.password === target || form.newPasswords.includes(target)),
    );
  };

  const listeners: [string, (event: Event) => void][] = [
    ["input", onInput],
    ["submit", onSubmit],
    ["click", onClick],
    ["keydown", onKeydown],
  ];
  for (const [type, listener] of listeners) doc.addEventListener(type, listener, true);
  return () => {
    for (const [type, listener] of listeners) doc.removeEventListener(type, listener, true);
    typed = new WeakMap();
    last = null;
  };
}
