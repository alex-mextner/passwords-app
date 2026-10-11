// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Puts values into page inputs the way a user's typing would look to the page's scripts.
// Frameworks such as React keep their own copy of an input's value and only notice changes
// made through the native setter followed by an `input` event, so that is the only path used.

import type { LoginForm, OtpGroup } from "./types";

type InputPrototypeHolder = Window & { readonly HTMLInputElement: typeof HTMLInputElement };

function writeNativeValue(element: HTMLInputElement, value: string): void {
  // The element's own realm: a same-origin frame has its own prototype objects. Reflect.set
  // with the element as receiver runs the prototype's setter, bypassing any instance override.
  const view = element.ownerDocument.defaultView as InputPrototypeHolder | null;
  const prototype = view?.HTMLInputElement.prototype ?? HTMLInputElement.prototype;
  if (!Reflect.set(prototype, "value", value, element)) element.value = value;
}

function isFocused(element: HTMLInputElement): boolean {
  const root = element.getRootNode() as Document | ShadowRoot;
  return "activeElement" in root && root.activeElement === element;
}

/**
 * Runs the native focus/blur; when the browser fired no event (it skips them while the window
 * itself is unfocused) dispatches one, because page listeners still expect the pair.
 */
function moveFocus(element: HTMLInputElement, type: "focus" | "blur"): void {
  const seen: Event[] = [];
  const mark = (event: Event): void => {
    seen.push(event);
  };
  element.addEventListener(type, mark);
  if (type === "focus") element.focus({ preventScroll: true });
  else element.blur();
  element.removeEventListener(type, mark);
  if (seen.length > 0) return;
  element.dispatchEvent(new FocusEvent(type));
  const bubbling = type === "focus" ? "focusin" : "focusout";
  element.dispatchEvent(new FocusEvent(bubbling, { bubbles: true, composed: true }));
}

/**
 * Sets `value` like an autofill: focus (unless already focused), native setter, `input`
 * (insertReplacementText) and `change`, then blur only if the field was not focused before.
 * Disabled and read-only fields are left alone.
 */
export function setInputValue(element: HTMLInputElement, value: string): void {
  if (element.disabled || element.readOnly) return;
  const wasFocused = isFocused(element);
  if (!wasFocused) moveFocus(element, "focus");
  writeNativeValue(element, value);
  element.dispatchEvent(
    new InputEvent("input", {
      bubbles: true,
      composed: true,
      cancelable: false,
      inputType: "insertReplacementText",
      data: null,
    }),
  );
  element.dispatchEvent(new Event("change", { bubbles: true }));
  if (!wasFocused) moveFocus(element, "blur");
}

/** Fills the username (when the form has one and the login has one) and the password. */
export function fillLogin(
  form: LoginForm,
  credential: { username: string; password: string },
): void {
  if (form.username !== null && credential.username !== "") {
    setInputValue(form.username, credential.username);
  }
  if (form.password !== null) setInputValue(form.password, credential.password);
}

/** Puts a new password into the new-password field and its confirmation. */
export function fillNewPassword(form: LoginForm, password: string): void {
  for (const input of form.newPasswords) setInputValue(input, password);
}

function boxWidth(input: HTMLInputElement): number {
  const length = Number.parseInt(input.getAttribute("maxlength") ?? "", 10);
  return length >= 1 && length <= 2 ? length : 1;
}

/**
 * Enters a one-time code. A single field receives the whole code; split boxes receive one
 * character each (two where a box takes two), with focus moving box to box like typing and
 * staying on the last box filled. Separators in the code are dropped; a short code fills the
 * leading boxes only and characters beyond the last box are ignored.
 */
export function fillOtp(group: OtpGroup, code: string): void {
  const compact = code.replace(/[\s-]+/g, "");
  const [first, ...rest] = group.inputs;
  if (first === undefined || compact === "") return;
  if (rest.length === 0) {
    setInputValue(first, compact);
    return;
  }
  const characters = Array.from(compact);
  let position = 0;
  for (const box of group.inputs) {
    if (position >= characters.length) break;
    const width = boxWidth(box);
    const piece = characters.slice(position, position + width).join("");
    position += width;
    if (box.disabled || box.readOnly) continue;
    if (!isFocused(box)) moveFocus(box, "focus");
    setInputValue(box, piece);
  }
}
