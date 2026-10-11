// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Finds credential fields on arbitrary pages and groups them into forms. Pages are hostile and
// inconsistent, so decisions combine cheap wording signals (English and Russian) with document
// order; layout is consulted only through the visibility check, which tests replace because
// happy-dom has no layout.

import type { DetectOptions, FieldRole, FormKind, LoginForm, OtpGroup } from "./types";

/** What a page's own wording says a form is for. */
export type Intent = "login" | "signup" | "change";

// Every pattern runs on `normalize()` output: lowercase words separated by single spaces with a
// space at both ends, so " word " is a whole-word match. \b is not used because it ignores
// Cyrillic letters.
const USERNAME_WORDS =
  / (?:user ?name|user ?id|user|login|log ?in|login ?id|identifier|account ?(?:name|id|number)?|nick ?name|member ?(?:id|name)|customer ?(?:id|number)|uid|логин\p{L}*|пользовател\p{L}*|уч[её]тн\p{L}* запис\p{L}*) /u;
const EMAIL_WORDS = / (?:e ?mail|mail|почт\p{L}*) /u;
const PASSWORD_WORDS = / (?:pass ?word|passwd|pwd|pass|pw|парол\p{L}*) /u;
const NEW_WORDS =
  / (?:new|create|choose|set|generate|нов(?:ый|ая|ое|ого|ые)|придума\p{L}*|задай\p{L}*|установ\p{L}*) /u;
const CONFIRM_WORDS =
  / (?:confirm\p{L}*|repeat\p{L}*|retype|re ?type|re ?enter|again|verify|verification|re ?pass ?word|re pwd|(?:pass ?word|pass|pwd|pw) 2|повтор\p{L}*|подтвер\p{L}*|ещ[её] раз) /u;
const CURRENT_WORDS =
  / (?:current|old|existing|previous|present|текущ\p{L}*|стар\p{L}*|прежн\p{L}*|действующ\p{L}*) /u;
const OTP_STRONG_WORDS =
  / (?:otp|totp|hotp|2fa|mfa|tfa|one ?time|2 ?step|two ?(?:factor|step)|authenticator|auth ?code|sms ?code|(?:verification|verify|confirmation) code|одноразов\p{L}*|код (?:подтвержд\p{L}*|из (?:смс|sms)|верификац\p{L}*)|(?:смс|sms) ?код) /u;
const OTP_WEAK_WORDS = / (?:code|код|token|pass ?code|verification|verify|digits?|цифр\p{L}*) /u;
const SEARCH_WORDS = / (?:search\p{L}*|поиск\p{L}*|query|найти|искать|keywords?) /u;
const CAPTCHA_WORDS = / (?:\p{L}*captcha\p{L}*|капч\p{L}*|антибот) /u;
const CARD_WORDS =
  / (?:cc|cc ?(?:num|number|exp|name|csc|cvc|cvv|type)|card\p{L}*|credit\p{L}*|debit|cvv|cvc|csc|cvn|expir\p{L}*|exp ?(?:month|year|date|mm|yy|yyyy)|mm ?yy|security ?code|iban|routing|карт\p{L}*|срок действия) /u;
const ID_NUMBER_WORDS =
  / (?:pin|pin ?code|пин|пин ?код|ssn|social security|снилс|инн|passport\p{L}*|паспорт\p{L}*) /u;
const ZIP_WORDS = / (?:zip|zip ?code|postal\p{L}*|post ?code|индекс) /u;
const PROMO_WORDS =
  / (?:promo\p{L}*|coupon\p{L}*|voucher\p{L}*|gift ?card|discount|invit\p{L}* code|referral\p{L}*|промо ?код\p{L}*|промокод\p{L}*|купон\p{L}*) /u;
const PERSONAL_WORDS =
  / (?:(?:first|last|full|middle|given|family|sur|your|real|display) ?name|fname|lname|surname|фамили\p{L}*|отчеств\p{L}*|имя|street|city|town|country|address|адрес\p{L}*|город\p{L}*|улиц\p{L}*|company|organi[sz]ation|компани\p{L}*|организац\p{L}*|birth\p{L}*|dob|рождени\p{L}*|amount|quantity|qty|price|сумм\p{L}*|comment\p{L}*|message|subject|комментар\p{L}*|сообщени\p{L}*|тема) /u;
const NEWSLETTER_WORDS =
  / (?:newsletter\p{L}*|subscri\p{L}*|mailing ?list|digest|рассылк\p{L}*|подпис\p{L}*|новост\p{L}*) /u;
const LOGIN_WORDS =
  / (?:sign ?in|log ?in|log ?on|logon|authori[sz]\p{L}*|authenticat\p{L}*|session|войти|вход\p{L}*|войдите|авториз\p{L}*) /u;
const NEXT_WORDS = / (?:continue|next|proceed|далее|продолжить|дальше) /u;
const SIGNUP_WORDS =
  / (?:sign ?up|register\p{L}*|registration|create [\p{L} ]{0,30}?account|new account|join|get started|enroll\p{L}*|зарегистр\p{L}*|регистрац\p{L}*|создать [\p{L} ]{0,30}?(?:аккаунт|учетн\p{L}*|учётн\p{L}*|профиль)|присоедин\p{L}*) /u;
const CHANGE_WORDS =
  / (?:(?:change|update|reset|set|recover\p{L}*|restore|сменить|смена|смените|изменить|изменени\p{L}*|обновить|сбросить|сброс|восстанов\p{L}*|установить) [\p{L} ]{0,30}?(?:pass ?word|pwd|парол\p{L}*)|pass ?word (?:reset|change|update|recovery|edit)) /u;
// "Forgot password?" buttons sit in login forms; their wording must not turn a login into a reset.
const FORGOT_WORDS = / (?:forgot\p{L}*|lost|забыли|не помню) /u;

const SEARCH_NAMES: Record<string, true> = { q: true, s: true, query: true, search: true };
const ELIGIBLE_TYPES: Record<string, true> = {
  text: true,
  email: true,
  tel: true,
  password: true,
  number: true,
};
const TEXT_TYPES: Record<string, true> = { text: true, email: true, tel: true };
const BOX_TYPES: Record<string, true> = { text: true, tel: true, number: true };
const AUTOCOMPLETE_MODIFIERS: Record<string, true> = {
  shipping: true,
  billing: true,
  home: true,
  work: true,
  mobile: true,
  fax: true,
  pager: true,
  webauthn: true,
};
const NON_CREDENTIAL_AUTOCOMPLETE: Record<string, true> = {
  name: true,
  "honorific-prefix": true,
  "given-name": true,
  "additional-name": true,
  "family-name": true,
  "honorific-suffix": true,
  "organization-title": true,
  organization: true,
  "street-address": true,
  country: true,
  "country-name": true,
  "postal-code": true,
  "transaction-currency": true,
  "transaction-amount": true,
  language: true,
  sex: true,
  url: true,
  photo: true,
  impp: true,
};

const BUTTON_SELECTOR =
  "button, input[type=submit], input[type=button], input[type=image], [role=button]";
const HEADING_SELECTOR = "h1, h2, h3, h4, legend, [role=heading]";
// Page-controlled text is clipped before any regex sees it.
const MAX_TEXT = 300;
// Split code boxes sit in a shallow wrapper; anything further apart is a different widget.
const BOX_DISTANCE = 3;
// How far a lone password may reach upwards for the username that precedes it.
const USERNAME_REACH = 4;
// How far a container may grow to find the button that names its purpose.
const BUTTON_REACH = 3;

function normalize(text: string): string {
  const words = text
    .slice(0, MAX_TEXT)
    .replace(/(\p{Ll})(\p{Lu})/gu, "$1 $2")
    .replace(/(\p{Lu})(\p{Lu}\p{Ll})/gu, "$1 $2")
    .replace(/(\p{L})(\p{N})/gu, "$1 $2")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim();
  return ` ${words} `;
}

/** Narrows any DOM node to an `<input>`, across realms where `instanceof` is unreliable. */
export function isInputElement(node: unknown): node is HTMLInputElement {
  return (
    typeof node === "object" &&
    node !== null &&
    (node as Node).nodeType === Node.ELEMENT_NODE &&
    (node as Element).localName === "input"
  );
}

function isShadowRoot(node: Node): node is ShadowRoot {
  return node.nodeType === Node.DOCUMENT_FRAGMENT_NODE && "host" in node;
}

/** Parent across shadow boundaries: a shadow root's top-level children belong to its host. */
export function composedParent(node: Node): Element | null {
  const parent = node.parentNode;
  if (parent === null) return null;
  if (parent.nodeType === Node.ELEMENT_NODE) return parent as Element;
  return isShadowRoot(parent) ? parent.host : null;
}

/**
 * Style-only visibility: display/visibility/opacity and the `hidden` attribute, on the element
 * and every composed ancestor. Works without layout, so tests inject it as `isVisible`.
 */
export function isStyleVisible(element: HTMLElement): boolean {
  const view = element.ownerDocument.defaultView;
  if (view === null) return !element.hidden;
  const own = view.getComputedStyle(element);
  if (own.visibility === "hidden" || own.visibility === "collapse") return false;
  for (let node: Element | null = element; node !== null; node = composedParent(node)) {
    if (node.hasAttribute("hidden")) return false;
    const style = view.getComputedStyle(node);
    if (style.display === "none" || Number.parseFloat(style.opacity) === 0) return false;
  }
  return true;
}

/**
 * Real-browser visibility: the style check plus a layout box that is not collapsed to a
 * pixel and not pushed off the top/left edge, the usual honeypot tricks.
 */
export function defaultIsVisible(element: HTMLElement): boolean {
  if (!isStyleVisible(element)) return false;
  if (element.getClientRects().length === 0) return false;
  const box = element.getBoundingClientRect();
  if (box.width < 2 || box.height < 2) return false;
  return box.right > 0 && box.bottom > 0;
}

// --- per-field analysis ----------------------------------------------------------------------

interface Field {
  readonly input: HTMLInputElement;
  readonly index: number;
  /** Composed ancestors, nearest first, ending at the scan root or the form owner. */
  readonly chain: readonly Element[];
  readonly ancestors: ReadonlySet<Element>;
  /** Holds a password (type=password, or a password shown as text by a reveal toggle). */
  readonly secret: boolean;
  /** One box of a split one-time code. */
  readonly box: boolean;
  readonly role: FieldRole | null;
  /** 2: autocomplete said so; 1: the field's wording said so; 0: a default. */
  readonly certainty: 0 | 1 | 2;
  /** A password worded as the repetition of another one. */
  readonly confirm: boolean;
  /** For usernames: 2 named as a login/username, 1 only as an e-mail address. */
  readonly identity: 0 | 1 | 2;
  readonly newsletter: boolean;
}

type FieldTraits = Omit<Field, "input" | "index" | "chain" | "ancestors">;

const NEUTRAL: FieldTraits = {
  secret: false,
  box: false,
  role: null,
  certainty: 0,
  confirm: false,
  identity: 0,
  newsletter: false,
};

function autocompleteField(input: HTMLInputElement): string | null {
  const tokens = (input.getAttribute("autocomplete") ?? "")
    .toLowerCase()
    .split(/\s+/)
    .filter((token) => token !== "" && !token.startsWith("section-"))
    .filter((token) => !Object.hasOwn(AUTOCOMPLETE_MODIFIERS, token));
  return tokens.at(-1) ?? null;
}

const TEXT_NODE = 3; // Node.TEXT_NODE
const SHOW_TEXT = 0x4; // NodeFilter.SHOW_TEXT

/**
 * Text content clipped to what the wording patterns will ever look at. Walks text nodes and
 * stops at the budget: `textContent` would first build a hostile subtree's whole text.
 */
function textOf(node: Node | null | undefined): string {
  if (node === null || node === undefined) return "";
  if (node.nodeType === TEXT_NODE) return (node.nodeValue ?? "").slice(0, MAX_TEXT);
  const doc = node.ownerDocument;
  if (doc === null) return "";
  const walker = doc.createTreeWalker(node, SHOW_TEXT);
  let text = "";
  for (let t = walker.nextNode(); t !== null && text.length < MAX_TEXT; t = walker.nextNode()) {
    text += (t.nodeValue ?? "").slice(0, MAX_TEXT - text.length);
  }
  return text;
}

function labelText(input: HTMLInputElement): string {
  const parts: string[] = [];
  for (const label of Array.from(input.labels ?? [])) parts.push(textOf(label));
  const labelledBy = input.getAttribute("aria-labelledby");
  if (labelledBy !== null) {
    const root = input.getRootNode() as Document | ShadowRoot;
    for (const id of labelledBy.split(/\s+/).filter(Boolean).slice(0, 4)) {
      parts.push(textOf(root.getElementById(id)));
    }
  }
  if (parts.length === 0 && !input.hasAttribute("aria-label")) {
    // Many pages caption fields with a bare <span>/<div> right before them.
    const previous = input.previousElementSibling;
    const caption = textOf(previous).trim();
    if (previous !== null && !isInputElement(previous) && caption.length <= 60) parts.push(caption);
  }
  return parts.join(" | ");
}

function hintText(input: HTMLInputElement): string {
  return normalize(
    [
      input.name,
      input.id,
      input.getAttribute("class") ?? "",
      input.placeholder,
      input.getAttribute("aria-label") ?? "",
      input.title,
      labelText(input),
    ]
      .map((part) => part.slice(0, MAX_TEXT))
      .join(" | "),
  );
}

function maxLengthOf(input: HTMLInputElement): number {
  const value = Number.parseInt(input.getAttribute("maxlength") ?? "", 10);
  return Number.isNaN(value) ? -1 : value;
}

function isNumericEntry(input: HTMLInputElement): boolean {
  const mode = (input.getAttribute("inputmode") ?? "").toLowerCase();
  const pattern = input.getAttribute("pattern") ?? "";
  return (
    input.type === "tel" ||
    input.type === "number" ||
    mode === "numeric" ||
    mode === "decimal" ||
    pattern.includes("\\d") ||
    pattern.includes("0-9")
  );
}

function isCodeBox(input: HTMLInputElement): boolean {
  if (!Object.hasOwn(BOX_TYPES, input.type)) return false;
  const length = maxLengthOf(input);
  if (length >= 1 && length <= 2) return true;
  const max = Number.parseInt(input.getAttribute("max") ?? "", 10);
  return input.type === "number" && max >= 0 && max <= 99;
}

/** Wording that rules a field out whatever its type: search, captcha, payment and ID numbers. */
function isNeverCredential(hints: string): boolean {
  return (
    SEARCH_WORDS.test(hints) ||
    CAPTCHA_WORDS.test(hints) ||
    CARD_WORDS.test(hints) ||
    ID_NUMBER_WORDS.test(hints)
  );
}

function secretTraits(hints: string, role: FieldRole | null, certainty: 0 | 1 | 2): FieldTraits {
  const confirm = CONFIRM_WORDS.test(hints);
  if (role !== null) return { ...NEUTRAL, secret: true, role, certainty, confirm };
  if (confirm || NEW_WORDS.test(hints)) {
    return { ...NEUTRAL, secret: true, role: "new-password", certainty: 1, confirm };
  }
  if (CURRENT_WORDS.test(hints)) {
    return { ...NEUTRAL, secret: true, role: "current-password", certainty: 1 };
  }
  return { ...NEUTRAL, secret: true, role: "current-password", certainty: 0 };
}

function textTraits(input: HTMLInputElement, hints: string): FieldTraits | null {
  if (Object.hasOwn(SEARCH_NAMES, input.name.toLowerCase())) return null;
  if (isNeverCredential(hints) || ZIP_WORDS.test(hints) || PROMO_WORDS.test(hints)) return null;
  const newsletter = NEWSLETTER_WORDS.test(hints);
  const box = isCodeBox(input);
  if (OTP_STRONG_WORDS.test(hints)) return { ...NEUTRAL, box, role: "otp", certainty: 1 };
  if (box) return { ...NEUTRAL, box, role: isNumericEntry(input) ? "otp" : null };
  const length = maxLengthOf(input);
  if (
    input.type !== "email" &&
    OTP_WEAK_WORDS.test(hints) &&
    (isNumericEntry(input) || (length >= 4 && length <= 10))
  ) {
    return { ...NEUTRAL, role: "otp", certainty: 1 };
  }
  if (input.type === "number") return null;
  const username = USERNAME_WORDS.test(hints);
  if (input.type === "text" && !username && PASSWORD_WORDS.test(hints)) {
    // A password whose reveal toggle switched it to type=text.
    return secretTraits(hints, null, 0);
  }
  if (username) return { ...NEUTRAL, role: "username", certainty: 1, identity: 2, newsletter };
  if (input.type === "email" || EMAIL_WORDS.test(hints) || input.placeholder.includes("@")) {
    return { ...NEUTRAL, role: "username", certainty: 1, identity: 1, newsletter };
  }
  if (PERSONAL_WORDS.test(hints)) return null;
  return { ...NEUTRAL, newsletter };
}

function isEligible(
  input: HTMLInputElement,
  isVisible: (element: HTMLElement) => boolean,
): boolean {
  if (!Object.hasOwn(ELIGIBLE_TYPES, input.type) || input.disabled || input.readOnly) return false;
  if (input.closest("fieldset[disabled]") !== null) return false;
  for (let node: Element | null = input; node !== null; node = composedParent(node)) {
    if (node.getAttribute("aria-hidden") === "true" || node.hasAttribute("inert")) return false;
  }
  return isVisible(input);
}

function traitsOf(input: HTMLInputElement): FieldTraits | null {
  const hints = hintText(input);
  const autocomplete = autocompleteField(input);
  switch (autocomplete) {
    case "current-password":
    case "new-password":
      if (input.type === "password" || input.type === "text") {
        return secretTraits(hints, autocomplete, 2);
      }
      break;
    case "one-time-code":
      return { ...NEUTRAL, box: isCodeBox(input), role: "otp", certainty: 2 };
    case "username":
      if (input.type !== "password") {
        return { ...NEUTRAL, role: "username", certainty: 2, identity: 2 };
      }
      break;
    case "email":
      if (Object.hasOwn(TEXT_TYPES, input.type)) {
        const newsletter = NEWSLETTER_WORDS.test(hints);
        return { ...NEUTRAL, role: "username", certainty: 2, identity: 1, newsletter };
      }
      break;
    case null:
      break;
    default:
      if (
        Object.hasOwn(NON_CREDENTIAL_AUTOCOMPLETE, autocomplete) ||
        autocomplete.startsWith("cc-") ||
        autocomplete.startsWith("address-") ||
        autocomplete.startsWith("bday")
      ) {
        return null;
      }
  }
  if (input.type !== "password") return textTraits(input, hints);
  if (isNeverCredential(hints)) return null;
  if (OTP_STRONG_WORDS.test(hints)) return { ...NEUTRAL, role: "otp", certainty: 1 };
  return secretTraits(hints, null, 0);
}

// --- scanning ----------------------------------------------------------------------------------

type ScanRoot = Document | Element | ShadowRoot;

/** Inputs in document order, descending into open shadow roots at their host's position. */
function collectInputs(root: ScanRoot): HTMLInputElement[] {
  const found: HTMLInputElement[] = [];
  const stack: Element[] =
    root.nodeType === Node.ELEMENT_NODE ? [root as Element] : Array.from(root.children).reverse();
  for (let element = stack.pop(); element !== undefined; element = stack.pop()) {
    if (isInputElement(element)) found.push(element);
    const shadow = element.shadowRoot;
    // Pushed one by one, last child first: spreading a huge child list exceeds the
    // engine's argument limit and would throw.
    for (const children of [element.children, shadow?.children]) {
      if (children === undefined) continue;
      for (let i = children.length - 1; i >= 0; i -= 1) {
        const child = children.item(i);
        if (child !== null) stack.push(child);
      }
    }
  }
  return found;
}

function chainOf(input: HTMLInputElement, root: ScanRoot): Element[] {
  const chain: Element[] = [];
  for (let node: Node = input; ;) {
    const parent = node.parentNode;
    if (parent === null || parent === root) {
      if (parent === root && root.nodeType === Node.ELEMENT_NODE) chain.push(root as Element);
      break;
    }
    const next = composedParent(node);
    if (next === null) break;
    chain.push(next);
    if (next === root) break;
    node = next;
  }
  const owner = input.form;
  const formAt = owner === null ? -1 : chain.indexOf(owner);
  return formAt === -1 ? chain : chain.slice(0, formAt + 1);
}

function scan(root: ScanRoot, isVisible: (element: HTMLElement) => boolean): Field[] {
  const fields: Field[] = [];
  for (const input of collectInputs(root)) {
    if (!isEligible(input, isVisible)) continue;
    const traits = traitsOf(input);
    if (traits === null) continue;
    const chain = chainOf(input, root);
    fields.push({ ...traits, input, index: fields.length, chain, ancestors: new Set(chain) });
  }
  return fields;
}

// --- page wording ------------------------------------------------------------------------------

class Tally {
  private login = 0;
  private signup = 0;
  private change = 0;
  /** "Continue"/"Next": leans towards a login but says nothing on its own. */
  private next = 0;
  newsletter = false;

  add(raw: string, weight: number): void {
    const text = normalize(raw);
    if (text.trim() === "") return;
    if (NEWSLETTER_WORDS.test(text)) this.newsletter = true;
    if (FORGOT_WORDS.test(text)) return;
    if (LOGIN_WORDS.test(text)) this.login += weight;
    if (NEXT_WORDS.test(text)) this.next += 1;
    if (SIGNUP_WORDS.test(text)) this.signup += weight;
    if (CHANGE_WORDS.test(text)) this.change += weight;
  }

  /** The single strongest purpose; `withNext` lets "Continue" count as a login. */
  intent(withNext: boolean): Intent | null {
    const login = this.login + (withNext ? this.next : 0);
    const best = Math.max(login, this.signup, this.change);
    if (best === 0) return null;
    const winners: Intent[] = [];
    if (login === best) winners.push("login");
    if (this.signup === best) winners.push("signup");
    if (this.change === best) winners.push("change");
    return winners.length === 1 ? (winners[0] ?? null) : null;
  }
}

/** The purpose a single caption (a button label, a heading) states, if any. */
export function textIntent(raw: string): Intent | null {
  const tally = new Tally();
  tally.add(raw, 1);
  return tally.intent(true);
}

/** Everything a button says about itself: its label, value, aria-label and title. */
export function buttonText(element: Element): string {
  const value = isInputElement(element) ? element.value : textOf(element);
  const aria = element.getAttribute("aria-label") ?? "";
  return `${value} ${aria} ${element.getAttribute("title") ?? ""}`;
}

interface Context {
  readonly intent: Intent | null;
  /** The intent from explicit wording only, ignoring "Continue"/"Next". */
  readonly stated: Intent | null;
  readonly newsletter: boolean;
}

function readContext(scope: Element | ScanRoot, owner: HTMLFormElement | null): Context {
  const tally = new Tally();
  if (owner !== null) {
    for (const name of ["action", "id", "name", "class"]) {
      tally.add(owner.getAttribute(name) ?? "", 1);
    }
    tally.add(owner.getAttribute("aria-label") ?? "", 2);
  }
  for (const button of Array.from(scope.querySelectorAll(BUTTON_SELECTOR)).slice(0, 12)) {
    if (button.getAttribute("type") !== "reset") tally.add(buttonText(button), 3);
  }
  for (const heading of Array.from(scope.querySelectorAll(HEADING_SELECTOR)).slice(0, 6)) {
    tally.add(textOf(heading), 2);
  }
  if (scope.nodeType === Node.ELEMENT_NODE) {
    const element = scope as Element;
    if (element !== owner) {
      tally.add(`${element.id} ${element.getAttribute("class") ?? ""}`, 1);
      tally.add(element.getAttribute("aria-label") ?? "", 2);
    }
    // Headings commonly sit just above the form rather than inside it.
    let sibling = element.previousElementSibling;
    for (let step = 0; sibling !== null && step < 3; step += 1) {
      const heading = sibling.matches(HEADING_SELECTOR)
        ? sibling
        : sibling.querySelector(HEADING_SELECTOR);
      if (heading !== null) tally.add(textOf(heading), 2);
      sibling = sibling.previousElementSibling;
    }
  }
  return { intent: tally.intent(true), stated: tally.intent(false), newsletter: tally.newsletter };
}

/** Grows a container along `chain` until it holds a button, so the wording is in reach. */
function contextScope(chain: readonly Element[], from: number, root: ScanRoot): Element | ScanRoot {
  let at = from;
  let scope = chain.at(at);
  if (scope === undefined) return root;
  for (
    let step = 0;
    step < BUTTON_REACH && scope.querySelector(BUTTON_SELECTOR) === null;
    step += 1
  ) {
    const parent = chain.at(at + 1);
    if (parent === undefined) break;
    at += 1;
    scope = parent;
  }
  return scope;
}

// --- grouping ----------------------------------------------------------------------------------

interface Unit {
  readonly kind: "secret" | "otp" | "text";
  readonly fields: readonly Field[];
  readonly first: Field;
}

/** Whether two code boxes share a wrapper at most BOX_DISTANCE levels above each of them. */
function isNear(a: Field, b: Field): boolean {
  const up = a.chain.findIndex((element) => b.ancestors.has(element));
  const down = b.chain.findIndex((element) => a.ancestors.has(element));
  return up !== -1 && down !== -1 && up < BOX_DISTANCE && down < BOX_DISTANCE;
}

/** Folds runs of 4–8 adjacent code boxes into one unit; shorter or longer runs are dropped. */
function toUnits(pool: readonly Field[]): Unit[] {
  const units: Unit[] = [];
  let i = 0;
  for (let field = pool.at(0); field !== undefined; field = pool.at(i)) {
    if (!field.box) {
      const kind = field.secret ? "secret" : field.role === "otp" ? "otp" : "text";
      units.push({ kind, fields: [field], first: field });
      i += 1;
      continue;
    }
    const run: Field[] = [field];
    for (let next = pool.at(i + 1); next?.box === true && isNear(field, next);) {
      run.push(next);
      next = pool.at(i + run.length);
    }
    if (run.length >= 4 && run.length <= 8) units.push({ kind: "otp", fields: run, first: field });
    else if (run.length === 1 && field.role === "otp" && field.certainty > 0) {
      units.push({ kind: "otp", fields: run, first: field });
    }
    i += run.length;
  }
  return units;
}

interface Draft {
  readonly units: readonly Unit[];
  readonly chain: readonly Element[];
  readonly container: number;
}

function unitsWithin(
  units: readonly Unit[],
  assigned: ReadonlySet<Unit>,
  at: Element | undefined,
): Unit[] {
  if (at === undefined) return [];
  return units.filter((unit) => !assigned.has(unit) && unit.first.ancestors.has(at));
}

/** A run of secrets ends where a plain text field follows it: that field starts the next form. */
function segmentOf(anchor: Unit, members: readonly Unit[]): Unit[] {
  let current: Unit[] = [];
  let hasCredential = false;
  let anchored = false;
  for (const unit of members) {
    if (unit.kind === "text" && hasCredential) {
      if (anchored) break;
      current = [];
      hasCredential = false;
    }
    current.push(unit);
    if (unit.kind !== "text") hasCredential = true;
    if (unit === anchor) anchored = true;
  }
  return current;
}

/** The anchor plus every free field sharing its closest common container. */
function gather(anchor: Unit, units: readonly Unit[], assigned: ReadonlySet<Unit>): Draft {
  const chain = anchor.first.chain;
  let container = chain.findIndex((element) =>
    unitsWithin(units, assigned, element).some((unit) => unit !== anchor),
  );
  if (container === -1) container = chain.length - 1;
  let members = container < 0 ? [anchor] : unitsWithin(units, assigned, chain.at(container));
  const precedes = (unit: Unit): boolean =>
    unit.kind === "text" && unit.first.index < anchor.first.index;
  if (anchor.kind === "secret" && !members.some(precedes)) {
    // A password wrapped together with its confirmation still wants the username above them.
    const limit = Math.min(chain.length, container + 1 + USERNAME_REACH);
    for (let at = container + 1; at < limit; at += 1) {
      const wider = unitsWithin(units, assigned, chain.at(at));
      if (wider.some((unit) => unit.kind === "secret" && !members.includes(unit))) break;
      if (wider.some(precedes)) {
        container = at;
        members = wider;
        break;
      }
    }
  }
  return { units: segmentOf(anchor, members), chain, container };
}

/**
 * The username for credentials starting at document index `before`: the nearest preceding
 * field worded as one, else (unless `named` is required) the nearest preceding text field.
 */
function decideUsername(
  texts: readonly Unit[],
  before: number,
  named: boolean,
): HTMLInputElement | null {
  const preceding = texts.filter((unit) => unit.first.index < before);
  const pick =
    preceding.filter((unit) => unit.first.role === "username").at(-1) ??
    (named
      ? undefined
      : preceding.filter((unit) => Object.hasOwn(TEXT_TYPES, unit.first.input.type)).at(-1));
  return pick?.first.input ?? null;
}

interface Shape {
  readonly kind: FormKind;
  readonly password: HTMLInputElement | null;
  readonly newPasswords: readonly HTMLInputElement[];
}

function changeShape(first: Field, secrets: readonly Field[]): Shape {
  const current =
    secrets.find((field) => field.role === "current-password" && field.certainty > 0) ?? first;
  const others = secrets.filter((field) => field !== current).slice(0, 2);
  return {
    kind: "change-password",
    password: current.input,
    newPasswords: others.map((field) => field.input),
  };
}

function newOnlyShape(kind: "signup" | "change-password", secrets: readonly Field[]): Shape {
  return { kind, password: null, newPasswords: secrets.slice(0, 2).map((field) => field.input) };
}

function shapeOf(secrets: readonly Field[], context: Context, hasUsername: boolean): Shape {
  const intent = context.intent;
  const isCurrent = (field: Field): boolean =>
    field.role === "current-password" && field.certainty > 0;
  const isNew = (field: Field): boolean => field.role === "new-password" && field.certainty > 0;
  const [first, second] = secrets;
  if (first === undefined) return { kind: "otp", password: null, newPasswords: [] };
  if (secrets.length >= 3 || (secrets.some(isCurrent) && secrets.some(isNew))) {
    return changeShape(first, secrets);
  }
  // Without a username a page asking for a new password is a reset, not a registration.
  const newKind =
    intent === "change" || (!hasUsername && intent !== "signup") ? "change-password" : "signup";
  if (second !== undefined) {
    if (isCurrent(first)) return changeShape(first, secrets);
    if (intent === "change" && !second.confirm && !isNew(first)) return changeShape(first, secrets);
    return newOnlyShape(newKind, secrets);
  }
  // Sites put new-password on login forms to block autofill; only explicit wording overrides it.
  if (isNew(first) && context.stated !== "login") return newOnlyShape(newKind, secrets);
  if (!isCurrent(first) && !isNew(first) && (intent === "signup" || intent === "change")) {
    return newOnlyShape(intent === "signup" ? "signup" : "change-password", secrets);
  }
  return { kind: "login", password: first.input, newPasswords: [] };
}

function buildForm(draft: Draft, owner: HTMLFormElement | null, root: ScanRoot): LoginForm | null {
  const secrets = draft.units.filter((unit) => unit.kind === "secret").map((unit) => unit.first);
  const otpUnit = draft.units.find((unit) => unit.kind === "otp");
  const texts = draft.units.filter((unit) => unit.kind === "text");
  const firstSecret = secrets.at(0);
  const start = firstSecret ?? otpUnit?.first;
  if (start === undefined) return null;
  const otp: OtpGroup | null =
    otpUnit === undefined ? null : { inputs: otpUnit.fields.map((field) => field.input) };
  const username = decideUsername(texts, start.index, firstSecret === undefined);
  const context = readContext(contextScope(draft.chain, Math.max(draft.container, 0), root), owner);
  const shape = shapeOf(secrets, context, username !== null);
  return { form: owner, username, otp, ...shape };
}

/** A lone username field qualifies when it is named as one or the page says "sign in". */
function usernameOnly(unit: Unit, owner: HTMLFormElement | null, root: ScanRoot): LoginForm | null {
  const field = unit.first;
  if (field.role !== "username" || field.newsletter) return null;
  const context = readContext(contextScope(field.chain, 0, root), owner);
  if (context.newsletter) return null;
  if (field.identity < 2 && context.intent !== "login") return null;
  return {
    form: owner,
    kind: "username-only",
    username: field.input,
    password: null,
    newPasswords: [],
    otp: null,
  };
}

function groupPool(
  pool: readonly Field[],
  owner: HTMLFormElement | null,
  root: ScanRoot,
): [number, LoginForm][] {
  const units = toUnits(pool);
  const assigned = new Set<Unit>();
  const found: [number, LoginForm][] = [];
  for (const anchor of units) {
    if (anchor.kind === "text" || assigned.has(anchor)) continue;
    const draft = gather(anchor, units, assigned);
    for (const unit of draft.units) assigned.add(unit);
    const form = buildForm(draft, owner, root);
    const first = draft.units.at(0);
    if (form !== null && first !== undefined) found.push([first.first.index, form]);
  }
  for (const unit of units) {
    if (assigned.has(unit) || unit.kind !== "text") continue;
    const form = usernameOnly(unit, owner, root);
    if (form !== null) found.push([unit.first.index, form]);
  }
  return found;
}

/**
 * Every credential form under `root`, in document order: `<form>`s, and for formless pages the
 * fields grouped by their closest common container. Open shadow roots are searched too.
 */
export function detectForms(
  root: Document | Element | ShadowRoot,
  options: DetectOptions = {},
): LoginForm[] {
  const fields = scan(root, options.isVisible ?? defaultIsVisible);
  const pools = new Map<HTMLFormElement | null, Field[]>();
  for (const field of fields) {
    const owner = field.input.form;
    const pool = pools.get(owner);
    if (pool === undefined) pools.set(owner, [field]);
    else pool.push(field);
  }
  const found: [number, LoginForm][] = [];
  for (const [owner, pool] of pools) found.push(...groupPool(pool, owner, root));
  return found.sort((a, b) => a[0] - b[0]).map(([, form]) => form);
}

/**
 * The role `input` plays in the forms of its page, or null when it is not a credential field.
 * Classification needs the neighbours (a password after a phone field makes the phone a
 * username), so this runs `detectForms` over the input's whole document, crossing open shadow
 * boundaries.
 */
export function classifyField(
  input: HTMLInputElement,
  options: DetectOptions = {},
): FieldRole | null {
  let root = input.getRootNode();
  while (isShadowRoot(root) && root.mode === "open") root = root.host.getRootNode();
  for (const form of detectForms(root as ScanRoot, options)) {
    if (form.username === input) return "username";
    if (form.password === input) return "current-password";
    if (form.newPasswords.includes(input)) return "new-password";
    if (form.otp?.inputs.includes(input) === true) return "otp";
  }
  return null;
}
