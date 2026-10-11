// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Toolbar popup: the current site's saved logins with instant search, one-click fill, codes,
// and the sync state. Pure DOM rendering from a PopupState so tests need no browser.

import { t, type MessageKey } from "../shared/i18n";
import type { CandidateView, PopupState } from "../shared/messages";
import { monogramColors, monogramLetter } from "../shared/monogram";
import type { DaemonState, ErrorCode } from "../shared/protocol";

export interface PopupHandlers {
  readonly onFill: (id: string) => void;
  readonly onCode: (id: string) => void;
}

/** Case- and accent-insensitive search over title, username and host. */
export function filterItems(items: readonly CandidateView[], query: string): CandidateView[] {
  const fold = (text: string): string =>
    text.normalize("NFKD").replace(/\p{M}/gu, "").toLocaleLowerCase();
  const terms = fold(query)
    .split(/\s+/)
    .filter((term) => term !== "");
  if (terms.length === 0) return [...items];
  return items.filter((item) => {
    const haystack = fold(`${item.title} ${item.username} ${item.host}`);
    return terms.every((term) => haystack.includes(term));
  });
}

const STATE_TEXT: Readonly<Record<DaemonState, MessageKey>> = {
  idle: "stateIdle",
  syncing: "stateSyncing",
  paused: "statePaused",
  offline: "stateOffline",
  "signed-out": "stateSignedOut",
  "signin-required": "stateSigninRequired",
  error: "stateError",
};

export type StatusTone = "ok" | "busy" | "warn" | "error";

/** One line about whether autofill can work right now, and how worried to look. */
export function statusLine(
  state: DaemonState | null,
  error: ErrorCode | null,
): {
  readonly text: string;
  readonly tone: StatusTone;
} {
  if (error === "host-unavailable") return { text: t("hostUnavailable"), tone: "error" };
  if (error === "daemon-unavailable" || error === "timeout") {
    return { text: t("daemonUnavailable"), tone: "error" };
  }
  if (error === "locked") return { text: t("locked"), tone: "warn" };
  if (error === "auth-required") return { text: t("stateSignedOut"), tone: "warn" };
  // Any other failure (status answered, matching failed) must not read as healthy.
  if (state === null || error !== null) return { text: t("genericError"), tone: "error" };
  const tone: StatusTone =
    state === "idle" ? "ok" : state === "syncing" ? "busy" : state === "error" ? "error" : "warn";
  return { text: t(STATE_TEXT[state]), tone };
}

function el(doc: Document, tag: string, cls: string, text?: string): HTMLElement {
  const node = doc.createElement(tag);
  if (cls !== "") node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function row(doc: Document, item: CandidateView, handlers: PopupHandlers): HTMLElement {
  const li = el(doc, "li", "item");
  li.setAttribute("role", "option");
  li.dataset["id"] = item.id;
  const fill = el(doc, "button", "fill");
  fill.setAttribute("type", "button");
  fill.setAttribute("aria-label", `${t("fill")}: ${item.title} — ${item.username}`);
  const [top, bottom] = monogramColors(item.site || item.title);
  const icon = el(doc, "span", "monogram", monogramLetter(item.title, item.site));
  icon.setAttribute("aria-hidden", "true");
  icon.style.background = `linear-gradient(${top}, ${bottom})`;
  const text = el(doc, "span", "text");
  text.append(
    el(doc, "span", "title", item.title),
    el(doc, "span", "username", item.username === "" ? t("noUsername") : item.username),
  );
  fill.append(icon, text);
  fill.addEventListener("click", () => {
    handlers.onFill(item.id);
  });
  li.append(fill);
  if (item.hasCode) {
    const code = el(doc, "button", "code", t("fillCode"));
    code.setAttribute("type", "button");
    code.addEventListener("click", () => {
      handlers.onCode(item.id);
    });
    li.append(code);
  }
  return li;
}

/** Re-render the list part for `query`; returns how many items are shown. */
export function renderList(
  doc: Document,
  list: HTMLElement,
  empty: HTMLElement,
  state: PopupState,
  query: string,
  handlers: PopupHandlers,
): number {
  const shown = filterItems(state.items, query);
  list.replaceChildren(...shown.map((item) => row(doc, item, handlers)));
  list.hidden = shown.length === 0;
  empty.hidden = shown.length > 0;
  if (state.host === null) empty.textContent = t("notAWebPage");
  else if (state.items.length === 0) empty.textContent = t("noMatches");
  else empty.textContent = t("noResults");
  return shown.length;
}

/** Fill the static popup skeleton (popup.html) from a state. */
export function renderPopup(doc: Document, state: PopupState, handlers: PopupHandlers): void {
  const byId = (id: string): HTMLElement => {
    const node = doc.getElementById(id);
    if (node === null) throw new Error(`popup.html lacks #${id}`);
    return node;
  };
  const search = byId("search") as HTMLInputElement;
  const list = byId("list");
  const empty = byId("empty");
  byId("title").textContent = t("actionTitle");
  byId("site").textContent = state.host ?? "";
  search.placeholder = t("searchPlaceholder");
  search.setAttribute("aria-label", t("searchPlaceholder"));
  search.disabled = state.items.length === 0;
  const status = statusLine(state.state, state.error);
  const statusNode = byId("status");
  statusNode.textContent = status.text;
  statusNode.dataset["tone"] = status.tone;
  // Own clear button: Chromium draws a native one for type=search, Firefox none.
  const clear = byId("clear") as HTMLButtonElement;
  clear.setAttribute("aria-label", t("clearSearch"));
  clear.title = t("clearSearch");
  const refresh = (): void => {
    clear.hidden = search.value === "";
    renderList(doc, list, empty, state, search.value, handlers);
  };
  const reset = (): void => {
    search.value = "";
    refresh();
    search.focus();
  };
  refresh();
  search.oninput = refresh;
  clear.onclick = reset;
  search.onkeydown = (event) => {
    if (event.key === "Escape" && search.value !== "") {
      event.preventDefault(); // clear first; a second Escape closes the popup
      reset();
      return;
    }
    if (event.key !== "Enter") return;
    const first = filterItems(state.items, search.value)[0];
    if (first !== undefined) handlers.onFill(first.id);
  };
}
