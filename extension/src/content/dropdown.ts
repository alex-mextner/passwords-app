// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// The autofill menu under a credential field. Focus never leaves the page's input: the menu
// follows the input's arrow keys, Enter and Escape, and swallows mousedown so a click does not
// blur the field. Picks count only for trusted (user-generated) events, so a page script that
// synthesises clicks or key presses cannot make the extension release a password.

import type { CandidateView } from "../shared/messages";
import { t } from "../shared/i18n";
import { BASE_CSS, type Overlay, createOverlay, el, keyIcon, monogram } from "./ui";

export type DropdownEntry =
  | { readonly kind: "login"; readonly candidate: CandidateView }
  | { readonly kind: "code"; readonly candidate: CandidateView }
  | { readonly kind: "generate"; readonly password: string };

export interface DropdownOptions {
  readonly onPick: (entry: DropdownEntry) => void;
  readonly onClose?: () => void;
  /** Real browsers: `event.isTrusted`. Unit tests replace it because happy-dom's events are not. */
  readonly isTrusted?: (event: Event) => boolean;
  /** Box to place the menu under; defaults to the anchor's (split code boxes pass the row). */
  readonly anchorRect?: () => DOMRect;
}

const WIDTH_MIN = 280;
const WIDTH_MAX = 380;
const GAP = 4;

const CSS = `${BASE_CSS}
.card { padding: 5px; min-width: ${WIDTH_MIN}px; max-height: 320px; overflow-y: auto; }
.row {
  display: flex; align-items: center; gap: 10px; padding: 6px 8px; border-radius: 7px;
  cursor: default; user-select: none;
}
.row[aria-selected="true"] { background: #0a7aff; color: #fff; }
.row[aria-selected="true"] .secondary { color: rgba(255, 255, 255, 0.86); }
.text { display: flex; flex-direction: column; min-width: 0; }
.title, .subtitle { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.title { font-weight: 600; }
.subtitle { font-size: 12px; }
.mono { font-family: ui-monospace, "SF Mono", "DejaVu Sans Mono", monospace; letter-spacing: 0.02em; }
.key {
  display: inline-flex; align-items: center; justify-content: center; flex: none;
  width: 28px; height: 28px; border-radius: 22%;
  background: linear-gradient(#ffcf4a, #f0a30a);
  box-shadow: inset 0 0 0 0.5px rgba(0, 0, 0, 0.12);
}
.separator { height: 1px; margin: 4px 8px; background: rgba(0, 0, 0, 0.1); }
@media (prefers-color-scheme: dark) { .separator { background: rgba(255, 255, 255, 0.12); } }
`;

function entryKey(entry: DropdownEntry): string {
  return entry.kind === "generate" ? "generate" : `${entry.kind}:${entry.candidate.id}`;
}

export class Dropdown {
  readonly overlay: Overlay;
  private readonly rowElements: HTMLElement[] = [];
  private active = 0;
  private closed = false;
  private readonly isTrusted: (event: Event) => boolean;
  private readonly cleanups: (() => void)[] = [];

  constructor(
    private readonly anchor: HTMLInputElement,
    readonly entries: readonly DropdownEntry[],
    private readonly options: DropdownOptions,
  ) {
    const doc = anchor.ownerDocument;
    this.isTrusted = options.isTrusted ?? ((event) => event.isTrusted);
    this.overlay = createOverlay(doc, CSS, "dropdown");
    const card = el(doc, "div", {
      class: "card",
      role: "listbox",
      "aria-label": t("dropdownLabel"),
    });
    entries.forEach((entry, index) => {
      if (entry.kind === "generate" && index > 0)
        card.append(el(doc, "div", { class: "separator" }));
      const row = this.renderRow(doc, entry, index);
      this.rowElements.push(row);
      card.append(row);
    });
    this.overlay.root.append(card);
    this.highlight(0);
    this.listen();
    this.position();
  }

  get activeIndex(): number {
    return this.active;
  }

  get isOpen(): boolean {
    return !this.closed;
  }

  /** The rendered rows, in order (for tests and screenshots; pages cannot reach them). */
  rows(): readonly HTMLElement[] {
    return this.rowElements;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const cleanup of this.cleanups.splice(0)) cleanup();
    this.overlay.remove();
    this.options.onClose?.();
  }

  /** Place the menu under the field, or above it when the viewport has no room below. */
  position(): void {
    const view = this.anchor.ownerDocument.defaultView;
    const rect = this.options.anchorRect?.() ?? this.anchor.getBoundingClientRect();
    const width = Math.min(WIDTH_MAX, Math.max(WIDTH_MIN, rect.width));
    const height = this.overlay.host.getBoundingClientRect().height;
    const viewportHeight = view?.innerHeight ?? 0;
    const viewportWidth = view?.innerWidth ?? 0;
    const below = rect.bottom + GAP;
    const top =
      below + height > viewportHeight && rect.top - GAP - height > 0
        ? rect.top - GAP - height
        : below;
    const left = Math.max(GAP, Math.min(rect.left, viewportWidth - width - GAP));
    const style = this.overlay.host.style;
    style.top = `${Math.round(top)}px`;
    style.left = `${Math.round(left)}px`;
    style.width = `${Math.round(width)}px`;
  }

  private renderRow(doc: Document, entry: DropdownEntry, index: number): HTMLElement {
    let icon: HTMLElement;
    let title: string;
    let subtitle: HTMLElement;
    if (entry.kind === "generate") {
      icon = el(doc, "span", { class: "key", "aria-hidden": "true" }, keyIcon(doc));
      title = t("useStrongPassword");
      subtitle = el(doc, "span", { class: "subtitle secondary mono" }, entry.password);
    } else {
      const c = entry.candidate;
      icon = monogram(doc, c.title, c.site);
      if (entry.kind === "code") {
        title = t("verificationCode");
        subtitle = el(doc, "span", { class: "subtitle secondary" }, t("codeFrom", c.title));
      } else {
        title = c.title;
        subtitle = el(
          doc,
          "span",
          { class: "subtitle secondary" },
          c.username === "" ? t("noUsername") : c.username,
        );
      }
    }
    const row = el(
      doc,
      "div",
      { class: "row", role: "option", "aria-selected": "false", "data-entry": entryKey(entry) },
      icon,
      el(doc, "span", { class: "text" }, el(doc, "span", { class: "title" }, title), subtitle),
    );
    row.addEventListener("mousedown", (event) => {
      event.preventDefault(); // keep focus (and the caret) in the page's field
    });
    row.addEventListener("mousemove", () => {
      if (index !== this.active) this.highlight(index);
    });
    row.addEventListener("click", (event) => {
      if (this.isTrusted(event)) this.pick(index);
    });
    return row;
  }

  private highlight(index: number): void {
    if (this.rowElements.length === 0) return;
    const count = this.rowElements.length;
    this.active = ((index % count) + count) % count;
    this.rowElements.forEach((row, i) => {
      row.setAttribute("aria-selected", i === this.active ? "true" : "false");
    });
    this.rowElements[this.active]?.scrollIntoView({ block: "nearest" });
  }

  private pick(index: number): void {
    const entry = this.entries[index];
    if (entry === undefined || this.closed) return;
    this.close();
    this.options.onPick(entry);
  }

  /** Whether Enter in `field` picks from this menu instead of submitting the page's form. */
  consumesEnter(field: EventTarget | null): boolean {
    return !this.closed && field === this.anchor;
  }

  /** React to a key pressed in the anchor field; true when the menu consumed it. */
  handleKey(event: KeyboardEvent): boolean {
    if (this.closed) return false;
    switch (event.key) {
      case "ArrowDown":
        this.highlight(this.active + 1);
        return true;
      case "ArrowUp":
        this.highlight(this.active - 1);
        return true;
      case "Home":
        this.highlight(0);
        return true;
      case "End":
        this.highlight(this.rowElements.length - 1);
        return true;
      case "Enter":
        // Enter that confirms an IME composition belongs to the input method.
        if (!this.isTrusted(event) || event.isComposing) return false;
        this.pick(this.active);
        return true;
      case "Escape":
        this.close();
        return true;
      case "Tab":
        this.close();
        return false; // let focus move on as usual
      default:
        return false;
    }
  }

  private listen(): void {
    const doc = this.anchor.ownerDocument;
    const view = doc.defaultView;
    // composedPath()[0], not target: a document listener sees a shadow-root field's events
    // retargeted to its host.
    const onKey = (event: Event): void => {
      if (event.composedPath()[0] !== this.anchor || !(event instanceof KeyboardEvent)) return;
      if (this.handleKey(event)) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
    };
    // Scroll fires per scroller and per frame; one layout read/write per animation frame.
    let frame: number | null = null;
    const onReposition = (): void => {
      if (frame !== null || view === null) return;
      frame = view.requestAnimationFrame(() => {
        frame = null;
        if (!this.anchor.isConnected) this.close();
        else if (!this.closed) this.position();
      });
    };
    this.cleanups.push(() => {
      if (frame !== null) view?.cancelAnimationFrame(frame);
    });
    const onPointer = (event: Event): void => {
      const path = event.composedPath();
      if (!path.includes(this.overlay.host) && !path.includes(this.anchor)) this.close();
    };
    const onAnchorEvent = (event: Event): void => {
      // Leaving the field, or typing into it by hand, means the user is not picking from us.
      const fromAnchor = event.composedPath()[0] === this.anchor;
      if (fromAnchor && (event.type === "focusout" || this.isTrusted(event))) {
        this.close();
      }
    };
    // Capture phase on the document runs before the page's own handlers on the field.
    const listeners: [EventTarget | null, string, (event: Event) => void, boolean][] = [
      [doc, "keydown", onKey, true],
      [doc, "pointerdown", onPointer, true],
      [doc, "focusout", onAnchorEvent, true],
      [doc, "input", onAnchorEvent, true],
      [view, "scroll", onReposition, true],
      [view, "resize", onReposition, false],
    ];
    for (const [target, type, listener, capture] of listeners) {
      target?.addEventListener(type, listener, capture);
      this.cleanups.push(() => {
        target?.removeEventListener(type, listener, capture);
      });
    }
  }
}
