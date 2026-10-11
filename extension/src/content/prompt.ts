// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// "Save this password?" card in the page's top-right corner after a login, sign-up or
// password change. It shows the site and username only: the password stays in the background.

import type { PromptAnswer, PromptView } from "../shared/messages";
import { t } from "../shared/i18n";
import { BASE_CSS, type Overlay, createOverlay, el, monogram } from "./ui";

export interface PromptOptions {
  readonly onAnswer: (answer: PromptAnswer) => void;
  readonly isTrusted?: (event: Event) => boolean;
}

const CSS = `${BASE_CSS}
.card { width: 344px; padding: 14px 14px 12px; }
.head { display: flex; gap: 12px; align-items: flex-start; }
.text { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.title { font-size: 14px; font-weight: 600; }
.site, .user { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.body { margin-top: 6px; font-size: 12px; }
.actions { display: flex; align-items: center; gap: 8px; margin-top: 12px; }
.spacer { flex: 1; }
button {
  font: inherit; font-size: 13px; border-radius: 7px; padding: 5px 12px; cursor: default;
  border: 0.5px solid rgba(0, 0, 0, 0.18); background: #fff; color: inherit;
}
button.primary { background: #0a7aff; border-color: #0a7aff; color: #fff; font-weight: 600; }
button.link { border: none; background: none; padding: 5px 2px; color: #0a7aff; font-size: 12px; }
button:focus-visible { outline: 3px solid rgba(10, 122, 255, 0.45); outline-offset: 1px; }
@media (prefers-color-scheme: dark) {
  button { background: rgba(255, 255, 255, 0.1); border-color: rgba(255, 255, 255, 0.16); }
  button.link { color: #409cff; }
}
`;

export class SavePrompt {
  readonly overlay: Overlay;
  private answered = false;
  private readonly isTrusted: (event: Event) => boolean;
  private readonly onKey: (event: KeyboardEvent) => void;

  constructor(
    doc: Document,
    readonly view: PromptView,
    private readonly options: PromptOptions,
  ) {
    this.isTrusted = options.isTrusted ?? ((event) => event.isTrusted);
    this.overlay = createOverlay(doc, CSS, "save-prompt");
    this.overlay.host.style.left = "auto";
    this.overlay.host.style.right = "16px";
    this.overlay.host.style.top = "16px";
    const update = view.action === "update";
    const button = (label: string, answer: PromptAnswer, cls: string): HTMLElement => {
      const node = el(doc, "button", { type: "button", class: cls, "data-answer": answer }, label);
      node.addEventListener("click", (event) => {
        if (this.isTrusted(event)) this.answer(answer);
      });
      return node;
    };
    const card = el(
      doc,
      "div",
      { class: "card", role: "dialog", "aria-label": update ? t("updateTitle") : t("saveTitle") },
      el(
        doc,
        "div",
        { class: "head" },
        monogram(doc, "", view.site, 36),
        el(
          doc,
          "div",
          { class: "text" },
          el(doc, "span", { class: "title" }, update ? t("updateTitle") : t("saveTitle")),
          el(doc, "span", { class: "site secondary" }, view.host),
          view.username === "" ? null : el(doc, "span", { class: "user" }, view.username),
        ),
      ),
      el(doc, "div", { class: "body secondary" }, t("promptBody")),
      el(
        doc,
        "div",
        { class: "actions" },
        update ? null : button(t("never"), "never", "link"),
        el(doc, "span", { class: "spacer" }),
        button(t("notNow"), "not-now", "secondary-button"),
        button(update ? t("update") : t("save"), "save", "primary"),
      ),
    );
    this.overlay.root.append(card);
    this.onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && this.isTrusted(event)) this.answer("not-now");
    };
    doc.addEventListener("keydown", this.onKey, true);
  }

  get isOpen(): boolean {
    return !this.answered;
  }

  /** The buttons by answer, for tests and screenshots. */
  button(answer: PromptAnswer): HTMLButtonElement | null {
    return this.overlay.root.querySelector<HTMLButtonElement>(`button[data-answer="${answer}"]`);
  }

  /** Remove the card without answering (another prompt replaced it, or the page went away). */
  dismiss(): void {
    if (this.answered) return;
    this.answered = true;
    this.overlay.host.ownerDocument.removeEventListener("keydown", this.onKey, true);
    this.overlay.remove();
  }

  private answer(answer: PromptAnswer): void {
    if (this.answered) return;
    this.dismiss();
    this.options.onAnswer(answer);
  }
}
