// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Content script entry. Runs in every http(s) frame, in the extension's isolated world: it
// finds credential fields, shows the dropdown when one gets focus, fills only after a trusted
// pick and only into the origin the background released the secret for, and reports submitted
// logins so the background can offer to save them.

import type {
  CandidateView,
  ContentReplies,
  ContentRequest,
  PromptAnswer,
  PromptView,
  TabCommand,
} from "../shared/messages";
import { detectForms } from "./detect";
import { Dropdown, type DropdownEntry } from "./dropdown";
import { fillLogin, fillNewPassword, fillOtp } from "./fill";
import { applePassword } from "./generator";
import { SavePrompt } from "./prompt";
import { observeSubmissions, shouldOffer } from "./submit";
import type { CapturedLogin, FieldRole, LastFill, LoginForm } from "./types";

/** Candidates are fetched once per focus burst, not on every keystroke or refocus. */
const CANDIDATE_TTL_MS = 30_000;
const RESCAN_DELAY_MS = 250;

interface Located {
  readonly form: LoginForm;
  readonly role: FieldRole;
}

function send<T extends ContentRequest["type"]>(
  message: Extract<ContentRequest, { type: T }>,
): Promise<ContentReplies[T] | undefined> {
  return chrome.runtime
    .sendMessage<ContentRequest, ContentReplies[T]>(message)
    .catch(() => undefined);
}

/** The focused element, looking inside open shadow roots (custom-element login forms). */
function deepActiveElement(doc: Document): Element | null {
  let active = doc.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  return active;
}

/** Our own overlays move and restyle themselves; that is never a reason to rescan the page. */
function isOwnMutation(record: MutationRecord): boolean {
  const node = record.target instanceof Element ? record.target : record.target.parentElement;
  return node?.closest("[data-passwords-app]") != null;
}

/** Smallest box around all `elements` (the row of split one-time-code boxes). */
function unionRect(elements: readonly HTMLElement[]): DOMRect {
  const rects = elements.map((e) => e.getBoundingClientRect());
  const left = Math.min(...rects.map((r) => r.left));
  const top = Math.min(...rects.map((r) => r.top));
  const right = Math.max(...rects.map((r) => r.right));
  const bottom = Math.max(...rects.map((r) => r.bottom));
  return new DOMRect(left, top, right - left, bottom - top);
}

class ContentScript {
  private forms: LoginForm[] = [];
  private candidates: { readonly items: readonly CandidateView[]; readonly at: number } | null =
    null;
  private lastFill: LastFill | null = null;
  private dropdown: Dropdown | null = null;
  private prompt: SavePrompt | null = null;
  private rescanTimer: number | null = null;
  private opening: HTMLInputElement | null = null;

  constructor(private readonly doc: Document) {}

  start(): void {
    this.rescan();
    new MutationObserver((records) => {
      if (!records.every(isOwnMutation)) this.scheduleRescan();
    }).observe(this.doc.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["type", "autocomplete", "hidden", "style", "class"],
    });
    this.doc.addEventListener(
      "focusin",
      (event) => {
        void this.onFocus(event);
      },
      true,
    );
    this.doc.addEventListener(
      "click",
      (event) => {
        // Clicking a field that already has focus reopens a dismissed menu.
        if (event.isTrusted && event.composedPath()[0] === deepActiveElement(this.doc)) {
          void this.onFocus(event);
        }
      },
      true,
    );
    observeSubmissions(
      this.doc,
      () => this.forms,
      (captured) => {
        if (shouldOffer(captured, this.lastFill)) void this.reportCapture(captured);
      },
      { enterConsumed: (field) => this.dropdown?.consumesEnter(field) === true },
    );
    chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
      if (sender.id !== chrome.runtime.id) return false;
      const reply = this.onCommand(message);
      if (reply === undefined) return false;
      sendResponse(reply);
      return false;
    });
    // The top frame shows the prompt after a login navigated the page; a frame that submitted
    // and navigated on its own asks too (the background only answers the frame that captured).
    void this.showPendingPrompt();
  }

  // ------------------------------------------------------------------ detection

  private rescan(): void {
    this.forms = detectForms(this.doc);
  }

  private scheduleRescan(): void {
    if (this.rescanTimer !== null) return;
    this.rescanTimer = window.setTimeout(() => {
      this.rescanTimer = null;
      this.rescan();
    }, RESCAN_DELAY_MS);
  }

  private locate(input: HTMLInputElement): Located | null {
    for (const form of this.forms) {
      if (form.username === input) return { form, role: "username" };
      if (form.password === input) return { form, role: "current-password" };
      if (form.newPasswords.includes(input)) return { form, role: "new-password" };
      if (form.otp?.inputs.includes(input) === true) return { form, role: "otp" };
    }
    return null;
  }

  // ------------------------------------------------------------------ dropdown

  private async candidateList(): Promise<readonly CandidateView[]> {
    if (this.candidates !== null && Date.now() - this.candidates.at < CANDIDATE_TTL_MS) {
      return this.candidates.items;
    }
    const reply = await send({ type: "candidates" });
    const items = reply?.ok === true ? reply.items : [];
    this.candidates = { items, at: Date.now() };
    return items;
  }

  private async onFocus(event: Event): Promise<void> {
    if (!event.isTrusted) return;
    const target = event.composedPath()[0];
    if (!(target instanceof HTMLInputElement)) return;
    let located = this.locate(target);
    if (located === null) {
      this.rescan();
      located = this.locate(target);
    }
    // focusin and the click that caused it arrive together; open one menu, not two.
    if (located === null || this.dropdown !== null || this.opening === target) return;
    this.opening = target;
    const valueBefore = target.value;
    let entries: DropdownEntry[];
    try {
      entries = await this.entriesFor(located);
    } finally {
      this.opening = null;
    }
    // The user may have moved on or started typing while the background answered, or another
    // focus event may have opened a menu meanwhile (invisible to the checker across the await).
    if (
      entries.length === 0 ||
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
      this.dropdown !== null ||
      target.value !== valueBefore ||
      deepActiveElement(this.doc) !== target
    ) {
      return;
    }
    const { form, role } = located;
    const boxes = role === "otp" ? (form.otp?.inputs ?? []) : [];
    this.dropdown = new Dropdown(target, entries, {
      onPick: (entry) => {
        void this.onPick(form, entry);
      },
      onClose: () => {
        this.dropdown = null;
      },
      // Split code boxes read as one field: the menu spans the whole row.
      ...(boxes.length > 1 ? { anchorRect: () => unionRect(boxes) } : {}),
    });
  }

  private async entriesFor({ form, role }: Located): Promise<DropdownEntry[]> {
    if (role === "new-password") {
      // Offer a generated password only where the page creates or changes one.
      return form.newPasswords[0] === undefined
        ? []
        : [{ kind: "generate", password: applePassword() }];
    }
    const items = await this.candidateList();
    if (role === "otp") {
      return items
        .filter((c) => c.hasCode)
        .map((candidate) => ({ kind: "code" as const, candidate }));
    }
    return items.map((candidate) => ({ kind: "login" as const, candidate }));
  }

  private async onPick(form: LoginForm, entry: DropdownEntry): Promise<void> {
    if (entry.kind === "generate") {
      fillNewPassword(form, entry.password);
      return;
    }
    if (entry.kind === "code") {
      const reply = await send({ type: "code", id: entry.candidate.id });
      if (reply?.ok === true && form.otp !== null && reply.origin === location.origin) {
        fillOtp(form.otp, reply.code);
      }
      return;
    }
    const reply = await send({ type: "fill", id: entry.candidate.id });
    // The secret was released for one origin; if this frame navigated since, drop it.
    if (reply?.ok !== true || reply.origin !== location.origin) return;
    fillLogin(form, { username: reply.username, password: reply.password });
    this.lastFill = { id: entry.candidate.id, username: reply.username, password: reply.password };
  }

  // ------------------------------------------------------------------ popup commands

  private focusedForm(): LoginForm | null {
    const focused = deepActiveElement(this.doc);
    return focused instanceof HTMLInputElement ? (this.locate(focused)?.form ?? null) : null;
  }

  /** Where a saved login goes: the focused form when it has login fields, else the first. */
  private bestForm(): LoginForm | null {
    this.rescan();
    const fillable = (f: LoginForm): boolean => f.password !== null || f.username !== null;
    const focused = this.focusedForm();
    if (focused !== null && fillable(focused)) return focused;
    // A sign-up form (new-password fields only) has nothing a saved login can fill.
    return this.forms.find(fillable) ?? null;
  }

  private onCommand(message: unknown): unknown {
    if (typeof message !== "object" || message === null || !("type" in message)) return undefined;
    if (message.type === "top-url") return window === window.top ? location.href : undefined;
    if (message.type !== "apply-fill" && message.type !== "apply-code") return undefined;
    // Only our own background reaches this listener (sender.id was checked by the caller).
    const command = message as TabCommand;
    if (command.origin !== location.origin) return false;
    if (command.type === "apply-code") {
      this.rescan();
      // The focused form's code boxes first, else the page's only/first code field.
      const group =
        this.focusedForm()?.otp ?? this.forms.find((f) => f.otp !== null)?.otp ?? null;
      if (group === null) return false;
      fillOtp(group, command.code);
      return true;
    }
    const form = this.bestForm();
    if (form === null) return false;
    fillLogin(form, { username: command.username, password: command.password });
    this.lastFill = { id: command.id, username: command.username, password: command.password };
    return true;
  }

  // ------------------------------------------------------------------ saving

  private async reportCapture(captured: CapturedLogin): Promise<void> {
    const reply = await send({
      type: "captured",
      kind: captured.kind,
      username: captured.username,
      password: captured.password,
      filledId: this.lastFill?.id ?? null,
    });
    if (reply?.ok === true && reply.prompt !== null) this.showPrompt(reply.prompt);
  }

  private async showPendingPrompt(): Promise<void> {
    const reply = await send({ type: "pending-prompt" });
    if (reply?.ok === true && reply.prompt !== null) this.showPrompt(reply.prompt);
  }

  private showPrompt(view: PromptView): void {
    this.prompt?.dismiss();
    this.prompt = new SavePrompt(this.doc, view, {
      onAnswer: (answer: PromptAnswer) => {
        void send({ type: "prompt-answer", answer, captureId: view.captureId });
      },
    });
  }
}

new ContentScript(document).start();
