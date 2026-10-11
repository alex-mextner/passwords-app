// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Everything the background decides, behind small interfaces so tests drive it without a
// browser. Security rules live here: the URL of every request is the browser-reported URL of
// the sending frame, subframes only get credentials of their top page's site, and every
// candidate passes the extension's own site check before anything is filled.

import type {
  CandidateView,
  CapturedReply,
  CodeReply,
  ContentReplies,
  ContentRequest,
  FillReply,
  PopupReplies,
  PopupRequest,
  PopupState,
  PromptAnswer,
  PromptView,
  TabCommand,
} from "../shared/messages";
import {
  type Candidate,
  type Command,
  type ErrorCode,
  ProtocolError,
  type Request,
  type ResultFor,
} from "../shared/protocol";
import { displayHost, frameAllowed, matchSite, originOf, siteName } from "../shared/site";

export interface Host {
  request<C extends Command>(request: Extract<Request, { cmd: C }>): Promise<ResultFor[C]>;
}

export interface KeyValueStore {
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown): Promise<void>;
  remove(key: string): Promise<void>;
}

/** The page tab the popup acts on; its URL comes from our content script in its top frame. */
export interface TargetTab {
  readonly id: number;
  readonly url: string;
}

export interface Browser {
  /**
   * Id of the tab the popup acts on: the active tab of the last focused window, or — when the
   * popup itself was opened as a tab (`popupTabId`) — the most recently used other tab.
   */
  targetTabId(popupTabId: number | null): Promise<number | null>;
  /** URL of the tab's top document as its content script reports it; null if none answers. */
  topUrl(tabId: number): Promise<string | null>;
  sendToTab(tabId: number, frameId: number, command: TabCommand): Promise<unknown>;
  /** Memory-only storage (cleared with the browser session) for pending save prompts. */
  readonly session: KeyValueStore;
  /** Persistent storage for preferences such as "never save on this website". */
  readonly local: KeyValueStore;
  now(): number;
}

/** Who sent a content message, as the browser reports it. */
export interface Sender {
  readonly tabId: number;
  readonly frameId: number;
  readonly url: string;
}

interface PendingSave {
  /** Names this capture; an answer from a prompt of an earlier capture must not save this one. */
  readonly captureId: string;
  /** Frame that submitted the form: the prompt is shown there, so it may answer it. */
  readonly frameId: number;
  readonly url: string;
  readonly origin: string;
  readonly username: string;
  readonly password: string;
  readonly itemId: string | null;
  readonly action: "create" | "update";
  readonly at: number;
}

/** A capture lives long enough to survive the post-login redirect chain, not much longer. */
export const PENDING_TTL_MS = 3 * 60 * 1000;
const NEVER_SAVE_KEY = "never-save";

function errorCode(error: unknown): ErrorCode {
  return error instanceof ProtocolError ? error.code : "internal";
}

function view(c: Candidate): CandidateView {
  const host = displayHost(c.url);
  return {
    id: c.id,
    title: c.title.trim() === "" ? host : c.title,
    username: c.username,
    host,
    site: siteName(c.url),
    hasCode: c.has_code,
  };
}

function isPendingSave(value: unknown): value is PendingSave {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v["captureId"] === "string" &&
    typeof v["frameId"] === "number" &&
    typeof v["url"] === "string" &&
    typeof v["origin"] === "string" &&
    typeof v["username"] === "string" &&
    typeof v["password"] === "string" &&
    (v["itemId"] === null || typeof v["itemId"] === "string") &&
    (v["action"] === "create" || v["action"] === "update") &&
    typeof v["at"] === "number"
  );
}

export class Background {
  /** Captures still being checked with the host, per tab. */
  private readonly capturing = new Map<number, Promise<CapturedReply>>();
  /** The newest capture per tab; an older one finishing later must not replace its prompt. */
  private readonly latestCapture = new Map<number, symbol>();

  constructor(
    private readonly host: Host,
    private readonly browser: Browser,
  ) {}

  async handleContent<T extends ContentRequest["type"]>(
    message: Extract<ContentRequest, { type: T }>,
    sender: Sender,
  ): Promise<ContentReplies[T]> {
    // The mapped reply type cannot be narrowed through a switch on a generic parameter.
    return (await this.dispatchContent(message, sender)) as ContentReplies[T];
  }

  async handlePopup<T extends PopupRequest["type"]>(
    message: Extract<PopupRequest, { type: T }>,
    popupTabId: number | null,
  ): Promise<PopupReplies[T]> {
    return (await this.dispatchPopup(message, popupTabId)) as PopupReplies[T];
  }

  private async dispatchContent(
    message: ContentRequest,
    sender: Sender,
  ): Promise<ContentReplies[ContentRequest["type"]]> {
    try {
      switch (message.type) {
        case "candidates":
          return { ok: true, items: await this.candidatesFor(sender) };
        case "fill":
          return { ok: true, ...(await this.fill(message.id, sender)) };
        case "code":
          return { ok: true, ...(await this.code(message.id, sender)) };
        case "captured": {
          const capture = this.captured(message, sender);
          this.capturing.set(sender.tabId, capture);
          try {
            return { ok: true, ...(await capture) };
          } finally {
            if (this.capturing.get(sender.tabId) === capture) this.capturing.delete(sender.tabId);
          }
        }
        case "pending-prompt":
          // The landing page can ask before the submitting page's capture is checked.
          await this.capturing.get(sender.tabId)?.catch(() => undefined);
          return { ok: true, prompt: await this.pendingPrompt(sender) };
        case "prompt-answer":
          return {
            ok: true,
            saved: await this.answer(message.answer, message.captureId, sender),
          };
      }
    } catch (error) {
      return { ok: false, error: errorCode(error) };
    }
  }

  private async dispatchPopup(
    message: PopupRequest,
    popupTabId: number | null,
  ): Promise<PopupReplies[PopupRequest["type"]]> {
    try {
      switch (message.type) {
        case "popup-state":
          return { ok: true, ...(await this.popupState(popupTabId)) };
        case "popup-fill":
          return { ok: true, filled: await this.popupFill(message.id, popupTabId) };
        case "popup-code":
          return { ok: true, ...(await this.popupCode(message.id, popupTabId)) };
      }
    } catch (error) {
      return { ok: false, error: errorCode(error) };
    }
  }

  // ------------------------------------------------------------------ candidates

  private async frameIsAllowed(sender: Sender): Promise<boolean> {
    if (sender.frameId === 0) return originOf(sender.url) !== null;
    const top = await this.browser.topUrl(sender.tabId);
    return top !== null && frameAllowed(sender.url, top);
  }

  /** Daemon matches that also pass the extension's own site check for `url`. */
  private async verifiedMatches(url: string): Promise<Candidate[]> {
    const { items } = await this.host.request({ cmd: "match", url });
    return items.filter((c) => matchSite(url, [c.url, ...c.alt_urls]) !== "none");
  }

  private async candidatesFor(sender: Sender): Promise<CandidateView[]> {
    if (!(await this.frameIsAllowed(sender))) return [];
    return (await this.verifiedMatches(sender.url)).map(view);
  }

  private async verifiedCandidate(id: string, url: string): Promise<Candidate> {
    const candidate = (await this.verifiedMatches(url)).find((c) => c.id === id);
    if (candidate === undefined) {
      throw new ProtocolError("not-allowed", "item is not a candidate for this page");
    }
    return candidate;
  }

  private async releaseFor(sender: Sender): Promise<string> {
    const origin = originOf(sender.url);
    if (origin === null || !(await this.frameIsAllowed(sender))) {
      throw new ProtocolError("not-allowed", "this frame may not be filled");
    }
    return origin;
  }

  private async fill(id: string, sender: Sender): Promise<FillReply> {
    const origin = await this.releaseFor(sender);
    await this.verifiedCandidate(id, sender.url);
    const secret = await this.host.request({ cmd: "fill", item_id: id, url: sender.url });
    return { origin, username: secret.username, password: secret.password };
  }

  private async code(id: string, sender: Sender): Promise<CodeReply> {
    const origin = await this.releaseFor(sender);
    await this.verifiedCandidate(id, sender.url);
    const code = await this.host.request({ cmd: "code", item_id: id, url: sender.url });
    return { origin, code: code.code, secondsLeft: code.seconds_left };
  }

  // ------------------------------------------------------------------ saving

  private pendingKey(tabId: number): string {
    return `pending:${tabId}`;
  }

  private async neverSave(): Promise<string[]> {
    const value = await this.browser.local.get(NEVER_SAVE_KEY);
    return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
  }

  private async captured(
    message: Extract<ContentRequest, { type: "captured" }>,
    sender: Sender,
  ): Promise<CapturedReply> {
    const ticket = Symbol("capture");
    this.latestCapture.set(sender.tabId, ticket);
    const origin = await this.releaseFor(sender);
    if ((await this.neverSave()).includes(origin)) return { prompt: null };
    let username = message.username;
    let itemId: string | undefined;
    if (message.filledId !== null) {
      const filled = (await this.verifiedMatches(sender.url)).find(
        (c) => c.id === message.filledId,
      );
      // A change-password form has no username field: the item it updates keeps its own.
      if (filled !== undefined && (username === "" || username === filled.username)) {
        username = filled.username;
        itemId = filled.id;
      }
    }
    const probe = await this.host.request({
      cmd: "save",
      url: sender.url,
      username,
      password: message.password,
      dry_run: true,
      ...(itemId === undefined ? {} : { item_id: itemId }),
    });
    if (this.latestCapture.get(sender.tabId) !== ticket) return { prompt: null };
    const key = this.pendingKey(sender.tabId);
    if (probe.action === "none") {
      await this.browser.session.remove(key);
      return { prompt: null };
    }
    const pending: PendingSave = {
      captureId: crypto.randomUUID(),
      frameId: sender.frameId,
      url: sender.url,
      origin,
      username,
      password: message.password,
      itemId: probe.id,
      action: probe.action,
      at: this.browser.now(),
    };
    await this.browser.session.set(key, pending);
    return { prompt: this.promptView(pending) };
  }

  private promptView(pending: PendingSave): PromptView {
    return {
      captureId: pending.captureId,
      action: pending.action,
      host: displayHost(pending.url),
      site: siteName(pending.url),
      username: pending.username,
    };
  }

  /**
   * The pending save of the sender's tab, if it is fresh and the tab is still on that site.
   * The top frame (the landing page after a login) and the frame that captured it may see it.
   */
  private async loadPending(sender: Sender): Promise<PendingSave | null> {
    const key = this.pendingKey(sender.tabId);
    const pending = await this.browser.session.get(key);
    if (!isPendingSave(pending)) return null;
    if (this.browser.now() - pending.at > PENDING_TTL_MS) {
      await this.browser.session.remove(key);
      return null;
    }
    if (sender.frameId !== 0 && sender.frameId !== pending.frameId) return null;
    if (!(await this.frameIsAllowed(sender))) return null;
    // After a login the site may redirect to another of its hosts, never to another site.
    if (matchSite(sender.url, [pending.url]) === "none") return null;
    return pending;
  }

  private async pendingPrompt(sender: Sender): Promise<PromptView | null> {
    const pending = await this.loadPending(sender);
    return pending === null ? null : this.promptView(pending);
  }

  private async answer(answer: PromptAnswer, captureId: string, sender: Sender): Promise<boolean> {
    const pending = await this.loadPending(sender);
    // A newer capture replaced the one this prompt showed: its answer is stale.
    if (pending?.captureId !== captureId) return false;
    await this.browser.session.remove(this.pendingKey(sender.tabId));
    if (answer === "never") {
      const origins = await this.neverSave();
      if (!origins.includes(pending.origin)) {
        await this.browser.local.set(NEVER_SAVE_KEY, [...origins, pending.origin]);
      }
      return false;
    }
    if (answer === "not-now") return false;
    const result = await this.host.request({
      cmd: "save",
      url: pending.url,
      username: pending.username,
      password: pending.password,
      ...(pending.action === "update" && pending.itemId !== null
        ? { item_id: pending.itemId }
        : {}),
    });
    return result.saved;
  }

  // ------------------------------------------------------------------ popup

  /** The tab the popup acts on, or null when it is not a web page our content script serves. */
  private async targetTab(popupTabId: number | null): Promise<TargetTab | null> {
    const id = await this.browser.targetTabId(popupTabId);
    if (id === null) return null;
    const url = await this.browser.topUrl(id);
    return url === null || originOf(url) === null ? null : { id, url };
  }

  private async popupState(popupTabId: number | null): Promise<PopupState> {
    const tab = await this.targetTab(popupTabId);
    let state: PopupState["state"] = null;
    let error: ErrorCode | null = null;
    try {
      state = (await this.host.request({ cmd: "status" })).state;
    } catch (e) {
      error = errorCode(e);
    }
    if (tab === null) return { host: null, state, items: [], error };
    let items: CandidateView[] = [];
    if (error === null) {
      try {
        items = (await this.verifiedMatches(tab.url)).map(view);
      } catch (e) {
        error = errorCode(e);
      }
    }
    return { host: displayHost(tab.url), state, items, error };
  }

  private async popupTarget(
    popupTabId: number | null,
  ): Promise<{ readonly tab: TargetTab; readonly origin: string }> {
    const tab = await this.targetTab(popupTabId);
    const origin = tab === null ? null : originOf(tab.url);
    if (tab === null || origin === null) {
      throw new ProtocolError("not-allowed", "the active tab is not a web page");
    }
    return { tab, origin };
  }

  private async popupFill(id: string, popupTabId: number | null): Promise<boolean> {
    const { tab, origin } = await this.popupTarget(popupTabId);
    await this.verifiedCandidate(id, tab.url);
    const secret = await this.host.request({ cmd: "fill", item_id: id, url: tab.url });
    const applied = await this.browser.sendToTab(tab.id, 0, {
      type: "apply-fill",
      origin,
      id,
      username: secret.username,
      password: secret.password,
    });
    return applied === true;
  }

  private async popupCode(
    id: string,
    popupTabId: number | null,
  ): Promise<{ code: string; secondsLeft: number }> {
    const { tab, origin } = await this.popupTarget(popupTabId);
    await this.verifiedCandidate(id, tab.url);
    const code = await this.host.request({ cmd: "code", item_id: id, url: tab.url });
    await this.browser.sendToTab(tab.id, 0, { type: "apply-code", origin, code: code.code });
    return { code: code.code, secondsLeft: code.seconds_left };
  }
}
