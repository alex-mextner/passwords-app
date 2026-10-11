// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Messages between the extension's own contexts (content script, popup, background). Pages
// cannot send these: content scripts run in an isolated world and the extension exposes no
// externally_connectable surface. URLs are never part of a message from a page context; the
// background takes them from the browser's MessageSender.

import type { DaemonState, ErrorCode, SaveAction } from "./protocol";

/** What a page or the popup may show about a candidate: never a secret. */
export interface CandidateView {
  readonly id: string;
  readonly title: string;
  readonly username: string;
  readonly host: string;
  /** Registrable domain (`fabrikam.example` for `accounts.fabrikam.example`): icon key. */
  readonly site: string;
  readonly hasCode: boolean;
}

export interface PromptView {
  /** The capture this prompt shows; its answer names it so a newer capture is never saved. */
  readonly captureId: string;
  readonly action: Exclude<SaveAction, "none">;
  readonly host: string;
  readonly site: string;
  readonly username: string;
}

export type PromptAnswer = "save" | "not-now" | "never";

/** Content script → background. */
export type ContentRequest =
  | { readonly type: "candidates" }
  | { readonly type: "fill"; readonly id: string }
  | { readonly type: "code"; readonly id: string }
  | {
      readonly type: "captured";
      readonly kind: "login" | "signup" | "change-password";
      readonly username: string;
      readonly password: string;
      /** Item the page was filled from, when the user submitted what we filled or edited it. */
      readonly filledId: string | null;
    }
  | { readonly type: "pending-prompt" }
  | {
      readonly type: "prompt-answer";
      readonly answer: PromptAnswer;
      readonly captureId: string;
    };

/** Popup → background. */
export type PopupRequest =
  | { readonly type: "popup-state" }
  | { readonly type: "popup-fill"; readonly id: string }
  | { readonly type: "popup-code"; readonly id: string };

/** Background → content script (tabs.sendMessage). */
export type TabCommand =
  | {
      readonly type: "apply-fill";
      readonly origin: string;
      readonly id: string;
      readonly username: string;
      readonly password: string;
    }
  | { readonly type: "apply-code"; readonly origin: string; readonly code: string };

export interface Failure {
  readonly ok: false;
  readonly error: ErrorCode;
}

export type Reply<T> = ({ readonly ok: true } & T) | Failure;

export interface CandidatesReply {
  readonly items: readonly CandidateView[];
}

export interface FillReply {
  /** Origin the secret was released for; the content script refuses to fill anywhere else. */
  readonly origin: string;
  readonly username: string;
  readonly password: string;
}

export interface CodeReply {
  readonly origin: string;
  readonly code: string;
  readonly secondsLeft: number;
}

export interface CapturedReply {
  readonly prompt: PromptView | null;
}

export interface PopupState {
  readonly host: string | null;
  readonly state: DaemonState | null;
  readonly items: readonly CandidateView[];
  readonly error: ErrorCode | null;
}

export interface ContentReplies {
  readonly candidates: Reply<CandidatesReply>;
  readonly fill: Reply<FillReply>;
  readonly code: Reply<CodeReply>;
  readonly captured: Reply<CapturedReply>;
  readonly "pending-prompt": Reply<CapturedReply>;
  readonly "prompt-answer": Reply<{ readonly saved: boolean }>;
}

export interface PopupReplies {
  readonly "popup-state": Reply<PopupState>;
  readonly "popup-fill": Reply<{ readonly filled: boolean }>;
  readonly "popup-code": Reply<{ readonly code: string; readonly secondsLeft: number }>;
}
