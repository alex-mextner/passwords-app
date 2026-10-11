// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Shapes shared by the page-side modules: what detection finds, what a submit captures.

export type FieldRole = "username" | "current-password" | "new-password" | "otp";

/** One-time-code inputs in visual order: one input for a plain field, 4–8 for split boxes. */
export interface OtpGroup {
  readonly inputs: readonly HTMLInputElement[];
}

export type FormKind = "login" | "signup" | "change-password" | "otp" | "username-only";

/**
 * A group of credential fields that belong together: a <form>, or for formless pages the
 * fields that share their closest common container.
 */
export interface LoginForm {
  readonly form: HTMLFormElement | null;
  readonly kind: FormKind;
  readonly username: HTMLInputElement | null;
  readonly password: HTMLInputElement | null;
  /** New password first, then its confirmation, when the page asks for one twice. */
  readonly newPasswords: readonly HTMLInputElement[];
  readonly otp: OtpGroup | null;
}

/** What the user submitted, read at submit time. */
export interface CapturedLogin {
  readonly kind: "login" | "signup" | "change-password";
  readonly username: string;
  readonly password: string;
}

/** The candidate this page was last filled from, if any. */
export interface LastFill {
  readonly id: string;
  readonly username: string;
  readonly password: string;
}

export interface DetectOptions {
  /** Layout-dependent visibility check; tests inject one because happy-dom has no layout. */
  readonly isVisible?: (element: HTMLElement) => boolean;
}
