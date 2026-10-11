// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// UI strings come from the browser's own i18n catalog (_locales/*/messages.json) so the
// extension follows the browser language; the English catalog is the fallback where the API
// is missing (unit tests) and the source of the key type.

import en from "../../static/_locales/en/messages.json";

export type MessageKey = keyof typeof en;

function fallback(key: MessageKey, substitutions: readonly string[]): string {
  // Catalog placeholders are named ($TITLE$) and each maps to one positional substitution.
  let index = 0;
  return en[key].message.replace(/\$[A-Z_]+\$/g, () => substitutions[index++] ?? "");
}

export function t(key: MessageKey, ...substitutions: string[]): string {
  // `chrome` is absent outside the browser (unit tests); getMessage returns "" for misses.
  const text = typeof chrome === "undefined" ? "" : chrome.i18n.getMessage(key, substitutions);
  return text === "" ? fallback(key, substitutions) : text;
}
