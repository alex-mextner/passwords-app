// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Site icons without the network: a letter on a colour that stays the same for a site in the
// dropdown, the popup and across sessions (favicons would leak every page visit to a server).

/** Apple-like system colours, as gradient pairs (top, bottom). */
export const MONOGRAM_COLORS: readonly (readonly [string, string])[] = [
  ["#5e9cff", "#2f6fe0"],
  ["#4cd07d", "#249d55"],
  ["#ffb340", "#f08a00"],
  ["#ff6b6b", "#e0383e"],
  ["#bf7af0", "#8e44c9"],
  ["#5ad1d6", "#2a9fa6"],
  ["#ff7eb6", "#e04a8a"],
  ["#8e9aaf", "#5f6b80"],
];

/** FNV-1a: tiny, stable across engines, and spreads similar hosts over the palette. */
function fnv1a(text: string): number {
  let hash = 0x811c9dc5;
  for (const ch of text) {
    hash ^= ch.codePointAt(0) ?? 0;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash;
}

const NEUTRAL: readonly [string, string] = ["#8e9aaf", "#5f6b80"];

export function monogramColors(key: string): readonly [string, string] {
  return MONOGRAM_COLORS[fnv1a(key.toLowerCase()) % MONOGRAM_COLORS.length] ?? NEUTRAL;
}

/** First letter or digit of the title, else of the host; "?" when neither has one. */
export function monogramLetter(title: string, host: string): string {
  for (const text of [title, host]) {
    const match = /[\p{L}\p{N}]/u.exec(text);
    if (match !== null) return match[0].toLocaleUpperCase();
  }
  return "?";
}
