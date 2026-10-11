// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { MONOGRAM_COLORS, monogramColors, monogramLetter } from "../src/shared/monogram";

describe("monogramLetter", () => {
  test.each([
    ["Northwind", "northwind.example", "N"],
    ["", "mail.example.com", "M"],
    ["  ", "example.com", "E"],
    ["«Почта»", "", "П"],
    ["ąbc", "", "Ą"],
    ["123 Bank", "", "1"],
    ["—", "—", "?"],
    ["", "", "?"],
  ] as const)("%j / %j → %s", (title, host, expected) => {
    expect(monogramLetter(title, host)).toBe(expected);
  });
});

describe("monogramColors", () => {
  test("stable for the same key, case-insensitively", () => {
    expect(monogramColors("Example.com")).toEqual(monogramColors("example.com"));
  });

  test("always a palette entry", () => {
    for (const key of ["", "a", "example.com", "пример.рф", "x".repeat(500)]) {
      expect(MONOGRAM_COLORS).toContainEqual(monogramColors(key));
    }
  });

  test("spreads different sites over the palette", () => {
    const hosts = Array.from({ length: 64 }, (_, i) => `site${i}.example`);
    const used = new Set(hosts.map((h) => monogramColors(h)[0]));
    expect(used.size).toBeGreaterThanOrEqual(MONOGRAM_COLORS.length - 1);
  });
});
