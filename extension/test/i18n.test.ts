// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { t } from "../src/shared/i18n";

const LOCALES = join(import.meta.dir, "..", "static", "_locales");

interface Entry {
  readonly message: string;
  readonly placeholders?: Record<string, { readonly content: string }>;
}

function catalog(locale: string): Record<string, Entry> {
  return JSON.parse(readFileSync(join(LOCALES, locale, "messages.json"), "utf8")) as Record<
    string,
    Entry
  >;
}

const en = catalog("en");

describe("catalogs", () => {
  const locales = readdirSync(LOCALES);

  test("English and Russian are shipped", () => {
    expect(locales.sort()).toEqual(["en", "ru"]);
  });

  test.each(locales.filter((l) => l !== "en"))("%s has exactly the English keys", (locale) => {
    expect(Object.keys(catalog(locale)).sort()).toEqual(Object.keys(en).sort());
  });

  test.each(locales)("%s placeholders are declared where used", (locale) => {
    for (const [key, entry] of Object.entries(catalog(locale))) {
      const used = [...entry.message.matchAll(/\$([A-Z_]+)\$/g)].map((m) => m[1]?.toLowerCase());
      const declared = Object.keys(entry.placeholders ?? {});
      expect({ key, used: used.sort() }).toEqual({ key, used: declared.sort() });
    }
  });

  test.each(locales)("%s keeps manifest strings within store limits", (locale) => {
    const c = catalog(locale);
    expect(c["extName"]?.message.length).toBeLessThanOrEqual(45);
    expect(c["extDescription"]?.message.length).toBeLessThanOrEqual(132);
  });

  test("user-facing text never says escrow", () => {
    for (const locale of locales)
      expect(JSON.stringify(catalog(locale)).toLowerCase()).not.toContain("escrow");
  });
});

describe("t()", () => {
  test("falls back to English outside the browser", () => {
    expect(t("save")).toBe("Save");
  });

  test("fills positional substitutions into named placeholders", () => {
    expect(t("codeFrom", "Northwind")).toBe("From Northwind");
    expect(t("secondsLeft", "17")).toBe("17 s");
  });

  test("missing substitutions leave the placeholder empty, not literal", () => {
    expect(t("codeFrom")).toBe("From ");
  });
});
