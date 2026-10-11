// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import {
  type MatchKind,
  displayHost,
  frameAllowed,
  matchSite,
  originOf,
  parseWebUrl,
  registrableDomain,
  siteName,
} from "../src/shared/site";
import cases from "./fixtures/site-match-cases.json";

interface Case {
  readonly page: string;
  readonly url: string;
  readonly alt: readonly string[];
  readonly expected: MatchKind;
}

// Exported verbatim from the daemon's tests (tests/unit/core/test_urls.py, MATCH_CASES) so the
// extension's independent second check agrees with core/urls.py case by case.
const table = cases as Case[];

describe("matchSite agrees with the daemon's match table", () => {
  test.each(table.map((c) => [c.page, c.url, c.alt, c.expected] as const))(
    "%s vs %s %j → %s",
    (page, url, alt, expected) => {
      expect(matchSite(page, [url, ...alt])).toBe(expected);
    },
  );

  test("the shared table covers every outcome, lookalikes and downgrades", () => {
    const kinds = new Set(table.map((c) => c.expected));
    expect(kinds).toEqual(new Set<MatchKind>(["exact-host", "same-site", "none"]));
    expect(table.some((c) => c.page.startsWith("http://") && c.url.startsWith("https://"))).toBe(
      true,
    );
  });
});

describe("frameAllowed", () => {
  test.each([
    ["https://accounts.example.com/frame", "https://www.example.com/", true],
    ["https://example.com/", "https://example.com/", true],
    ["https://login.example.co.uk/", "https://shop.example.co.uk/", true],
    ["https://evil.example/", "https://example.com/", false],
    ["https://example.com.evil.example/", "https://example.com/", false],
    ["http://example.com/", "https://example.com/", false],
    ["https://example.com/", "http://example.com/", true],
    ["https://a.github.io/", "https://b.github.io/", false],
    ["https://192.0.2.1/", "https://192.0.2.1/", true],
    ["https://192.0.2.1/", "https://192.0.2.2/", false],
    ["about:blank", "https://example.com/", false],
    ["https://example.com/", "file:///etc/passwd", false],
  ] as const)("frame %s in top %s → %p", (frame, top, expected) => {
    expect(frameAllowed(frame, top)).toBe(expected);
  });
});

describe("originOf", () => {
  test.each([
    ["https://example.com/login?next=/x#top", "https://example.com"],
    ["https://Example.COM:443/", "https://example.com"],
    ["http://example.com:8080/a", "http://example.com:8080"],
    ["https://[2001:db8::1]:8443/", "https://[2001:db8::1]:8443"],
    ["https://user:secret@example.com/", "https://example.com"],
    // location.origin keeps a trailing-dot host; fill replies are compared with it verbatim.
    ["https://example.com./login", "https://example.com."],
    ["example.com/login", "https://example.com"],
    ["ftp://example.com/", null],
    ["javascript:alert(1)", null],
    ["https://", null],
    ["", null],
  ] as const)("%s → %s", (raw, expected) => {
    expect(originOf(raw)).toBe(expected);
  });
});

describe("parseWebUrl", () => {
  test.each([
    "https://a..example.com/",
    "https://.example.com/",
    "https://0x7f.0.0.1/",
    "https://127.1/",
    "data:text/html,hi",
    "chrome-extension://abc/popup.html",
    "moz-extension://abc/popup.html",
  ])("rejects %s", (raw) => {
    expect(parseWebUrl(raw)).toBeNull();
  });

  test("keeps explicit non-default ports and drops default ones", () => {
    expect(parseWebUrl("https://example.com:8443")?.port).toBe(8443);
    expect(parseWebUrl("https://example.com:443")?.port).toBeNull();
    expect(parseWebUrl("http://example.com:80")?.port).toBeNull();
  });

  test("reads IDN hosts as punycode and marks IP literals", () => {
    expect(parseWebUrl("https://пример.рф/")?.host).toBe("xn--e1afmkfd.xn--p1ai");
    expect(parseWebUrl("https://192.0.2.7/")?.isIp).toBe(true);
    expect(parseWebUrl("https://[::1]/")?.isIp).toBe(true);
    expect(parseWebUrl("https://example.com/")?.isIp).toBe(false);
  });
});

describe("registrableDomain", () => {
  test.each([
    ["login.example.com", "example.com"],
    ["a.b.example.co.uk", "example.co.uk"],
    ["alex.github.io", "alex.github.io"],
    ["github.io", null],
    ["com", null],
    ["192.0.2.1", null],
  ] as const)("%s → %s", (host, expected) => {
    expect(registrableDomain(host)).toBe(expected);
  });
});

describe("displayHost", () => {
  test.each([
    ["https://www.example.com/login", "example.com"],
    ["https://mail.example.com", "mail.example.com"],
    ["not a url at all", "not a url at all"],
  ] as const)("%s → %s", (raw, expected) => {
    expect(displayHost(raw)).toBe(expected);
  });
});

describe("siteName", () => {
  test.each([
    ["https://accounts.fabrikam.example/login", "fabrikam.example"],
    ["https://www.example.co.uk/", "example.co.uk"],
    ["https://alex.github.io/", "alex.github.io"],
    ["https://192.0.2.1:8443/", "192.0.2.1"],
    // Unknown TLDs follow the PSL default rule: the last label is the suffix.
    ["https://wiki.intranet/", "wiki.intranet"],
    ["not a url", "not a url"],
  ] as const)("%s → %s", (raw, expected) => {
    expect(siteName(raw)).toBe(expected);
  });
});
