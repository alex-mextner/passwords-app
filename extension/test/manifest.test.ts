// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import {
  CHROME_ID,
  CHROME_PUBLIC_KEY,
  EXTENSION_PAGES_CSP,
  FIREFOX_ID,
  manifestFor,
} from "../src/manifest";
import { HOST_NAME } from "../src/shared/protocol";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** Chrome's id derivation: SHA-256 of the DER public key, first 32 hex digits mapped to a–p. */
function chromeIdFor(base64Key: string): string {
  const hex = createHash("sha256")
    .update(Buffer.from(base64Key, "base64"))
    .digest("hex")
    .slice(0, 32);
  return hex.replace(/[0-9a-f]/g, (c) => String.fromCharCode(97 + parseInt(c, 16)));
}

const firefox = manifestFor("firefox");
const chrome = manifestFor("chrome");

describe("manifests", () => {
  test.each([
    ["firefox", firefox],
    ["chrome", chrome],
  ] as const)("%s asks only for nativeMessaging and storage", (_name, m) => {
    expect(m["permissions"]).toEqual(["nativeMessaging", "storage"]);
    expect(m).not.toHaveProperty("host_permissions");
    expect(m).not.toHaveProperty("optional_permissions");
    expect(m).not.toHaveProperty("externally_connectable");
    expect(m).not.toHaveProperty("web_accessible_resources");
    expect(m["manifest_version"]).toBe(3);
  });

  test.each([
    ["firefox", firefox],
    ["chrome", chrome],
  ] as const)("%s content script runs on web pages in every frame only", (_name, m) => {
    expect(m["content_scripts"]).toEqual([
      {
        matches: ["http://*/*", "https://*/*"],
        js: ["content.js"],
        all_frames: true,
        run_at: "document_end",
      },
    ]);
  });

  test("extension pages forbid remote and inline code", () => {
    expect(EXTENSION_PAGES_CSP).toContain("script-src 'self'");
    expect(EXTENSION_PAGES_CSP).toContain("object-src 'none'");
    expect(EXTENSION_PAGES_CSP).not.toContain("unsafe");
    expect(firefox["content_security_policy"]).toEqual({ extension_pages: EXTENSION_PAGES_CSP });
    expect(chrome["content_security_policy"]).toEqual({ extension_pages: EXTENSION_PAGES_CSP });
  });

  test("Firefox has the fixed add-on id and declares no data collection", () => {
    expect(firefox["browser_specific_settings"]).toEqual({
      gecko: {
        id: FIREFOX_ID,
        strict_min_version: "142.0",
        data_collection_permissions: { required: ["none"] },
      },
    });
    expect(firefox["background"]).toEqual({ scripts: ["background.js"] });
    expect(firefox).not.toHaveProperty("key");
  });

  test("Chrome's pinned key yields the id the native host manifest allows", () => {
    expect(chrome["key"]).toBe(CHROME_PUBLIC_KEY);
    expect(chromeIdFor(CHROME_PUBLIC_KEY)).toBe(CHROME_ID);
    expect(chrome["background"]).toEqual({ service_worker: "background.js" });
  });

  test("the pinned key is a public key only", () => {
    const der = Buffer.from(CHROME_PUBLIC_KEY, "base64");
    expect(der.length).toBeLessThan(400); // an RSA-2048 SubjectPublicKeyInfo is 294 bytes
    expect(CHROME_PUBLIC_KEY).not.toContain("PRIVATE");
  });

  test("native host templates name this extension and this host", () => {
    const root = join(import.meta.dir, "..", "..", "data", "native-messaging");
    const ff = JSON.parse(readFileSync(join(root, "firefox.json.in"), "utf8")) as Record<
      string,
      unknown
    >;
    const cr = JSON.parse(readFileSync(join(root, "chrome.json.in"), "utf8")) as Record<
      string,
      unknown
    >;
    expect(ff["name"]).toBe(HOST_NAME);
    expect(cr["name"]).toBe(HOST_NAME);
    expect(ff["allowed_extensions"]).toEqual([FIREFOX_ID]);
    expect(cr["allowed_origins"]).toEqual([`chrome-extension://${CHROME_ID}/`]);
  });

  test("names and descriptions come from the locale catalogs", () => {
    expect(firefox["name"]).toBe("__MSG_extName__");
    expect(chrome["description"]).toBe("__MSG_extDescription__");
    expect(chrome["default_locale"]).toBe("en");
  });

  test("the version follows package.json", () => {
    const pkg = JSON.parse(readFileSync(join(import.meta.dir, "..", "package.json"), "utf8")) as {
      version: string;
    };
    expect(firefox["version"]).toBe(pkg.version);
    expect(chrome["version"]).toBe(pkg.version);
  });
});
