// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// One source for both browsers' manifest.json. Permissions are the minimum the features need:
// nativeMessaging (the host), storage (pending save prompts in memory-only session storage,
// "never save" sites in local storage). No tabs/activeTab/host permissions: content scripts
// report their own frame's URL and the background only trusts the browser's MessageSender.

import packageJson from "../package.json";

export type Target = "firefox" | "chrome";

export const FIREFOX_ID = "passwords-app@alex-mextner.github.io";
/**
 * Public half of the key that pins the Chrome extension id (djaiceficanbdafmmlcmgbfjefiapjaf)
 * for unpacked loads, so the native host manifest can name it in allowed_origins. The private
 * half is not in the repository; it is only needed to pack a .crx.
 */
export const CHROME_PUBLIC_KEY =
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtIvhgVt0EaoZaOI7EuWeMQlpnGWgcJbgoP9ksexPQye/V8oebfVc9OZSLesXJ1HMpIvvSef6PtNs6DrE/e9cqNLCXOJ1f8P1YSTfR8Duwy/C6azhUJ7pYu3yDXNPpFUiob/lYDPV+RB7aAI3JVReV88PdIprg6Y+QE5YQaqVyLvCT7y3/ok6TjcwiWTtyGoThagoCx/aSGs2JdD2msjGVjztMYTler6Nf3Z991OagBIztnvvxz+Hx5tSPGEHJvnKgRlFZyyP0fMhS8Qvo+Yr9JbPvcl6UaPwlodk3R16Ys7h18ksuzhVPGOV68JFftE9Kcm/B1wtXzd1qs8UcD0TOQIDAQAB";
export const CHROME_ID = "djaiceficanbdafmmlcmgbfjefiapjaf";

/** Extension pages run only bundled code; nothing may be framed, posted or based elsewhere. */
export const EXTENSION_PAGES_CSP =
  "script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const ICONS = {
  "16": "icons/icon-16.png",
  "32": "icons/icon-32.png",
  "48": "icons/icon-48.png",
  "96": "icons/icon-96.png",
  "128": "icons/icon-128.png",
};

export function manifestFor(target: Target): Record<string, unknown> {
  const common = {
    manifest_version: 3,
    name: "__MSG_extName__",
    description: "__MSG_extDescription__",
    version: packageJson.version,
    default_locale: "en",
    icons: ICONS,
    action: {
      default_title: "__MSG_actionTitle__",
      default_popup: "popup.html",
      default_icon: { "16": ICONS["16"], "32": ICONS["32"] },
    },
    permissions: ["nativeMessaging", "storage"],
    content_scripts: [
      {
        matches: ["http://*/*", "https://*/*"],
        js: ["content.js"],
        all_frames: true,
        // DOM ready, before load: a field the user types into right away is already watched.
        run_at: "document_end",
      },
    ],
    content_security_policy: { extension_pages: EXTENSION_PAGES_CSP },
  };
  if (target === "firefox") {
    return {
      ...common,
      background: { scripts: ["background.js"] },
      browser_specific_settings: {
        gecko: {
          id: FIREFOX_ID,
          // 142: first desktop and Android release that knows data_collection_permissions.
          strict_min_version: "142.0",
          // Nothing leaves the machine: the extension talks only to the local native host.
          data_collection_permissions: { required: ["none"] },
        },
      },
    };
  }
  return {
    ...common,
    key: CHROME_PUBLIC_KEY,
    minimum_chrome_version: "121",
    background: { service_worker: "background.js" },
  };
}
