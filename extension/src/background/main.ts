// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Background entry: binds Background to the real browser APIs and routes runtime messages.

import type { ContentRequest, PopupRequest, TabCommand } from "../shared/messages";
import { NativeClient } from "./native";
import { Background, type Browser, type KeyValueStore, type Sender } from "./service";

function store(area: chrome.storage.StorageArea): KeyValueStore {
  return {
    async get(key) {
      const items = await area.get(key);
      return items[key];
    },
    set: (key, value) => area.set({ [key]: value }),
    remove: (key) => area.remove(key),
  };
}

const browserApi: Browser = {
  async targetTabId(popupTabId) {
    const [active] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (active?.id !== undefined && active.id !== popupTabId) return active.id;
    // The popup was opened as a tab of its own: act on the tab the user used before it.
    const others = (await chrome.tabs.query({ windowType: "normal" })).filter(
      (t) => t.id !== undefined && t.id !== popupTabId,
    );
    // Tab.lastAccessed exists in Chrome ≥ 121 (the manifest's minimum) and every Firefox MV3.
    others.sort((a, b) => b.lastAccessed - a.lastAccessed);
    return others[0]?.id ?? null;
  },
  async topUrl(tabId) {
    try {
      const reply: unknown = await chrome.tabs.sendMessage(
        tabId,
        { type: "top-url" },
        { frameId: 0 },
      );
      return typeof reply === "string" ? reply : null;
    } catch {
      return null; // no content script in the top frame: not a web page we serve
    }
  },
  sendToTab: (tabId: number, frameId: number, command: TabCommand) =>
    chrome.tabs.sendMessage(tabId, command, { frameId }),
  session: store(chrome.storage.session),
  local: store(chrome.storage.local),
  now: () => Date.now(),
};

const background = new Background(new NativeClient(), browserApi);

const CONTENT_TYPES: Record<string, true> = {
  candidates: true,
  fill: true,
  code: true,
  captured: true,
  "pending-prompt": true,
  "prompt-answer": true,
};
const POPUP_TYPES: Record<string, true> = {
  "popup-state": true,
  "popup-fill": true,
  "popup-code": true,
};

function messageType(message: unknown): string | null {
  if (typeof message !== "object" || message === null) return null;
  const type = (message as Record<string, unknown>)["type"];
  return typeof type === "string" ? type : null;
}

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  // Only this extension's own contexts reach onMessage; no externally_connectable is declared.
  if (sender.id !== chrome.runtime.id) return false;
  const type = messageType(message);
  if (type === null) return false;
  let reply: Promise<unknown> | null = null;
  const fromPopup = sender.url?.startsWith(chrome.runtime.getURL("popup.html")) === true;
  if (POPUP_TYPES[type] === true && fromPopup) {
    reply = background.handlePopup(message as PopupRequest, sender.tab?.id ?? null);
  } else if (
    CONTENT_TYPES[type] === true &&
    !fromPopup &&
    sender.tab?.id !== undefined &&
    sender.frameId !== undefined &&
    sender.url !== undefined
  ) {
    const from: Sender = { tabId: sender.tab.id, frameId: sender.frameId, url: sender.url };
    reply = background.handleContent(message as ContentRequest, from);
  }
  if (reply === null) return false;
  void reply.then(sendResponse);
  return true; // keeps the channel open for the asynchronous reply
});
