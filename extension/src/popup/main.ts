// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Popup entry: asks the background for the current tab's state and wires the view to it.

import { t } from "../shared/i18n";
import type { PopupReplies, PopupRequest, PopupState } from "../shared/messages";
import { renderPopup } from "./view";

async function send<T extends PopupRequest["type"]>(
  message: Extract<PopupRequest, { type: T }>,
): Promise<PopupReplies[T] | undefined> {
  try {
    return await chrome.runtime.sendMessage<PopupRequest, PopupReplies[T]>(message);
  } catch {
    return undefined;
  }
}

const EMPTY: PopupState = { host: null, state: null, items: [], error: "internal" };

async function main(): Promise<void> {
  document.documentElement.lang = chrome.i18n.getUILanguage();
  document.title = t("actionTitle");
  const reply = await send({ type: "popup-state" });
  const state: PopupState =
    reply?.ok === true ? reply : reply === undefined ? EMPTY : { ...EMPTY, error: reply.error };
  renderPopup(document, state, {
    onFill: (id) => {
      void send({ type: "popup-fill", id }).then((result) => {
        if (result?.ok === true && result.filled) window.close();
      });
    },
    onCode: (id) => {
      void send({ type: "popup-code", id }).then((result) => {
        if (result?.ok !== true) return;
        const button = document.querySelector<HTMLElement>(`li[data-id="${CSS.escape(id)}"] .code`);
        if (button !== null) {
          button.textContent = `${result.code} · ${t("secondsLeft", String(result.secondsLeft))}`;
        }
      });
    },
  });
  document.getElementById("search")?.focus();
}

void main();
