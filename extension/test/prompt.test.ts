// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
import { beforeEach, describe, expect, test } from "bun:test";
import { SavePrompt } from "../src/content/prompt";
import type { PromptAnswer, PromptView } from "../src/shared/messages";

const SAVE: PromptView = {
  captureId: "capture-1",
  action: "create",
  host: "northwind.example",
  site: "northwind.example",
  username: "alex@example.com",
};
const UPDATE: PromptView = {
  captureId: "capture-2",
  action: "update",
  host: "northwind.example",
  site: "northwind.example",
  username: "alex@example.com",
};

let answers: PromptAnswer[];
const opened: SavePrompt[] = [];

function open(view: PromptView, isTrusted: (e: Event) => boolean = () => true): SavePrompt {
  const prompt = new SavePrompt(document, view, { onAnswer: (a) => answers.push(a), isTrusted });
  opened.push(prompt);
  return prompt;
}

function text(prompt: SavePrompt, selector: string): string | null | undefined {
  return prompt.overlay.root.querySelector(selector)?.textContent;
}

beforeEach(() => {
  answers = [];
  for (const prompt of opened.splice(0)) prompt.dismiss();
});

describe("SavePrompt", () => {
  test("a new login asks to save and offers Never", () => {
    const p = open(SAVE);
    expect(text(p, ".title")).toBe("Save this password?");
    expect(text(p, ".site")).toBe("northwind.example");
    expect(text(p, ".user")).toBe("alex@example.com");
    expect(p.button("save")?.textContent).toBe("Save");
    expect(p.button("never")?.textContent).toBe("Never for This Website");
    expect(p.button("not-now")?.textContent).toBe("Not Now");
  });

  test("a changed password asks to update and has no Never", () => {
    const p = open(UPDATE);
    expect(text(p, ".title")).toBe("Update the saved password?");
    expect(p.button("save")?.textContent).toBe("Update");
    expect(p.button("never")).toBeNull();
  });

  test("an empty username is left out instead of shown blank", () => {
    const p = open({ ...SAVE, username: "" });
    expect(p.overlay.root.querySelector(".user")).toBeNull();
  });

  test.each(["save", "not-now", "never"] as const)(
    "clicking %s answers once and closes",
    (answer) => {
      const p = open(SAVE);
      p.button(answer)?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      p.button(answer)?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      expect(answers).toEqual([answer]);
      expect(p.isOpen).toBe(false);
      expect(document.querySelector('[data-passwords-app="save-prompt"]')).toBeNull();
    },
  );

  test("synthetic clicks from the page do not answer", () => {
    const p = open(SAVE, (e) => e.isTrusted);
    p.button("save")?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(answers).toEqual([]);
    expect(p.isOpen).toBe(true);
  });

  test("Escape means Not Now", () => {
    open(SAVE);
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(answers).toEqual(["not-now"]);
  });

  test("dismiss removes the card without answering", () => {
    const p = open(SAVE);
    p.dismiss();
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(answers).toEqual([]);
    expect(p.isOpen).toBe(false);
  });

  test("the card is a labelled dialog in a closed shadow root", () => {
    const p = open(SAVE);
    expect(p.overlay.host.shadowRoot).toBeNull();
    expect(p.overlay.root.querySelector('[role="dialog"]')?.getAttribute("aria-label")).toBe(
      "Save this password?",
    );
  });

  test("site and username are text, never markup", () => {
    const p = open({ ...SAVE, username: "<img src=x onerror=alert(1)>" });
    expect(p.overlay.root.querySelector("img")).toBeNull();
  });
});

test("the tile shows the site's letter", () => {
  const p = open({ ...SAVE, host: "accounts.fabrikam.example", site: "fabrikam.example" });
  expect(p.overlay.root.querySelector(".monogram")?.textContent).toBe("F");
  expect(text(p, ".site")).toBe("accounts.fabrikam.example");
});
