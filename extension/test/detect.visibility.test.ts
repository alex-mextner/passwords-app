// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// The visibility checks honeypot filtering relies on. happy-dom computes styles but has no
// layout, so the layout half of the default check is driven by stubbing the element's boxes.

import { describe, expect, test } from "bun:test";

import { defaultIsVisible, detectForms, isStyleVisible } from "../src/content/detect";
import { loadBody, loadFixture } from "./fixtures/load";

function target(): HTMLInputElement {
  const found = document.getElementById("t");
  if (!(found instanceof HTMLInputElement)) throw new Error("needs input#t");
  return found;
}

describe("isStyleVisible", () => {
  test.each([
    ["a plain input", `<input id="t">`, true],
    ["display:none on the input", `<input id="t" style="display:none">`, false],
    [
      "display:none on an ancestor",
      `<div style="display:none"><div><input id="t"></div></div>`,
      false,
    ],
    ["visibility:hidden on the input", `<input id="t" style="visibility:hidden">`, false],
    ["visibility:hidden inherited", `<div style="visibility:hidden"><input id="t"></div>`, false],
    [
      "visibility re-enabled on the input",
      `<div style="visibility:hidden"><input id="t" style="visibility:visible"></div>`,
      true,
    ],
    ["opacity:0 on an ancestor", `<div style="opacity:0"><input id="t"></div>`, false],
    ["opacity:0.5 stays visible", `<div style="opacity:0.5"><input id="t"></div>`, true],
    ["hidden attribute on an ancestor", `<section hidden><input id="t"></section>`, false],
    [
      "stylesheet rule",
      `<style>.trap{display:none}</style><p class="trap"><input id="t"></p>`,
      false,
    ],
  ])("%s", (_name, body, visible) => {
    loadBody(body);
    expect(isStyleVisible(target())).toBe(visible);
  });

  test("a shadow host hidden by its page hides the inputs inside it", () => {
    loadBody("");
    const host = document.createElement("div");
    host.style.display = "none";
    document.body.append(host);
    const inner = document.createElement("input");
    host.attachShadow({ mode: "open" }).append(inner);
    expect(isStyleVisible(inner)).toBe(false);
  });
});

describe("defaultIsVisible", () => {
  function layOut(
    input: HTMLElement,
    box: { x: number; y: number; w: number; h: number } | null,
  ): void {
    input.getClientRects = () =>
      (box === null ? [] : [new DOMRect(box.x, box.y, box.w, box.h)]) as unknown as DOMRectList;
    input.getBoundingClientRect = () =>
      box === null ? new DOMRect(0, 0, 0, 0) : new DOMRect(box.x, box.y, box.w, box.h);
  }

  test.each([
    ["a normal field", { x: 20, y: 100, w: 240, h: 32 }, true],
    ["no layout box at all", null, false],
    ["collapsed to one pixel", { x: 20, y: 100, w: 1, h: 1 }, false],
    ["zero height", { x: 20, y: 100, w: 200, h: 0 }, false],
    ["pushed off the left edge", { x: -9999, y: 100, w: 200, h: 30 }, false],
    ["pushed above the page", { x: 20, y: -500, w: 200, h: 30 }, false],
    ["partly off-screen still counts", { x: -100, y: 100, w: 200, h: 30 }, true],
  ])("%s", (_name, box, visible) => {
    loadBody(`<input id="t">`);
    layOut(target(), box);
    expect(defaultIsVisible(target())).toBe(visible);
  });

  test("style beats layout", () => {
    loadBody(`<input id="t" style="visibility:hidden">`);
    layOut(target(), { x: 20, y: 100, w: 240, h: 32 });
    expect(defaultIsVisible(target())).toBe(false);
  });

  test("an off-screen honeypot username is skipped by detectForms", () => {
    loadBody(
      `<form><input id="trap" name="username"><input id="u" name="email" type="email"><input id="p" type="password"><button>Sign in</button></form>`,
    );
    const boxes: Record<string, { x: number; y: number; w: number; h: number }> = {
      trap: { x: -9999, y: 0, w: 200, h: 30 },
      u: { x: 20, y: 100, w: 200, h: 30 },
      p: { x: 20, y: 140, w: 200, h: 30 },
    };
    for (const input of Array.from(document.querySelectorAll("input"))) {
      layOut(input, boxes[input.id] ?? null);
    }
    const [found] = detectForms(document);
    expect(found?.username?.id).toBe("u");
    expect(found?.password?.id).toBe("p");
  });
});

describe("honeypot fixture", () => {
  test("only the real fields survive", () => {
    const doc = loadFixture("honeypot-login");
    const forms = detectForms(doc, { isVisible: isStyleVisible });
    const used = forms.flatMap((form) => [form.username?.id, form.password?.id]);
    expect(used).toEqual(["hu", "hpw"]);
  });
});
