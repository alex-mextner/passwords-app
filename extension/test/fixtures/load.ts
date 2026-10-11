// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Loads HTML fixture pages into the global happy-dom document. happy-dom does not parse
// declarative shadow DOM (<template shadowrootmode>), so the loader attaches those roots itself,
// the way a browser's parser would.

import { readFileSync } from "node:fs";

function attachShadowTemplates(root: ParentNode): void {
  for (const template of Array.from(root.querySelectorAll("template[shadowrootmode]"))) {
    const host = template.parentElement;
    if (host === null || !(template instanceof HTMLTemplateElement)) continue;
    const mode = template.getAttribute("shadowrootmode") === "closed" ? "closed" : "open";
    const shadow = host.attachShadow({ mode });
    const content = template.content.cloneNode(true);
    template.remove();
    shadow.append(content);
    attachShadowTemplates(shadow);
  }
}

/** Replaces the global document's content with `html`. */
export function loadHtml(html: string): Document {
  const parsed = new DOMParser().parseFromString(html, "text/html");
  const nodes = Array.from(parsed.documentElement.childNodes, (node) =>
    document.importNode(node, true),
  );
  document.documentElement.replaceChildren(...nodes);
  attachShadowTemplates(document);
  return document;
}

/** Wraps a fragment in a minimal page and loads it. */
export function loadBody(body: string): Document {
  return loadHtml(`<!doctype html><html><head><title>t</title></head><body>${body}</body></html>`);
}

export function fixtureHtml(name: string): string {
  return readFileSync(new URL(`./${name}.html`, import.meta.url), "utf8");
}

export function loadFixture(name: string): Document {
  return loadHtml(fixtureHtml(name));
}

/** Every element with this id, searching open shadow roots too. */
export function byId(id: string, root: ParentNode = document): HTMLElement {
  const found = deepQueryAll(root, `#${id}`).at(0);
  if (!(found instanceof HTMLElement)) throw new Error(`no element #${id}`);
  return found;
}

export function inputById(id: string): HTMLInputElement {
  const found = byId(id);
  if (!(found instanceof HTMLInputElement)) throw new Error(`#${id} is not an input`);
  return found;
}

/** querySelectorAll that also descends into open shadow roots, in document order. */
export function deepQueryAll(root: ParentNode, selector: string): Element[] {
  const found: Element[] = [];
  const visit = (node: ParentNode): void => {
    for (const child of Array.from(node.children)) {
      if (child.matches(selector)) found.push(child);
      if (child.shadowRoot !== null) visit(child.shadowRoot);
      visit(child);
    }
  };
  visit(root);
  return found;
}
