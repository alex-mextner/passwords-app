// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Building blocks for UI the extension draws inside web pages. Everything lives in a closed
// shadow root hung off <html>, so page scripts cannot read candidate names out of it and page
// CSS cannot restyle it; text is only ever set through textContent.

import { monogramColors, monogramLetter } from "../shared/monogram";

/** The topmost z-index browsers honour; pages often stack overlays just below it. */
export const TOP_LAYER = "2147483647";

export interface Overlay {
  readonly host: HTMLElement;
  readonly root: ShadowRoot;
  remove(): void;
}

/** A positioned host element with a closed shadow root and the given stylesheet. */
export function createOverlay(doc: Document, css: string, name: string): Overlay {
  const host = doc.createElement("div");
  host.setAttribute("data-passwords-app", name);
  // `all: initial` resets inherited page styles on the host; the shadow tree has its own CSS.
  host.style.cssText = `all: initial; position: fixed; top: 0; left: 0; z-index: ${TOP_LAYER};`;
  const root = host.attachShadow({ mode: "closed" });
  const style = doc.createElement("style");
  style.textContent = css;
  root.append(style);
  doc.documentElement.append(host);
  return {
    host,
    root,
    remove: () => {
      host.remove();
    },
  };
}

type Child = Node | string | null | false;

/** Create an element with attributes and text/element children (never markup). */
export function el(
  doc: Document,
  tag: string,
  attrs: Readonly<Record<string, string>> = {},
  ...children: Child[]
): HTMLElement {
  const node = doc.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  for (const child of children) {
    if (child === null || child === false) continue;
    node.append(typeof child === "string" ? doc.createTextNode(child) : child);
  }
  return node;
}

/** Letter tile for a login: colour keyed by `site` so all of a site's logins match. */
export function monogram(doc: Document, title: string, site: string, size = 28): HTMLElement {
  const [top, bottom] = monogramColors(site || title);
  const node = el(
    doc,
    "span",
    { class: "monogram", "aria-hidden": "true" },
    monogramLetter(title, site),
  );
  node.style.background = `linear-gradient(${top}, ${bottom})`;
  node.style.width = `${size}px`;
  node.style.height = `${size}px`;
  node.style.fontSize = `${Math.round(size * 0.5)}px`;
  return node;
}

const SVG_NS = "http://www.w3.org/2000/svg";

/** White key glyph (the "strong password" mark), drawn with DOM calls, not markup. */
export function keyIcon(doc: Document): SVGSVGElement {
  const svg = doc.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "17");
  svg.setAttribute("height", "17");
  const ring = doc.createElementNS(SVG_NS, "circle");
  ring.setAttribute("cx", "8");
  ring.setAttribute("cy", "8");
  ring.setAttribute("r", "4.5");
  const shaft = doc.createElementNS(SVG_NS, "path");
  shaft.setAttribute("d", "M11.2 11.2 20 20M16.5 16.5l2.5-2.5M14 14l2-2");
  for (const node of [ring, shaft]) {
    node.setAttribute("fill", "none");
    node.setAttribute("stroke", "#fff");
    node.setAttribute("stroke-width", "2.4");
    node.setAttribute("stroke-linecap", "round");
    svg.append(node);
  }
  return svg;
}

/** Light/dark palette and type shared by every overlay, in the spirit of macOS menus. */
export const BASE_CSS = `
:host { all: initial; }
* { box-sizing: border-box; }
.card {
  font: 13px/1.3 -apple-system, system-ui, "Cantarell", "Inter", "Segoe UI", sans-serif;
  color: #1d1d1f;
  background: rgba(250, 250, 252, 0.98);
  border: 0.5px solid rgba(0, 0, 0, 0.16);
  border-radius: 12px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.18), 0 1px 3px rgba(0, 0, 0, 0.12);
  -webkit-font-smoothing: antialiased;
}
.monogram {
  display: inline-flex; align-items: center; justify-content: center; flex: none;
  border-radius: 22%; color: #fff; font-weight: 600;
  box-shadow: inset 0 0 0 0.5px rgba(0, 0, 0, 0.12);
}
.secondary { color: #6e6e73; }
@media (prefers-color-scheme: dark) {
  .card {
    color: #f5f5f7;
    background: rgba(44, 44, 46, 0.98);
    border-color: rgba(255, 255, 255, 0.14);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), 0 1px 3px rgba(0, 0, 0, 0.4);
  }
  .secondary { color: #a1a1a6; }
}
`;
