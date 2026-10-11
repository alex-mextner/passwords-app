// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Brand the page from its host and record what the page itself observes, like a real site's
// framework would: every input/change event and the values it saw.
(function () {
  "use strict";
  var host = location.hostname;
  var brand = host.indexOf("fabrikam") >= 0 ? "Fabrikam" : "Northwind";
  document.body.classList.add(brand.toLowerCase());
  document.querySelectorAll("[data-brand]").forEach(function (node) { node.textContent = brand; });
  window.__events = [];
  document.addEventListener("input", function (e) { window.__events.push(["input", e.target.id, e.target.value, e.isTrusted]); }, true);
  document.addEventListener("change", function (e) { window.__events.push(["change", e.target.id, e.target.value, e.isTrusted]); }, true);
  // ?focus=<id>: the page focuses a field while it loads (like `autofocus`), before any
  // extension content script can run: those start once the document is parsed at the earliest.
  var focus = new URLSearchParams(location.search).get("focus");
  if (focus) document.getElementById(focus).focus();
})();
