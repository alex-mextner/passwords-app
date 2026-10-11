// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// The extension's own copy of the daemon's site rules (src/passwords_app/core/urls.py). The
// daemon already decides what matches; this second, independent check means a bug or a
// compromised answer on the other side still cannot put a password into a foreign page.

import { parse } from "tldts";

export type MatchKind = "exact-host" | "same-site" | "none";

interface WebUrl {
  readonly scheme: "http" | "https";
  readonly host: string;
  /** Explicit non-default port, or null. */
  readonly port: number | null;
  readonly isIp: boolean;
}

const DEFAULT_PORTS = { http: 80, https: 443 } as const;
const SCHEME = /^[a-z][a-z0-9+.-]*:/i;
const IPV4_PART = /^\d{1,3}$/;

/**
 * Whether `text` starts with a scheme. Like the daemon, `host:8080/x` is a scheme-less host
 * with a port, not scheme "host".
 */
function hasScheme(text: string): boolean {
  const scheme = SCHEME.exec(text)?.[0];
  if (scheme === undefined) return false;
  const rest = text.slice(scheme.length);
  const end = rest.search(/[/?#]/);
  const port = end === -1 ? rest : rest.slice(0, end);
  return port === "" || !/^\d+$/.test(port);
}

/** The authority's host exactly as written, before WHATWG parsing rewrites it. */
function writtenHost(absolute: string): string {
  const start = absolute.indexOf("//");
  if (start === -1) return "";
  const rest = absolute.slice(start + 2);
  const end = rest.search(/[/?#\\]/);
  const authority = end === -1 ? rest : rest.slice(0, end);
  const hostPort = authority.slice(authority.lastIndexOf("@") + 1);
  if (hostPort.startsWith("[")) return hostPort.slice(0, hostPort.indexOf("]") + 1);
  const colon = hostPort.indexOf(":");
  return colon === -1 ? hostPort : hostPort.slice(0, colon);
}

/**
 * WHATWG parsing silently repairs hosts the daemon rejects (`a..b`, `.a.com`, `0x7f.1`). Both
 * sides must refuse the same inputs, so such spellings are rejected here as well.
 */
function hostWasCanonical(written: string, parsed: string): boolean {
  if (written.startsWith("[")) return true;
  const labels = written.split(".");
  if (labels.length > 1 && labels.at(-1) === "") labels.pop();
  if (labels.includes("")) return false;
  const parts = parsed.split(".");
  const isIpv4 = parts.length === 4 && parts.every((p) => IPV4_PART.test(p));
  return !isIpv4 || written.replace(/\.$/, "") === parsed;
}

/** Parse an http(s) URL the way the browser does; null for anything else. */
export function parseWebUrl(raw: string): WebUrl | null {
  const trimmed = raw.trim();
  const text = hasScheme(trimmed) ? trimmed : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  const scheme = url.protocol === "https:" ? "https" : url.protocol === "http:" ? "http" : null;
  if (scheme === null || url.hostname === "") return null;
  const written = writtenHost(text);
  if (!hostWasCanonical(written, url.hostname)) return null;
  const host = url.hostname
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "")
    .toLowerCase();
  if (host === "") return null;
  return {
    scheme,
    host,
    port: url.port === "" ? null : Number(url.port),
    isIp: parse(host).isIp === true,
  };
}

function effectivePort(u: WebUrl): number {
  return u.port ?? DEFAULT_PORTS[u.scheme];
}

function stripWww(host: string): string {
  return host.startsWith("www.") && host.length > 4 ? host.slice(4) : host;
}

/** eTLD+1 including private suffixes (`user.github.io`); null for public suffixes and IPs. */
export function registrableDomain(host: string): string | null {
  const info = parse(host, { allowPrivateDomains: true });
  if (info.isIp === true) return null;
  return info.domain;
}

function originRulesAllow(page: WebUrl, cred: WebUrl): boolean {
  // An https secret must never reach a page that anyone on the network path can rewrite.
  if (cred.scheme === "https" && page.scheme === "http") return false;
  if (page.port === null && cred.port === null) return true;
  return effectivePort(page) === effectivePort(cred);
}

function matchOne(page: WebUrl, cred: WebUrl): MatchKind {
  if (!originRulesAllow(page, cred)) return "none";
  if (stripWww(page.host) === stripWww(cred.host)) return "exact-host";
  if (page.isIp || cred.isIp) return "none";
  const site = registrableDomain(page.host);
  if (site === null || site !== registrableDomain(cred.host)) return "none";
  return "same-site";
}

/** Best match of a page against a credential's website and additional websites. */
export function matchSite(pageUrl: string, credUrls: readonly string[]): MatchKind {
  const page = parseWebUrl(pageUrl);
  if (page === null) return "none";
  let best: MatchKind = "none";
  for (const raw of credUrls) {
    const cred = parseWebUrl(raw);
    if (cred === null) continue;
    const kind = matchOne(page, cred);
    if (kind === "exact-host") return kind;
    if (kind === "same-site") best = kind;
  }
  return best;
}

/**
 * Whether a frame may be offered or filled credentials at all: only top-level documents and
 * subframes of the same site, so a login form embedded by another site (clickjacking) and
 * ads or widgets from third parties never get a dropdown.
 */
export function frameAllowed(frameUrl: string, topUrl: string): boolean {
  const frame = parseWebUrl(frameUrl);
  const top = parseWebUrl(topUrl);
  if (frame === null || top === null) return false;
  if (top.scheme === "https" && frame.scheme === "http") return false;
  if (frame.host === top.host) return true;
  if (frame.isIp || top.isIp) return false;
  const site = registrableDomain(frame.host);
  return site !== null && site === registrableDomain(top.host);
}

/**
 * `scheme://host[:port]` of a web URL exactly as the browser serializes `location.origin`
 * (a trailing-dot host keeps its dot), so content scripts can compare it directly; or null.
 */
export function originOf(raw: string): string | null {
  const trimmed = raw.trim();
  const text = hasScheme(trimmed) ? trimmed : `https://${trimmed}`;
  return parseWebUrl(text) === null ? null : new URL(text).origin;
}

/** Host shown to people: no `www.`, Unicode IDNs left as the browser gives them. */
export function displayHost(raw: string): string {
  const u = parseWebUrl(raw);
  return u === null ? raw : stripWww(u.host);
}

/** The site people recognise: registrable domain, else the host (IPs, intranet names). */
export function siteName(raw: string): string {
  const u = parseWebUrl(raw);
  if (u === null) return raw;
  return registrableDomain(u.host) ?? stripWww(u.host);
}
