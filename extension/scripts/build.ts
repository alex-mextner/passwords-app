// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Builds dist/firefox and dist/chrome from the same sources. Bundles are not minified so the
// AMO review (and anyone else) reads exactly what runs.

import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { type Target, manifestFor } from "../src/manifest";

const ROOT = join(import.meta.dir, "..");
const ENTRIES = {
  content: "src/content/main.ts",
  background: "src/background/main.ts",
  popup: "src/popup/main.ts",
} as const;

async function buildTarget(target: Target): Promise<void> {
  const out = join(ROOT, "dist", target);
  await rm(out, { recursive: true, force: true });
  await mkdir(out, { recursive: true });
  for (const [name, entry] of Object.entries(ENTRIES)) {
    const result = await Bun.build({
      entrypoints: [join(ROOT, entry)],
      target: "browser",
      // Content scripts and Firefox background scripts are classic scripts, not modules.
      format: "iife",
      minify: false,
      sourcemap: "none",
      naming: `${name}.js`,
      outdir: out,
    });
    if (!result.success) {
      for (const log of result.logs) console.error(log);
      throw new Error(`build of ${entry} for ${target} failed`);
    }
  }
  await cp(join(ROOT, "static"), out, {
    recursive: true,
    filter: (source) => !source.endsWith(".svg"),
  });
  await writeFile(join(out, "manifest.json"), `${JSON.stringify(manifestFor(target), null, 2)}\n`);
  process.stdout.write(`built ${out}\n`);
}

const requested = process.argv
  .slice(2)
  .filter((arg): arg is Target => arg === "firefox" || arg === "chrome");
for (const target of requested.length > 0 ? requested : (["firefox", "chrome"] as const)) {
  await buildTarget(target);
}
