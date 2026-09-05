#!/usr/bin/env node
// Copy apps/body-map/dist to a required destination. No default path.

import { cpSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

export function exportBodyMap(destArg) {
  if (!destArg) {
    throw new Error("export-body-map: pass the destination directory");
  }
  const src = join(root, "apps", "body-map", "dist");
  if (!existsSync(src)) {
    throw new Error("export-body-map: build apps/body-map first");
  }
  const dest = resolve(destArg);
  if (dest === root || dest.startsWith(`${root}\\`) || dest.startsWith(`${root}/`)) {
    throw new Error("export-body-map: refuse to write inside the source tree");
  }
  mkdirSync(dest, { recursive: true });
  // Vite hashes bundle names, so a plain copy leaves the previous build behind.
  // Remove only the files this export owns; never the destination itself.
  const assets = join(dest, "assets");
  if (existsSync(assets)) {
    for (const name of readdirSync(assets)) {
      if (/^index-[A-Za-z0-9_-]+\.(js|css)$/.test(name)) rmSync(join(assets, name), { force: true });
    }
  }
  cpSync(src, dest, { recursive: true });
  return dest;
}

const invoked = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invoked) {
  try {
    const dest = exportBodyMap(process.argv[2]);
    process.stdout.write(`${dest}\n`);
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : err}\n`);
    process.exit(2);
  }
}
