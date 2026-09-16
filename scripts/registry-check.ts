#!/usr/bin/env node
// Asks the registry what it now holds for this server, and fails unless the
// row marked isLatest carries the version we meant to publish. The registry
// takes a moment to answer after a publish, so it retries rather than calling
// a fresh record missing.
//
// Run: node --experimental-strip-types scripts/registry-check.ts <name> <version>

import { latestRecord } from "./registry-record.ts";

const [name, want] = process.argv.slice(2);
if (!name || !want) {
  process.stderr.write("registry-check: <name> <version>\n");
  process.exit(2);
}

const url = `https://registry.modelcontextprotocol.io/v0/servers?search=${encodeURIComponent(name)}`;
let lastWhy = "never asked";

for (let attempt = 1; attempt <= 20; attempt += 1) {
  try {
    const res = await fetch(url);
    const text = await res.text();
    const { found, why } = latestRecord(text, name);
    if (found && found.version === want) {
      process.stdout.write(`registry: ${name} ${found.version} isLatest${found.publishedAt ? ` (${found.publishedAt})` : ""}\n`);
      process.exit(0);
    }
    lastWhy = found ? `latest is ${found.version}, expected ${want}` : why;
  } catch (err) {
    lastWhy = `request failed: ${(err as Error).message}`;
  }
  process.stdout.write(`attempt ${attempt}: ${lastWhy}\n`);
  await new Promise((resolve) => setTimeout(resolve, 15_000));
}

process.stderr.write(`the registry never answered with ${want}: ${lastWhy}\n`);
process.exit(1);
