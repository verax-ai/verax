#!/usr/bin/env node
/**
 * `verax-anchor-service` — start the hosted anchoring service from the
 * environment. Missing required configuration exits 64 with one sentence on
 * stderr.
 */
import { EX_USAGE, loadConfig } from "./config.ts";
import { startService } from "./server.ts";

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(EX_USAGE);
  }
  try {
    const running = await startService(config);
    process.stderr.write(`verax-anchor-service listening on ${running.url}\n`);
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(EX_USAGE);
  }
}

void main();
