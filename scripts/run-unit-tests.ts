#!/usr/bin/env node
// Discovers *.test.ts and hands them to node --test. A directory argument
// is treated as a module under --experimental-strip-types, so files are
// listed explicitly.

import { spawnSync } from "node:child_process";
import { globSync } from "node:fs";

const files = [
  ...globSync("tests/**/*.test.ts"),
  ...globSync("packages/*/tests/**/*.test.ts"),
  ...globSync("apps/*/tests/**/*.test.ts"),
].sort();

if (files.length === 0) {
  console.error("run-unit-tests: no test files found");
  process.exit(1);
}

const result = spawnSync(
  process.execPath,
  ["--experimental-strip-types", "--test", ...files],
  { stdio: "inherit" },
);

process.exit(result.status === null ? 1 : result.status);
