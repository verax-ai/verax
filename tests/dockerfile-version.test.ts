import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The image workflow passes the version from package.json, but a manual
 * `docker build .` takes the Dockerfile's default. Two copies of one number
 * drift silently; this holds them together.
 */
describe("Dockerfile version", () => {
  it("the default VERAX_VERSION is the body's package version", () => {
    const dockerfile = readFileSync(join(root, "Dockerfile"), "utf8");
    const match = /^ARG VERAX_VERSION=(\S+)$/m.exec(dockerfile);
    assert.ok(match, "Dockerfile has no ARG VERAX_VERSION default");
    const body = JSON.parse(readFileSync(join(root, "packages", "body", "package.json"), "utf8")) as { version: string };
    assert.equal(match[1], body.version);
  });
});
