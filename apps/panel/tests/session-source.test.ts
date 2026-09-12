import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("panel session is not the Vite inject path", () => {
  it("session and App never name VERAX_DEV_TOKEN or write localStorage", () => {
    const session = readFileSync(join(root, "src", "session.ts"), "utf8");
    const app = readFileSync(join(root, "src", "App.tsx"), "utf8");
    assert.equal(session.includes("VERAX_DEV_TOKEN"), false);
    assert.equal(app.includes("VERAX_DEV_TOKEN"), false);
    assert.equal(session.includes("localStorage"), false);
    assert.equal(app.includes("localStorage"), false);
    assert.match(session, /sessionStorage/);
    assert.match(session, /code_challenge_method/);
    assert.match(app, /sessionIssueError|resource metadata unreachable/);
  });

  it("Vite does not attach VERAX_DEV_TOKEN to proxied requests", () => {
    const vite = readFileSync(join(root, "vite.config.ts"), "utf8");
    assert.equal(vite.includes("VERAX_DEV_TOKEN"), false);
    assert.equal(vite.includes("Authorization"), false);
    assert.equal(vite.includes("setHeader"), false);
  });

  it("session reads authorization_servers and vite proxies the PRM path", () => {
    const session = readFileSync(join(root, "src", "session.ts"), "utf8");
    const vite = readFileSync(join(root, "vite.config.ts"), "utf8");
    assert.match(session, /authorization_servers/);
    assert.match(session, /oauth-protected-resource/);
    assert.match(vite, /\/\.well-known/);
  });
});
