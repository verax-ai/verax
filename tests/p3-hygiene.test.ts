import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { isLoopbackHost } from "../packages/body/src/config.ts";
import { listen } from "../packages/body/src/server.ts";
import { explain } from "../packages/proxy/src/explain.ts";
import { runGoldenScenario } from "../packages/proxy/tests/golden-scenario.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

describe("P3 hygiene", () => {
  it("13: 500 JSON bodies do not include a detail field", () => {
    const src = readFileSync(join(root, "packages", "body", "src", "server.ts"), "utf8");
    assert.equal(src.includes('error: "transport", detail'), false, src);
    assert.equal(/\bdetail\b/.test(src.split("send(res, 500")[1] ?? ""), false);
  });

  it("14: multiplication sign U+00D7 is gone", () => {
    const a = readFileSync(join(root, "apps", "panel", "perf", "check-baseline.mjs"), "utf8");
    const b = readFileSync(join(root, "docs", "PERF.md"), "utf8");
    assert.equal(a.includes("\u00d7"), false);
    assert.equal(b.includes("\u00d7"), false);
  });

  it("15: body tests do not embed an unlabeled private key", () => {
    for (const name of ["stale-memory.test.ts", "memory-id.test.ts"]) {
      const text = readFileSync(join(root, "packages", "body", "tests", name), "utf8");
      if (text.includes("BEGIN PRIVATE KEY")) {
        assert.match(text, /TEST KEY, NOT A SECRET/);
      }
    }
  });

  it("16: [::1] and ::1 are loopback after stripping brackets", () => {
    assert.equal(isLoopbackHost("::1"), true);
    assert.equal(isLoopbackHost("[::1]"), true);
    assert.equal(isLoopbackHost("0.0.0.0"), false);
  });

  it("17: explain returns balanced: boolean", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-p3-"));
    const ledger = await runGoldenScenario(dir);
    const n1 = await explain(ledger, "n1");
    assert.equal(typeof n1.balanced, "boolean");
    assert.equal(n1.balanced, true);
  });

  it("18: STATUS names the contest window gap", () => {
    const status = readFileSync(join(root, "docs", "STATUS.md"), "utf8");
    assert.match(status, /contest re-audits the whole ledger; no window bound \(phase 4\)/);
  });

  it("19: send() sets X-Content-Type-Options nosniff", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-nosniff-"));
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    const server = await listen({
      issuer: issuer.issuer,
      jwksUrl: issuer.jwksUrl,
      audience,
      stateDir,
      bindHost: "127.0.0.1",
      bindPort: 0,
      policyFile,
      tlsTerminated: false,
    });
    const port = (server.address() as { port: number }).port;
    try {
      const res = await fetch(`http://127.0.0.1:${port}/healthz`);
      assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
