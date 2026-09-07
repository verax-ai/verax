import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { diskProbe } from "../packages/proxy/src/disk.ts";
import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

describe("S3 unrecorded disk deny", () => {
  it("returns HTTP 507 and bumps disk_deny_unrecorded; no silent drop", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-http-507-"));
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    const origFree = diskProbe.freeBytes;
    const origFail = diskProbe.failAppend;
    diskProbe.freeBytes = (dir) => (dir === stateDir ? 0 : origFree(dir));
    diskProbe.failAppend = true;
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
    const mcp = `http://127.0.0.1:${port}/mcp`;
    try {
      const token = await issuer.sign({ scope: "verax:read" });
      const res = await fetch(mcp, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "memory.get", arguments: { id: "a" } },
        }),
      });
      assert.equal(res.status, 507, await res.text());
      const metrics = JSON.parse(readFileSync(join(stateDir, "metrics.json"), "utf8")) as {
        disk_deny_unrecorded?: number;
      };
      assert.equal(metrics.disk_deny_unrecorded, 1);
      assert.equal(existsSync(join(stateDir, "decisions.jsonl")), false);
    } finally {
      diskProbe.freeBytes = origFree;
      diskProbe.failAppend = origFail;
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
