import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { listen } from "../src/server.ts";
import { startDevIssuer } from "../../../tests/issuer-helper.ts";

function allowPolicyFile(dir: string): string {
  const path = join(dir, "allow-policy.json");
  writeFileSync(
    path,
    JSON.stringify({
      version: 1,
      default: "deny",
      rules: [
        {
          id: "get-allow",
          tool: "memory.get",
          requires: ["verax:read"],
          text: "Reads are allowed.",
        },
      ],
    }),
    "utf8",
  );
  return path;
}

describe("signed halt over HTTP", () => {
  it("T3 POST /api/halt records the halt before any call", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-signed-halt-t3-"));
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    const server = await listen({
      issuer: issuer.issuer,
      jwksUrl: issuer.jwksUrl,
      audience,
      stateDir,
      bindHost: "127.0.0.1",
      bindPort: 0,
      policyFile: allowPolicyFile(stateDir),
      tlsTerminated: false,
    });
    const port = (server.address() as { port: number }).port;
    try {
      const reader = await issuer.sign({ scope: "verax:audit", sub: "reader-3" });
      const stopped = await fetch(`http://127.0.0.1:${port}/api/halt`, {
        method: "POST",
        headers: { authorization: `Bearer ${reader}` },
      });
      assert.equal(stopped.status, 200);
      const decisions = readFileSync(join(stateDir, "decisions.jsonl"), "utf8")
        .split("\n")
        .filter((line) => line !== "")
        .map((line) => JSON.parse(line) as { claims: { decision: string; subject: string; reasonCode: string } });
      assert.equal(decisions.length, 1);
      assert.equal(decisions[0]?.claims.decision, "allow");
      assert.equal(decisions[0]?.claims.subject, "verax.halt");
      assert.equal(decisions[0]?.claims.reasonCode, "operator-halt");
      const effects = readFileSync(join(stateDir, "effects.jsonl"), "utf8");
      assert.match(effects, /verax\.control/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await issuer.close();
    }
  });
});
