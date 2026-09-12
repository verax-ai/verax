import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { panelBuildNeeded } from "../../../packages/body/src/desktop.ts";
import { listen } from "../../../packages/body/src/server.ts";
import { killStragglers, startPreview } from "../../../scripts/test-preview.ts";
import { startDevIssuer } from "../../../tests/issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const repo = join(root, "..", "..");
const viteJs = join(repo, "node_modules", "vite", "bin", "vite.js");
const policyFile = join(repo, "packages", "proxy", "policy", "default.json");

after(killStragglers);

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        server.close(() => reject(new Error("free-port")));
        return;
      }
      const port = addr.port;
      server.close(() => resolve(port));
    });
    server.once("error", reject);
  });
}

function ensurePanelBuilt(): void {
  const distIndex = join(root, "dist", "index.html");
  const sources = [join(root, "src"), join(root, "index.html"), join(root, "vite.config.ts")];
  if (!panelBuildNeeded(distIndex, sources)) return;
  const built = spawnSync(process.execPath, [viteJs, "build"], {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
  });
  assert.equal(built.status, 0, `panel-build-failed\n${built.stderr}\n${built.stdout}`);
}

/**
 * The preview used to attach VERAX_DEV_TOKEN to any /api request that arrived
 * without Authorization. A reverse proxy on the tailnet made that the
 * network's token: every device that could reach the panel could read the
 * ledger. This asks the running preview, not the source text.
 */
describe("preview does not hand out the body token", () => {
  it(
    "leaves /api/ledger 401 when Authorization is absent, even if VERAX_DEV_TOKEN is set",
    { timeout: 120_000 },
    async () => {
      const stateDir = mkdtempSync(join(tmpdir(), "verax-preview-token-"));
      const audience = "http://127.0.0.1/verax-preview-token";
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
      const bodyPort = (server.address() as { port: number }).port;
      const bodyUrl = `http://127.0.0.1:${bodyPort}`;
      const token = await issuer.sign({ scope: "verax:read verax:audit" });
      const port = await freePort();
      ensurePanelBuilt();
      const preview = await startPreview({
        viteJs,
        cwd: root,
        port,
        label: "preview-token",
        command: "preview",
        env: {
          VERAX_DEV_TOKEN: token,
          VERAX_BODY_URL: bodyUrl,
        },
      });
      try {
        const bare = await fetch(`${preview.base}/api/ledger?from=0&to=99`);
        assert.equal(
          bare.status,
          401,
          `preview attached a token the request did not send: ${bare.status}`,
        );
        const ok = await fetch(`${preview.base}/api/ledger?from=0&to=99`, {
          headers: { authorization: `Bearer ${token}` },
        });
        assert.equal(ok.status, 200, `valid token was refused: ${ok.status}`);
      } finally {
        preview.stop();
        await new Promise<void>((resolve, reject) => {
          server.close((err) => (err ? reject(err) : resolve()));
        });
        await issuer.close();
      }
    },
  );
});
