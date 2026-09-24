import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const workflow = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "..", ".github", "workflows", "install-e2e.yml"),
  "utf8",
);

describe("install-e2e workflow", () => {
  it("runs the isolated install on Windows and Linux", () => {
    assert.match(workflow, /windows-latest/);
    assert.match(workflow, /ubuntu-latest/);
    assert.match(workflow, /pull_request/);
    assert.match(workflow, /workflow_dispatch/);
    assert.match(workflow, /timeout-minutes:\s*15/);
    assert.match(workflow, /npm ci/);
    assert.match(workflow, /npm run build:dist/);
    const installLines = workflow.split(/\r?\n/).filter((line) => line.includes("cli.js install"));
    assert.ok(installLines.length > 0, "workflow has no cli.js install invocation");
    for (const line of installLines) {
      assert.match(line, /--from-tarballs\b/);
      assert.match(line, /--port 8801\b/);
    }
    assert.match(workflow, /healthz/);
    assert.match(workflow, /icacls/);
    assert.match(workflow, /veraxprobe/);
    assert.match(workflow, /Start-Process/);
    assert.match(workflow, /record\.private\.pem/);
    assert.match(workflow, /approval-commands\.jsonl/);
    assert.match(workflow, /uninstall/);
    assert.match(workflow, /SUDO_USER/);
    assert.match(workflow, /\/opt\/verax/);
    assert.match(workflow, /\/var\/lib\/verax/);
    assert.match(workflow, /second run refuses a state dir the probe user pre-created/);
    assert.match(workflow, /LASTEXITCODE -ne 78/);
    assert.match(workflow, /was not created by verax install/);
    assert.match(workflow, /Verax\\state/);
  });
});
