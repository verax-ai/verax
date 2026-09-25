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
  it("runs the isolated install on Windows, Linux, and macOS", () => {
    assert.match(workflow, /windows-latest/);
    assert.match(workflow, /ubuntu-latest/);
    assert.match(workflow, /macos-latest/);
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
    assert.match(workflow, /icacls \$dir \/inheritance:r \/grant:r "\*S-1-5-32-544:\(OI\)\(CI\)F" "\*S-1-5-18:\(OI\)\(CI\)F"\r?\n/);
    assert.match(workflow, /icacls "\$dir\\\*" \/reset \/T \/C/);
    assert.equal(/icacls \$dir \/inheritance:r \/grant:r "\*S-1-5-32-544:\(OI\)\(CI\)F" "\*S-1-5-18:\(OI\)\(CI\)F" \/T/.test(workflow), false);
    assert.match(workflow, /veraxprobe/);
    assert.match(workflow, /Start-Process/);
    assert.match(workflow, /record\.private\.pem/);
    assert.match(workflow, /approval-commands\.jsonl/);
    assert.match(workflow, /uninstall/);
    assert.match(workflow, /SUDO_USER/);
    assert.match(workflow, /\/opt\/verax/);
    assert.match(workflow, /\/var\/lib\/verax/);
    assert.match(workflow, /\/Library\/Verax/);
    assert.match(workflow, /verax-svc/);
    assert.equal(workflow.includes("LocalService missing"), false);
    assert.match(workflow, /second run refuses a state dir the probe user pre-created/);
    assert.match(workflow, /\$code -ne 78/);
    assert.match(workflow, /was not created by verax install/);
    assert.match(workflow, /Verax\\state/);
    assert.match(workflow, /icacls "\$env:ProgramData\\Verax" \| Out-String/);
    assert.match(workflow, /Write-Host \$rootAcl/);
    assert.match(workflow, /BUILTIN\\Users/);
    assert.match(workflow, /CREATOR OWNER/);
    assert.match(workflow, /Authenticated Users/);
    assert.match(workflow, /Write-Host "::error::ProgramData\\Verax ACL contains \$banned"; exit 1/);
  });

  it("reports step failures where the job log shows them", () => {
    assert.equal(workflow.includes("Write-Error"), false, "Write-Error does not reach the job log");
    const second = workflow.slice(workflow.indexOf("- name: second run refuses a state dir the probe user pre-created\n"));
    const step = second.slice(0, second.indexOf("\n      - name: ", 1));
    assert.match(step, /Write-Host \$log/);
    assert.match(step, /ok: install refused the pre-created state dir\"\r?\n\s*\$global:LASTEXITCODE = 0\r?\n\s*exit 0/);
  });

  it("prints tarball access evidence on Windows before install and again if that install fails", () => {
    const before = workflow.indexOf("- name: diagnose tarball access\n");
    const install = workflow.indexOf("- name: install, probe, uninstall\n");
    const after = workflow.indexOf("- name: diagnose tarball access on failure\n");
    const second = workflow.indexOf("- name: second run refuses a state dir the probe user pre-created\n");
    assert.ok(before > 0 && before < install, "diagnose step is not before the Windows install");
    assert.ok(install < after && after < second, "failure diagnose step is not between the Windows install and the second run");
    const failure = workflow.slice(after, second);
    assert.match(failure, /if:\s*failure\(\)/);
    for (const chunk of [workflow.slice(before, install), failure]) {
      assert.match(chunk, /whoami \/groups \/fo list/);
      assert.match(chunk, /Mandatory Label/);
      assert.match(chunk, /BUILTIN\\Administrators/);
      assert.match(chunk, /icacls/);
      assert.match(chunk, /Get-Acl/);
      assert.match(chunk, /Format-List Attributes/);
      assert.match(chunk, /\[IO\.File\]::ReadAllBytes/);
      assert.match(chunk, /\$env:VERAX_NODE -e "require\('fs'\)\.readFileSync\(process\.argv\[1\]\);console\.log\('ok'\)"/);
      assert.match(chunk, /Get-MpComputerStatus/);
      assert.match(chunk, /RealTimeProtectionEnabled/);
      assert.match(chunk, /AMRunningMode/);
      assert.match(chunk, /EnableControlledFolderAccess/);
    }
  });
});
