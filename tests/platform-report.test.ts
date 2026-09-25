import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  CLAIM,
  claimsForJob,
  derivePlatform,
  evidenceFromJob,
  formatPlatformReport,
  summaryFields,
  type ReportJob,
} from "../scripts/platform-report.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const sha = "87ebc4b0c0ffee87ebc4b0c0ffee87ebc4b0c0ff";
const date = "2026-09-25";
const statement = `This table is generated from CI for commit ${sha} on ${date}, and only these platforms are claimed.`;

const jobs: ReportJob[] = [
  {
    name: "windows (localized)",
    conclusion: "success",
    htmlUrl: "https://github.com/verax-ai/verax/actions/runs/10/job/1",
    platform: "Windows (windows-latest)",
    architecture: "x64",
    checked: claimsForJob("install-e2e", "windows (localized)"),
  },
  {
    name: "linux (ubuntu-24.04-arm)",
    conclusion: "failure",
    htmlUrl: "https://github.com/verax-ai/verax/actions/runs/10/job/2",
    platform: "Linux (ubuntu-24.04-arm)",
    architecture: "arm64",
    checked: claimsForJob("install-e2e", "linux (ubuntu-24.04-arm)"),
  },
  {
    name: "installed (macos-latest)",
    conclusion: "cancelled",
    htmlUrl: "https://github.com/verax-ai/verax/actions/runs/11/job/3",
    platform: "macOS (macos-latest)",
    architecture: "arm64",
    checked: claimsForJob("pack-smoke", "installed (macos-latest)"),
  },
];

describe("platform report", () => {
  it("shows failures, keeps a run URL on every row, and names only the listed platforms", () => {
    const { markdown, json, document } = formatPlatformReport({ sha, date, jobs });
    assert.equal(document.statement, statement);
    assert.match(markdown, /only these platforms are claimed/);
    assert.equal(markdown.includes("every platform"), false);
    assert.equal(markdown.includes("all systems"), false);
    assert.equal(document.rows.length, 3);
    assert.deepEqual(
      document.rows.map((row) => row.result),
      ["success", "failed", "failed"],
    );
    assert.deepEqual(
      document.rows.map((row) => row.conclusion),
      ["success", "failure", "cancelled"],
    );
    assert.deepEqual(
      document.rows.map((row) => row.job),
      ["windows (localized)", "linux (ubuntu-24.04-arm)", "installed (macos-latest)"],
    );
    for (const row of document.rows) {
      assert.match(row.runUrl, /^https:\/\/github\.com\//);
    }
    const parsed = JSON.parse(json) as { statement: string; rows: Array<{ result: string; runUrl: string; job: string }> };
    assert.equal(parsed.statement, statement);
    assert.equal(parsed.rows.length, 3);
    assert.deepEqual(
      parsed.rows.map((row) => row.job),
      document.rows.map((row) => row.job),
    );
    const tableRows = markdown
      .split("\n")
      .filter((line) => line.startsWith("| ") && !line.startsWith("| Platform") && !line.startsWith("| ---"));
    assert.equal(tableRows.length, 3);
    for (const row of tableRows) {
      assert.match(row, /https:\/\/github\.com\//);
    }
    assert.match(markdown, /windows \(localized\)/);
    assert.match(markdown, /linux \(ubuntu-24\.04-arm\)/);
    assert.match(markdown, /installed \(macos-latest\)/);
    assert.equal(markdown.split("| failed |").length - 1, 2);
    assert.equal(markdown.split("| success |").length - 1, 1);
    assert.match(markdown, /a non-admin user racing the install cannot plant inside the Verax root/);
    assert.match(markdown, /the npm packages install cleanly and init \/ serve \/ a tool call \/ verify work/);
  });

  it("refuses a row that has no run URL", () => {
    assert.throws(
      () => formatPlatformReport({ sha, date, jobs: [{ ...jobs[1]!, htmlUrl: "" }] }),
      /without a run URL/,
    );
  });

  it("keeps the Windows-only claims off Linux, macOS and pack-smoke", () => {
    assert.ok(claimsForJob("install-e2e", "windows (default)").includes(CLAIM.plantedDir));
    assert.ok(claimsForJob("install-e2e", "windows (localized)").includes(CLAIM.installRace));
    for (const name of ["linux (ubuntu-24.04)", "linux (ubuntu-22.04)", "linux (ubuntu-24.04-arm)", "macos (macos-15)", "macos (macos-13)"]) {
      const claims = claimsForJob("install-e2e", name);
      assert.equal(claims.includes(CLAIM.plantedDir), false, name);
      assert.equal(claims.includes(CLAIM.installRace), false, name);
      assert.equal(claims.includes(CLAIM.service), true, name);
    }
    assert.deepEqual(claimsForJob("pack-smoke", "installed (ubuntu-latest)"), [CLAIM.packSmoke]);
    assert.deepEqual(claimsForJob("pack-smoke", "installed (macos-latest)"), [CLAIM.packSmoke]);
  });

  it("reads an OS line from the payload and otherwise derives one from the runner label", () => {
    assert.deepEqual(summaryFields({ name: "linux (ubuntu-24.04)", labels: ["ubuntu-24.04"] }), {
      os: null,
      arch: null,
      claims: null,
    });
    const carried = summaryFields({
      steps: [
        {
          name: "platform evidence",
          text: "OS: Ubuntu 24.04.2 LTS\nArchitecture: aarch64\n✅ installs as a separate service account and starts the service\n",
        },
      ],
    });
    assert.equal(carried.os, "Ubuntu 24.04.2 LTS");
    assert.equal(carried.arch, "aarch64");
    assert.deepEqual(carried.claims, ["✅ installs as a separate service account and starts the service"]);
    const fromSummary = evidenceFromJob("install-e2e", {
      name: "linux (ubuntu-24.04-arm)",
      conclusion: "failure",
      html_url: "https://github.com/verax-ai/verax/actions/runs/10/job/9",
      labels: ["ubuntu-24.04-arm"],
      text: "OS: Ubuntu 24.04.2 LTS\nArchitecture: aarch64\n❌ installs as a separate service account and starts the service\n",
    });
    assert.equal(fromSummary.platform, "Ubuntu 24.04.2 LTS");
    assert.equal(fromSummary.architecture, "aarch64");
    assert.equal(fromSummary.conclusion, "failure");
    const derived = evidenceFromJob("install-e2e", {
      name: "linux (ubuntu-24.04-arm)",
      conclusion: "success",
      html_url: "https://github.com/verax-ai/verax/actions/runs/10/job/8",
      labels: ["ubuntu-24.04-arm"],
    });
    assert.deepEqual(derivePlatform("linux (ubuntu-24.04-arm)", ["ubuntu-24.04-arm"]), {
      platform: "Linux (ubuntu-24.04-arm)",
      architecture: "arm64",
    });
    assert.equal(derived.platform, "Linux (ubuntu-24.04-arm)");
    assert.equal(derived.architecture, "arm64");
    assert.equal(derivePlatform("macos (macos-13)", ["macos-13"]).architecture, "x64");
    assert.equal(derivePlatform("macos (macos-15)", ["macos-15"]).architecture, "arm64");
    assert.equal(derivePlatform("windows (localized)", ["windows-latest"]).platform, "Windows (windows-latest)");
    assert.equal(derivePlatform("installed (ubuntu-latest)", ["ubuntu-latest"]).architecture, "x64");
    assert.equal(derivePlatform("installed (macos-latest)", ["macos-latest"]).architecture, "arm64");
    assert.equal(derivePlatform("installed (windows-latest)", ["windows-latest"]).platform, "Windows (windows-latest)");
  });

  it("the workflows publish the same claims the table lists, on a step that always runs", () => {
    const install = readFileSync(join(root, ".github", "workflows", "install-e2e.yml"), "utf8").replace(/\r\n/g, "\n");
    const pack = readFileSync(join(root, ".github", "workflows", "pack-smoke.yml"), "utf8").replace(/\r\n/g, "\n");
    assert.equal(install.includes("Write-Error"), false);
    assert.equal(pack.includes("Write-Error"), false);
    const linuxAt = install.indexOf("\n  linux:\n");
    const macosAt = install.indexOf("\n  macos:\n");
    assert.ok(linuxAt > 0 && macosAt > linuxAt);
    const windows = install.slice(0, linuxAt);
    const linux = install.slice(linuxAt, macosAt);
    const macos = install.slice(macosAt);
    for (const claim of claimsForJob("install-e2e", "windows (localized)")) {
      assert.ok(windows.includes(claim), `windows job missing: ${claim}`);
    }
    for (const part of [windows, linux, macos]) {
      assert.match(part, /if: always\(\)/);
      assert.match(part, /GITHUB_STEP_SUMMARY/);
      assert.match(part, /steps\.install-probe\.outcome/);
    }
    assert.match(windows, /\(Get-CimInstance Win32_OperatingSystem\)\.Caption/);
    assert.match(windows, /\(Get-CimInstance Win32_OperatingSystem\)\.Version/);
    assert.match(windows, /steps\.planted-dir\.outcome/);
    assert.match(windows, /steps\.install-race\.outcome/);
    assert.match(windows, /Matrix leg: names:/);
    assert.equal(linux.includes(CLAIM.installRace), false);
    assert.equal(linux.includes(CLAIM.plantedDir), false);
    assert.equal(macos.includes(CLAIM.installRace), false);
    assert.equal(macos.includes(CLAIM.plantedDir), false);
    assert.match(linux, /\/etc\/os-release/);
    assert.match(linux, /PRETTY_NAME/);
    assert.match(macos, /sw_vers/);
    for (const claim of claimsForJob("install-e2e", "linux (ubuntu-24.04)")) {
      assert.ok(linux.includes(claim), claim);
      assert.ok(macos.includes(claim), claim);
    }
    assert.match(pack, /if: always\(\)/);
    assert.match(pack, /GITHUB_STEP_SUMMARY/);
    assert.match(pack, /steps\.pack-smoke-windows\.outcome/);
    assert.match(pack, /steps\.pack-smoke-posix\.outcome/);
    assert.ok(pack.includes(CLAIM.packSmoke));
    assert.match(pack, /\(Get-CimInstance Win32_OperatingSystem\)\.Caption/);
    assert.match(pack, /\/etc\/os-release/);
    assert.match(pack, /sw_vers/);
    assert.match(pack, /Write-Host/);
  });
});
