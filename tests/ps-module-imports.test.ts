import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { LOCAL_ACCOUNT_SIDS_COMMAND } from "../packages/body/src/desktop.ts";
import { planInstall, systemToolName, windowsPowerShellScripts } from "../packages/body/src/install.ts";
import { PS_MODULES, psModuleImportLine, type PsModule } from "../packages/body/src/ps-module-imports.ts";

/**
 * Cmdlets this product runs, and the module that defines them on Windows PowerShell 5.1.
 * A name in a generated script must be here, in CORE_CMDLETS, or a `function` declared in that script.
 */
const CMDLET_MODULE = {
  "ConvertFrom-Json": "Microsoft.PowerShell.Utility",
  "ConvertTo-Json": "Microsoft.PowerShell.Utility",
  "Compare-Object": "Microsoft.PowerShell.Utility",
  "Sort-Object": "Microsoft.PowerShell.Utility",
  "New-TimeSpan": "Microsoft.PowerShell.Utility",
  "Get-Item": "Microsoft.PowerShell.Management",
  "Get-ItemProperty": "Microsoft.PowerShell.Management",
  "Join-Path": "Microsoft.PowerShell.Management",
  "Remove-Item": "Microsoft.PowerShell.Management",
  "ConvertTo-SecureString": "Microsoft.PowerShell.Security",
  "Get-Acl": "Microsoft.PowerShell.Security",
  "Enable-LocalUser": "Microsoft.PowerShell.LocalAccounts",
  "Get-LocalUser": "Microsoft.PowerShell.LocalAccounts",
  "New-LocalUser": "Microsoft.PowerShell.LocalAccounts",
  "Remove-LocalGroupMember": "Microsoft.PowerShell.LocalAccounts",
  "Set-LocalUser": "Microsoft.PowerShell.LocalAccounts",
  "New-ScheduledTaskAction": "ScheduledTasks",
  "New-ScheduledTaskSettingsSet": "ScheduledTasks",
  "New-ScheduledTaskTrigger": "ScheduledTasks",
  "Register-ScheduledTask": "ScheduledTasks",
  "Start-ScheduledTask": "ScheduledTasks",
} as const satisfies Record<string, PsModule>;

/**
 * Engine cmdlets. Import-Module is how the other modules load; it does not itself need one.
 * Where-Object, ForEach-Object, Select-Object, Write-Output, Out-Null, New-Object, and
 * Get-Command are on this list because resolving them does not need an explicit module import.
 */
const CORE_CMDLETS = new Set([
  "Where-Object",
  "ForEach-Object",
  "Select-Object",
  "Write-Output",
  "Out-Null",
  "New-Object",
  "Get-Command",
  "Set-StrictMode",
  "Import-Module",
]);

// A command name starts with a PowerShell verb (Get-Verb), plus the few
// unapproved ones built-in cmdlets use. Matching any Capital-Capital pair
// read a regex class such as [A-Za-z] as a command.
const PS_VERBS = [
  "Add", "Approve", "Assert", "Backup", "Block", "Build", "Checkpoint", "Clear", "Close", "Compare",
  "Complete", "Compress", "Confirm", "Connect", "Convert", "ConvertFrom", "ConvertTo", "Copy", "Debug",
  "Deny", "Deploy", "Disable", "Disconnect", "Dismount", "Edit", "Enable", "Enter", "Exit", "Expand",
  "Export", "Find", "Format", "Get", "Grant", "Group", "Hide", "Import", "Initialize", "Install",
  "Invoke", "Join", "Limit", "Lock", "Measure", "Merge", "Mount", "Move", "New", "Open", "Optimize",
  "Out", "Ping", "Pop", "Protect", "Publish", "Push", "Read", "Receive", "Redo", "Register", "Remove",
  "Rename", "Repair", "Request", "Reset", "Resize", "Resolve", "Restart", "Restore", "Resume", "Revoke",
  "Save", "Search", "Select", "Send", "Set", "Show", "Skip", "Split", "Start", "Step", "Stop", "Submit",
  "Suspend", "Switch", "Sync", "Test", "Trace", "Unblock", "Undo", "Uninstall", "Unlock", "Unprotect",
  "Unpublish", "Unregister", "Update", "Use", "Wait", "Watch", "Write",
  // Unapproved verbs on built-in cmdlets, and the verb of this tree's own script function.
  "ForEach", "Normalize", "Sort", "Tee", "Where",
];
const VERB_NOUN = new RegExp(`\\b(?:${PS_VERBS.join("|")})-[A-Z][A-Za-z0-9]*\\b`, "g");

const EXPECT_CMDLET: Record<string, string | null> = {
  "machine-roots": "Get-Item",
  sddl: "Get-Acl",
  "sddl-batch": "ConvertFrom-Json",
  "acl-owner": "Get-Acl",
  "directory-owner-sid": "Get-Acl",
  "service-sid": "Get-LocalUser",
  "profile-image-path": "Get-ItemProperty",
  "account-create": "New-LocalUser",
  "account-update": "Set-LocalUser",
  "scheduled-task": "Register-ScheduledTask",
  "desktop-local-account-sids": null,
};

function localFunctions(script: string): Set<string> {
  const names = new Set<string>();
  for (const match of script.matchAll(/\bfunction\s+([A-Z][A-Za-z0-9]*-[A-Z][A-Za-z0-9]*)\b/g)) {
    names.add(match[1] ?? "");
  }
  return names;
}

function verbNouns(script: string): string[] {
  return [...script.matchAll(VERB_NOUN)].map((match) => match[0] ?? "");
}

function checkScript(label: string, script: string): void {
  const local = localFunctions(script);
  const unknown: string[] = [];
  const seen = new Set<string>();
  for (const name of verbNouns(script)) {
    if (seen.has(name)) continue;
    seen.add(name);
    if (name in CMDLET_MODULE || CORE_CMDLETS.has(name) || local.has(name)) continue;
    unknown.push(name);
  }
  if (unknown.length > 0) {
    throw new Error(`${label}: unclassified Verb-Noun: ${unknown.join(", ")}`);
  }

  for (const [cmdlet, module] of Object.entries(CMDLET_MODULE)) {
    const at = new RegExp(`\\b${cmdlet}\\b`).exec(script)?.index ?? -1;
    if (at < 0) continue;
    const imported = script.indexOf(psModuleImportLine(module));
    if (imported < 0 || imported >= at) {
      throw new Error(`${label}: ${cmdlet} at ${at} needs ${module} import before it (import at ${imported})`);
    }
  }
}

function powershellToolCalls(source: string): number {
  let count = 0;
  for (const match of source.matchAll(/toolArgv\(\s*/g)) {
    const start = (match.index ?? 0) + match[0].length;
    if (source.startsWith('"powershell"', start)) count += 1;
  }
  return count;
}

function planCommands(winAccount?: { exists: boolean; createdByUs: boolean }): string[] {
  const plan = planInstall("win32", {
    ProgramFiles: "C:\\Program Files",
    ProgramData: "C:\\ProgramData",
    USERPROFILE: "C:\\Users\\operator",
    USERNAME: "operator",
    USERDOMAIN: "DESKTOP",
  }, {
    port: 8801,
    days: 30,
    force: false,
    execPath: "C:\\Program Files\\nodejs\\node.exe",
    bodyVersion: "0.3.0",
    npmCli: "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js",
    stateExists: false,
    userSid: "S-1-5-21-1001",
    winAccount,
  });
  if (!plan.ok) throw new Error(plan.message);
  const scripts: string[] = [];
  for (const op of plan.ops) {
    if (op.op !== "argv" || systemToolName(op.argv[0] ?? "") !== "powershell") continue;
    const script = op.argv[op.argv.lastIndexOf("-Command") + 1];
    if (!script) throw new Error("powershell argv has no -Command script");
    scripts.push(script);
  }
  return scripts;
}

describe("PowerShell module imports", () => {
  it("names each module directory under System32, including LocalAccounts without a version folder", () => {
    for (const module of PS_MODULES) {
      const line = psModuleImportLine(module);
      assert.equal(line.includes(".psd1"), false, line);
      assert.equal(line.includes("1.0.0.0"), false, line);
      assert.equal(line.endsWith(`\\Modules\\${module}"`), true, line);
    }
  });

  it("imports each non-Core module before the first use of its cmdlets", () => {
    const scripts = [
      ...windowsPowerShellScripts(),
      { id: "desktop-local-account-sids", script: LOCAL_ACCOUNT_SIDS_COMMAND },
    ];
    assert.deepEqual(scripts.map((item) => item.id), Object.keys(EXPECT_CMDLET));
    for (const item of scripts) {
      const expected = EXPECT_CMDLET[item.id];
      if (expected === undefined) throw new Error(`missing expectation for ${item.id}`);
      if (expected === null) {
        const mapped = verbNouns(item.script).filter((name) => name in CMDLET_MODULE);
        assert.deepEqual(mapped, [], item.id);
      } else {
        assert.match(item.script, new RegExp(`\\b${expected}\\b`));
      }
      checkScript(item.id, item.script);
    }
    const update = scripts.find((item) => item.id === "account-update")?.script ?? "";
    assert.equal(update.includes("New-LocalUser"), false);
    const created = planCommands();
    const existing = planCommands({ exists: true, createdByUs: true });
    assert.equal(created.length, 2);
    assert.equal(existing.length, 2);
    assert.match(created.join("\n"), /\bNew-LocalUser\b/);
    assert.equal(existing.join("\n").includes("New-LocalUser"), false);
    assert.match(existing.join("\n"), /\bSet-LocalUser\b/);
    for (const script of [...created, ...existing]) checkScript("plan", script);
  });

  it("names a Verb-Noun that is neither mapped nor Core", () => {
    assert.throws(() => checkScript("probe", "Get-Clipboard"), /Get-Clipboard/);
  });

  it("fails when a mapped cmdlet precedes its module import", () => {
    const late = `Get-Acl\n${psModuleImportLine("Microsoft.PowerShell.Security")}`;
    assert.throws(() => checkScript("late", late), /Get-Acl/);
  });

  it("counts every powershell toolArgv in the body sources", () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src");
    const install = readFileSync(join(root, "install.ts"), "utf8");
    const desktop = readFileSync(join(root, "desktop.ts"), "utf8");
    // readWindowsMachineRoots, windowsSddlArgv, windowsSddlBatchArgv, powershellStdin,
    // ownerModeLine, execute service SID, directoryOwnerSid, ProfileImagePath, windowsServiceSid,
    // and desktop localAccountSids. A new call site has to join windowsPowerShellScripts.
    assert.equal(powershellToolCalls(install), 9, install);
    assert.equal(powershellToolCalls(desktop), 1, desktop);
  });
});
