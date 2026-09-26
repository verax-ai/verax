// R9: each class already found, looked for again where the fix did not touch.
// Each `it` asserts the safe behaviour. On the current tree the
// implementation does the unsafe thing, so the assertion fails. A fix
// should turn that assertion green without weakening it.

import { strict as assert } from "node:assert";
import { mkdtempSync, mkdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { tenantKey } from "@verax-ai/proxy";

import { messageSend } from "../packages/body/src/tools/message.ts";
import {
  linuxSelinuxCheck,
  planInstall,
  runUninstall,
  serviceAclFiles,
  systemToolName,
} from "../packages/body/src/install.ts";
import type { ExecResult, PlanOp } from "../packages/body/src/install.ts";

const linuxEnv = {
  SUDO_USER: "runner",
  VERAX_INVOKING_HOME: "/home/runner",
};

const linuxOpts = {
  port: 8801,
  days: 30,
  force: false,
  execPath: "/usr/bin/node",
  bodyVersion: "0.3.0",
  npmCli: "/usr/lib/node_modules/npm/bin/npm-cli.js",
  stateExists: false,
  linuxAccount: { exists: false, createdByUs: false, createdGroup: false },
};

function toolOf(argv: readonly string[]): string {
  return systemToolName(argv[0] ?? "");
}

function argvOf(ops: readonly PlanOp[], tool: string): string[] | undefined {
  for (const op of ops) {
    if (op.op === "argv" && toolOf(op.argv) === tool) return op.argv;
  }
  return undefined;
}

function deleted(seen: readonly string[][], tool: string, arg: string): boolean {
  return seen.some((argv) => toolOf(argv) === tool && argv.includes(arg));
}

describe("attack R9", () => {
  it("R9-1 a tenant outbox cannot grow without a cap", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-r9-outbox-"));
    try {
      const principal = { brain: "r9", scopes: new Set(["verax:act"]) };
      const text = "x".repeat(600_000);
      const send = (n: number) =>
        messageSend(
          { name: "message.send", arguments: { to: "ops@example.com", text } },
          dir,
          `r9-${n}`,
          principal,
        );
      const first = await send(1);
      assert.equal(first.isError, false);
      const second = await send(2);
      assert.equal(second.isError, true);
      const file = join(dir, "tenants", tenantKey(principal), "outbox.jsonl");
      assert.ok(statSync(file).size <= 1024 * 1024);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R9-2 Linux does not claim or delete the verax group without an explicit create and a recorded id", async () => {
    const plan = planInstall("linux", linuxEnv, linuxOpts);
    assert.equal(plan.ok, true, plan.ok ? "" : plan.message);
    if (plan.ok) {
      const useradd = argvOf(plan.ops, "useradd") ?? [];
      const pinsGroup =
        useradd.includes("-U") || useradd.includes("--user-group") || argvOf(plan.ops, "groupadd") !== undefined;
      assert.equal(pinsGroup, true);
    }

    const root = mkdtempSync(join(tmpdir(), "verax-r9-id-"));
    try {
      const posixRoot = root.replaceAll("\\", "/");
      mkdirSync(join(posixRoot, "opt", "verax"), { recursive: true });
      writeFileSync(
        `${posixRoot}/opt/verax/install.json`,
        `${JSON.stringify({
          version: "0.3.0",
          codeDir: `${posixRoot}/opt/verax`,
          createdUser: true,
          createdGroup: true,
          accountUid: 999,
          accountGid: 999,
        })}\n`,
      );
      const seen: string[][] = [];
      const out: string[] = [];
      const code = await runUninstall(["uninstall"], {
        platform: "linux",
        env: linuxEnv,
        posixRoot,
        elevated: () => true,
        exec: (argv): ExecResult => {
          seen.push([...argv]);
          const tool = toolOf(argv);
          if (tool === "getent" && argv[1] === "passwd" && argv[2] === "runner") {
            return { status: 0, stdout: "runner:x:1000:1000::/home/runner:/bin/bash\n", stderr: "" };
          }
          if (tool === "getent" && argv[1] === "passwd") {
            return { status: 0, stdout: "verax:x:480:480::/:/usr/sbin/nologin\n", stderr: "" };
          }
          if (tool === "getent" && argv[1] === "group") return { status: 0, stdout: "verax:x:480:\n", stderr: "" };
          if (tool === "id") return { status: 0, stdout: "uid=480(verax)\n", stderr: "" };
          if (tool === "systemctl") return { status: 1, stdout: "", stderr: "Unit verax.service not found.\n" };
          return { status: 1, stdout: "", stderr: "" };
        },
        io: {
          stdout: { write: (s: string) => out.push(s) },
          stderr: { write: (s: string) => out.push(s) },
        },
      });
      assert.equal(code, 0, out.join(""));
      assert.equal(deleted(seen, "userdel", "verax"), false, out.join(""));
      assert.equal(deleted(seen, "groupdel", "verax"), false, out.join(""));
      assert.match(out.join(""), /not removing account verax/);
      assert.match(out.join(""), /not removing group verax/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("R9-3 a failed delete with no output is not treated as the account already being gone", async () => {
    const root = mkdtempSync(join(tmpdir(), "verax-r9-empty-"));
    try {
      const posixRoot = root.replaceAll("\\", "/");
      mkdirSync(join(posixRoot, "opt", "verax"), { recursive: true });
      writeFileSync(
        `${posixRoot}/opt/verax/install.json`,
        `${JSON.stringify({ version: "0.3.0", codeDir: `${posixRoot}/opt/verax`, createdUser: true })}\n`,
      );
      const out: string[] = [];
      const code = await runUninstall(["uninstall"], {
        platform: "linux",
        env: linuxEnv,
        posixRoot,
        elevated: () => true,
        exec: (argv): ExecResult => {
          const tool = toolOf(argv);
          if (tool === "getent" && argv[1] === "passwd" && argv[2] === "runner") {
            return { status: 0, stdout: "runner:x:1000:1000::/home/runner:/bin/bash\n", stderr: "" };
          }
          if (tool === "getent" && argv[1] === "passwd") {
            return { status: 0, stdout: "verax:x:480:480::/:/usr/sbin/nologin\n", stderr: "" };
          }
          if (tool === "id") return { status: 0, stdout: "uid=480(verax)\n", stderr: "" };
          if (tool === "userdel") return { status: 1, stdout: "", stderr: "" };
          if (tool === "systemctl") return { status: 1, stdout: "", stderr: "Unit verax.service not found.\n" };
          return { status: 1, stdout: "", stderr: "" };
        },
        io: {
          stdout: { write: (s: string) => out.push(s) },
          stderr: { write: (s: string) => out.push(s) },
        },
      });
      const text = out.join("");
      assert.notEqual(code, 0, text);
      assert.doesNotMatch(text, /removed: account verax/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("R9-4 the code ACL read-back includes the service entrypoint", () => {
    const files = serviceAclFiles("verax-code-root", "code").map((file) => file.replaceAll("\\", "/"));
    assert.ok(files.some((file) => file.endsWith("node_modules/@verax-ai/body/dist/cli.js")));
  });

  it("R9-5 an enforcing host with an unknown service domain is not reported ok", () => {
    const check = linuxSelinuxCheck((argv) => {
      const file = argv[0] ?? "";
      if (file.endsWith("getenforce")) return { status: 0, stdout: "Enforcing\n", stderr: "" };
      if (file.endsWith("systemctl")) return { status: 0, stdout: "0\n", stderr: "" };
      return { status: 1, stdout: "", stderr: "" };
    });
    assert.notEqual(check.level, "ok");
    assert.match(check.detail, /unknown/);
  });
});
