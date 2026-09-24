import { strict as assert } from "node:assert";
import { existsSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { Server } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { loadApprovalsFromDir } from "@verax-ai/proxy";
import { runDemo } from "../packages/body/src/demo.ts";
import { runVerify } from "../packages/body/src/verify-cli.ts";

const BANNED =
  /\b(secure|secures|protects|isolates|tamper-proof|compliant|compliance-ready|unique|only|first|best|guarantee|military-grade)\b/i;

const DEMO_MS = 15_000;
const root = join(dirname(fileURLToPath(import.meta.url)), "..");

type Claims = {
  decision: string;
  reasonCode: string;
  subject: string;
};

function ioFor(opts: { isTTY?: boolean; answer?: string | string[] } = {}) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const answers =
    opts.answer === undefined ? undefined : Array.isArray(opts.answer) ? opts.answer : [opts.answer];
  const stdin =
    answers !== undefined
      ? Readable.from(answers.map((answer) => (answer.endsWith("\n") ? answer : `${answer}\n`)))
      : new Readable({
          read() {
            this.push(null);
          },
        });
  return {
    stdout: {
      write(s: string) {
        stdout.push(s);
        return true;
      },
    },
    stderr: {
      write(s: string) {
        stderr.push(s);
        return true;
      },
    },
    stdin,
    isTTY: opts.isTTY ?? false,
    out: () => stdout.join(""),
    err: () => stderr.join(""),
    both: () => `${stdout.join("")}${stderr.join("")}`,
  };
}

function keepDir(text: string): string | null {
  const m = /verax verify (\S+)/.exec(text);
  return m ? m[1]! : null;
}

const DEMO_PREFIX = "verax-demo-body-";

function runOwnedDemo(argv: string[], env: NodeJS.ProcessEnv, io: Parameters<typeof runDemo>[2]): Promise<number> {
  return runDemo(argv, env, io, { statePrefix: DEMO_PREFIX });
}

function demoDirs(): string[] {
  return readdirSync(tmpdir()).filter((name) => name.startsWith(DEMO_PREFIX));
}

function readDecisions(dir: string): Claims[] {
  const path = join(dir, "decisions.jsonl");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => (JSON.parse(line) as { claims: Claims }).claims);
}

function walkFiles(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walkFiles(full, out);
    else out.push(full);
  }
  return out;
}

function removeDir(dir: string | null): void {
  if (!dir) return;
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    // leftover for the OS temp cleaner
  }
}

function installTokenSpy(): { tokens: Set<string>; restore: () => void } {
  const tokens = new Set<string>();
  const orig = globalThis.fetch;
  const add = (raw: string | null | undefined) => {
    if (!raw) return;
    const m = /^Bearer\s+(\S+)/i.exec(raw);
    if (m) tokens.add(m[1]!);
  };
  globalThis.fetch = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    if (input instanceof Request) add(input.headers.get("authorization"));
    const headers = init?.headers;
    if (headers instanceof Headers) add(headers.get("authorization"));
    else if (Array.isArray(headers)) {
      for (const [key, value] of headers) {
        if (key.toLowerCase() === "authorization") add(value);
      }
    } else if (headers && typeof headers === "object") {
      for (const [key, value] of Object.entries(headers)) {
        if (key.toLowerCase() === "authorization" && typeof value === "string") add(value);
      }
    }
    return orig(input, init);
  }) as typeof fetch;
  return {
    tokens,
    restore: () => {
      globalThis.fetch = orig;
    },
  };
}

function installListenSpy(): { hosts: Array<string | undefined>; restore: () => void } {
  const hosts: Array<string | undefined> = [];
  const orig = Server.prototype.listen;
  Server.prototype.listen = function (...args: unknown[]) {
    let host: string | undefined;
    const first = args[0];
    if (first && typeof first === "object" && !Array.isArray(first) && "host" in first) {
      const named = (first as { host?: unknown }).host;
      host = typeof named === "string" ? named : undefined;
    } else if (typeof args[1] === "string") {
      host = args[1];
    }
    hosts.push(host);
    return orig.apply(this, args as never);
  };
  return {
    hosts,
    restore: () => {
      Server.prototype.listen = orig;
    },
  };
}

describe("verax demo", { concurrency: 1 }, () => {
  it("T1: TTY-less run exits 0 with allow, one deny, one held spend", { timeout: DEMO_MS }, async () => {
    const started = Date.now();
    const io = ioFor();
    const code = await runOwnedDemo(["demo", "--keep"], {}, io);
    const dir = keepDir(io.out());
    try {
      assert.equal(code, 0, io.err());
      assert.ok(dir && existsSync(dir), io.out());
      const recs = readDecisions(dir!);
      assert.ok(
        recs.some((r) => r.decision === "allow"),
        JSON.stringify(recs),
      );
      const denies = recs.filter((r) => r.decision === "deny");
      assert.equal(denies.length, 1, JSON.stringify(denies));
      assert.ok(denies[0]!.reasonCode.length > 0);
      const pending = loadApprovalsFromDir(dir!).filter((r) => r.subject === "spend" && r.status === "pending");
      assert.equal(pending.length, 1, JSON.stringify(pending));
      assert.ok(Date.now() - started <= DEMO_MS);
    } finally {
      removeDir(dir);
    }
  });

  it("T2: token string stays off stdout+stderr and disk; JWT key is not a file", { timeout: DEMO_MS }, async () => {
    const spy = installTokenSpy();
    const io = ioFor();
    let dir: string | null = null;
    try {
      const code = await runOwnedDemo(["demo", "--keep"], {}, io);
      assert.equal(code, 0, io.err());
      dir = keepDir(io.out());
      assert.ok(dir && existsSync(dir), io.out());
      assert.ok(spy.tokens.size > 0, "token spy caught nothing");
      const printed = io.both();
      for (const token of spy.tokens) {
        assert.equal(printed.includes(token), false, "token leaked to output");
        for (const file of walkFiles(dir!)) {
          let text = "";
          try {
            text = readFileSync(file, "utf8");
          } catch {
            continue;
          }
          assert.equal(text.includes(token), false, `token in ${file}`);
        }
      }
      assert.equal(existsSync(join(dir!, "jwks.json")), false);
      assert.deepEqual(readdirSync(join(dir!, "keys")).sort(), [
        "effect.private.pem",
        "effect.public.pem",
        "record.private.pem",
        "record.public.pem",
      ]);
    } finally {
      spy.restore();
      removeDir(dir);
    }
  });

  it("T3: default run removes the temp dir; --keep leaves it and verify returns 0", { timeout: DEMO_MS * 2 }, async () => {
    const before = new Set(demoDirs());
    const goneIo = ioFor();
    const goneCode = await runOwnedDemo(["demo"], {}, goneIo);
    assert.equal(goneCode, 0, goneIo.err());
    const leftover = demoDirs().filter((name) => !before.has(name));
    assert.deepEqual(leftover, [], leftover.join(", "));

    const keepIo = ioFor();
    const keepCode = await runOwnedDemo(["demo", "--keep"], {}, keepIo);
    const dir = keepDir(keepIo.out());
    try {
      assert.equal(keepCode, 0, keepIo.err());
      assert.ok(dir && existsSync(dir), keepIo.out());
      const verified = await runVerify([dir!], () => undefined);
      assert.equal(verified, 0);
    } finally {
      removeDir(dir);
    }
  });

  it("T4: NODE_ENV=production exits non-zero and listens on no port", { timeout: 5_000 }, async () => {
    const listen = installListenSpy();
    const io = ioFor();
    try {
      const code = await runOwnedDemo(["demo"], { NODE_ENV: "production" }, io);
      assert.notEqual(code, 0);
      assert.equal(listen.hosts.length, 0, JSON.stringify(listen.hosts));
    } finally {
      listen.restore();
    }
  });

  it("T5: TTY y binds an operator id; TTY N leaves spend held", { timeout: DEMO_MS * 3 }, async () => {
    const yesIo = ioFor({ isTTY: true, answer: ["y", "100"] });
    const yesCode = await runOwnedDemo(["demo", "--keep"], {}, yesIo);
    const yesDir = keepDir(yesIo.out());
    try {
      assert.equal(yesCode, 0, yesIo.err());
      assert.ok(yesDir);
      const approved = loadApprovalsFromDir(yesDir!).filter((r) => r.subject === "spend");
      assert.equal(approved.length, 1, JSON.stringify(approved));
      assert.equal(approved[0]!.status, "approved");
      const rows = readFileSync(join(yesDir!, "inputs.jsonl"), "utf8")
        .split("\n")
        .filter((line) => line !== "")
        .map(
          (line) =>
            JSON.parse(line) as {
              inputs: { approver?: { id?: string; via?: string } };
            },
        );
      const bound = rows.find((row) => (row.inputs.approver?.id ?? "") !== "");
      assert.ok(bound, "approver id missing from inputs");
      assert.equal(bound!.inputs.approver!.via, "cli");
    } finally {
      removeDir(yesDir);
    }

    const wrongIo = ioFor({ isTTY: true, answer: ["y", "999"] });
    const beforeWrong = new Set(demoDirs());
    const wrongCode = await runOwnedDemo(["demo", "--keep"], {}, wrongIo);
    const wrongName = demoDirs().find((name) => !beforeWrong.has(name)) ?? null;
    const wrongDir = wrongName ? join(tmpdir(), wrongName) : null;
    try {
      assert.notEqual(wrongCode, 0, wrongIo.out());
      assert.ok(wrongDir && existsSync(wrongDir), wrongIo.err());
      const heldSpend = loadApprovalsFromDir(wrongDir!).filter((r) => r.subject === "spend");
      assert.equal(heldSpend.length, 1, JSON.stringify(heldSpend));
      assert.equal(heldSpend[0]!.status, "pending");
      assert.equal(
        readDecisions(wrongDir!).some((row) => row.decision === "allow" && row.subject === "spend"),
        false,
      );
    } finally {
      removeDir(wrongDir);
    }

    const noIo = ioFor({ isTTY: true, answer: "N" });
    const noCode = await runOwnedDemo(["demo", "--keep"], {}, noIo);
    const noDir = keepDir(noIo.out());
    try {
      assert.equal(noCode, 0, noIo.err());
      assert.ok(noDir);
      const held = loadApprovalsFromDir(noDir!).filter((r) => r.subject === "spend" && r.status === "pending");
      assert.equal(held.length, 1, JSON.stringify(held));
    } finally {
      removeDir(noDir);
    }
  });

  it("T6: listen addresses are loopback, not 0.0.0.0", { timeout: DEMO_MS }, async () => {
    const listen = installListenSpy();
    const io = ioFor();
    const code = await runOwnedDemo(["demo"], {}, io);
    try {
      assert.equal(code, 0, io.err());
      assert.ok(listen.hosts.length > 0, "listen was not called");
      for (const host of listen.hosts) {
        assert.ok(host === "127.0.0.1" || host === "::1" || host === "[::1]", `host=${String(host)}`);
      }
    } finally {
      listen.restore();
    }
  });

  it("T7: output is at most 40 lines and carries none of the banned words", { timeout: DEMO_MS }, async () => {
    const io = ioFor();
    const code = await runOwnedDemo(["demo"], {}, io);
    assert.equal(code, 0, io.err());
    const text = io.both();
    const lines = text.split(/\r?\n/).filter((line) => line !== "");
    assert.ok(lines.length <= 40, `lines=${lines.length}\n${text}`);
    assert.equal(BANNED.test(text), false, text);
  });

  it("T8: a TTY-less run finishes within 15s", { timeout: DEMO_MS }, async () => {
    const started = Date.now();
    const io = ioFor();
    const code = await runOwnedDemo(["demo"], {}, io);
    const elapsed = Date.now() - started;
    assert.equal(code, 0, io.err());
    assert.ok(elapsed <= DEMO_MS, `elapsed=${elapsed}`);
  });

  // docs/demo.svg is a recording the README shows. It is a second copy of what
  // the command prints, so it is held against a run: same words, same order.
  it("T9: docs/demo.svg carries what a terminal run answered with y prints", { timeout: DEMO_MS }, async () => {
    const io = ioFor({ isTTY: true, answer: ["y", "100"] });
    const code = await runOwnedDemo(["demo"], {}, io);
    assert.equal(code, 0, io.err());

    const words = (s: string) =>
      s
        .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, "<ref>")
        .split(/\s+/)
        .filter((w) => w !== "")
        .join(" ");
    const unescape = (s: string) =>
      s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, "&");

    const svg = readFileSync(join(root, "docs", "demo.svg"), "utf8");
    const shown = [...svg.matchAll(/<text\b[^>]*>(.*?)<\/text>/gs)].map((m) => unescape(m[1]!.replace(/<[^>]+>/g, "")));
    assert.ok(shown.length > 0, "no <text> rows in docs/demo.svg");

    // The answer is typed, not printed; the recording shows it after the question.
    const printed = io.out().replace("[y/N]", "[y/N] y ");
    assert.equal(words(shown.join("\n")), words(`$ npx @verax-ai/body demo\n${printed}`));
  });
});
