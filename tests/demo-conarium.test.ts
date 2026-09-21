import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runDemo } from "../packages/body/src/demo.ts";
import { runVerify } from "../packages/body/src/verify-cli.ts";

// node --test runs files side by side, and tests/demo.test.ts counts the
// verax-demo-* directories left in the temp dir. This file makes them too, so
// it works under a temp root of its own: neither file's leftover check can see
// the other's runs. os.tmpdir() reads these on every call.
const privateTmp = mkdtempSync(join(tmpdir(), "verax-conarium-suite-"));
for (const name of ["TMPDIR", "TMP", "TEMP"]) process.env[name] = privateTmp;
after(() => rmSync(privateTmp, { recursive: true, force: true }));

const BANNED =
  /\b(secure|secures|protects|isolates|tamper-proof|compliant|compliance-ready|unique|only|first|best|guarantee|military-grade)\b/i;

const DEMO_MS = 20_000;
const stub = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "conarium-demo-stub.mjs");

type Claims = {
  decision: string;
  reasonCode: string;
  subject: string;
};

type CountEvent = {
  event: string;
  tool?: string;
  argv?: string[];
  env?: NodeJS.ProcessEnv;
};

function ioFor() {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const stdin = new Readable({
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
    isTTY: false,
    out: () => stdout.join(""),
    err: () => stderr.join(""),
    both: () => `${stdout.join("")}${stderr.join("")}`,
  };
}

function keepDir(text: string): string | null {
  const m = /verax verify (\S+)/.exec(text);
  return m ? m[1]! : null;
}

function demoDirs(): string[] {
  return readdirSync(tmpdir()).filter((name) => name.startsWith("verax-demo-"));
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

function readCounts(file: string): CountEvent[] {
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line) as CountEvent);
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

function childFor(countFile: string, extra: string[] = []) {
  return {
    command: process.execPath,
    args: [stub, "--count-file", countFile, ...extra],
  };
}

describe("verax demo --with-conarium", { concurrency: 1 }, () => {
  it("K1: a run without the flag still prints the old footer and no conarium.query", { timeout: DEMO_MS }, async () => {
    const io = ioFor();
    const code = await runDemo(["demo"], {}, io);
    assert.equal(code, 0, io.err());
    assert.match(io.out(), /data masking arrives with a downstream server such as Conarium/);
    assert.equal(io.out().includes("conarium.query"), false, io.out());
    assert.equal(io.out().includes("--with-conarium"), false, io.out());
  });

  it("K2: flagged run exits 0 and the ledger has two query allows and one list_tables deny", { timeout: DEMO_MS }, async () => {
    const countFile = join(mkdtempSync(join(tmpdir(), "verax-conarium-count-")), "count.jsonl");
    const io = ioFor();
    const code = await runDemo(["demo", "--with-conarium", "--keep"], {}, io, {
      conariumChild: childFor(countFile),
    });
    const dir = keepDir(io.out());
    try {
      assert.equal(code, 0, io.err());
      assert.ok(dir && existsSync(dir), io.out());
      const recs = readDecisions(dir!);
      const queries = recs.filter((r) => r.subject === "conarium.query");
      assert.equal(queries.length, 2, JSON.stringify(queries));
      assert.ok(
        queries.every((r) => r.decision === "allow"),
        JSON.stringify(queries),
      );
      const listed = recs.filter((r) => r.subject === "conarium.list_tables");
      assert.equal(listed.length, 1, JSON.stringify(listed));
      assert.equal(listed[0]!.decision, "deny", JSON.stringify(listed));
    } finally {
      removeDir(dir);
      removeDir(dirname(countFile));
    }
  });

  it("K3: list_tables never reaches the child; query is called twice", { timeout: DEMO_MS }, async () => {
    const countFile = join(mkdtempSync(join(tmpdir(), "verax-conarium-count-")), "count.jsonl");
    const io = ioFor();
    const code = await runDemo(["demo", "--with-conarium"], {}, io, {
      conariumChild: childFor(countFile),
    });
    try {
      assert.equal(code, 0, io.err());
      const calls = readCounts(countFile).filter((e) => e.event === "call");
      assert.equal(
        calls.filter((e) => e.tool === "list_tables").length,
        0,
        JSON.stringify(calls),
      );
      assert.equal(
        calls.filter((e) => e.tool === "query").length,
        2,
        JSON.stringify(calls),
      );
    } finally {
      removeDir(dirname(countFile));
    }
  });

  it("K4: unmasked rows skip the masked line and exit 1", { timeout: DEMO_MS }, async () => {
    const countFile = join(mkdtempSync(join(tmpdir(), "verax-conarium-count-")), "count.jsonl");
    const io = ioFor();
    const code = await runDemo(["demo", "--with-conarium"], {}, io, {
      conariumChild: childFor(countFile, ["--unmasked"]),
    });
    try {
      assert.equal(code, 1, io.err());
      assert.equal(io.out().includes("masked by Conarium"), false, io.out());
      assert.match(io.out(), /did not come out masked/);
    } finally {
      removeDir(dirname(countFile));
    }
  });

  it("K5: public.secrets comes back as Conarium's error, and the ledger row is allow", { timeout: DEMO_MS }, async () => {
    const countFile = join(mkdtempSync(join(tmpdir(), "verax-conarium-count-")), "count.jsonl");
    const io = ioFor();
    const code = await runDemo(["demo", "--with-conarium", "--keep"], {}, io, {
      conariumChild: childFor(countFile),
    });
    const dir = keepDir(io.out());
    try {
      assert.equal(code, 0, io.err());
      assert.match(io.out(), /allowed by this gate; Conarium answered with an error and no rows/);
      assert.match(io.out(), /recorded as a failed call/);
      assert.equal(/Verax[^\n]*mask/i.test(io.out()), false, io.out());
      const recs = readDecisions(dir!);
      const queries = recs.filter((r) => r.subject === "conarium.query");
      assert.equal(queries.length, 2, JSON.stringify(queries));
      assert.ok(
        queries.every((r) => r.decision === "allow"),
        JSON.stringify(queries),
      );
      assert.equal(
        recs.some((r) => r.subject === "conarium.query" && r.decision === "deny"),
        false,
        JSON.stringify(recs),
      );
    } finally {
      removeDir(dir);
      removeDir(dirname(countFile));
    }
  });

  it("K6: flagged stdout is at most 40 lines and carries none of the banned words", { timeout: DEMO_MS }, async () => {
    const countFile = join(mkdtempSync(join(tmpdir(), "verax-conarium-count-")), "count.jsonl");
    const io = ioFor();
    const code = await runDemo(["demo", "--with-conarium"], {}, io, {
      conariumChild: childFor(countFile),
    });
    try {
      assert.equal(code, 0, io.err());
      const text = io.out();
      const lines = text.split(/\r?\n/).filter((line) => line !== "");
      assert.ok(lines.length <= 40, `lines=${lines.length}\n${text}`);
      assert.equal(BANNED.test(text), false, text);
      assert.equal(/Verax[^\n]*mask/i.test(text), false, text);
    } finally {
      removeDir(dirname(countFile));
    }
  });

  it("K7: a missing child command exits 1, names --with-conarium, and removes the temp dir", { timeout: DEMO_MS }, async () => {
    const before = new Set(demoDirs());
    const missing = join(tmpdir(), "verax-no-such-conarium-child");
    const io = ioFor();
    const code = await runDemo(["demo", "--with-conarium", "--keep"], {}, io, {
      conariumChild: { command: missing, args: [] },
    });
    assert.equal(code, 1);
    assert.match(io.err(), /--with-conarium/);
    const leftover = demoDirs().filter((name) => !before.has(name));
    assert.deepEqual(leftover, [], leftover.join(", "));
  });

  it("K8: the token stays off stdout+stderr+disk and off the child's env and argv", { timeout: DEMO_MS }, async () => {
    const spy = installTokenSpy();
    const countFile = join(mkdtempSync(join(tmpdir(), "verax-conarium-count-")), "count.jsonl");
    const io = ioFor();
    let dir: string | null = null;
    try {
      const code = await runDemo(["demo", "--with-conarium", "--keep"], {}, io, {
        conariumChild: childFor(countFile),
      });
      assert.equal(code, 0, io.err());
      dir = keepDir(io.out());
      assert.ok(dir && existsSync(dir), io.out());
      assert.ok(spy.tokens.size > 0, "token spy caught nothing");
      const printed = io.both();
      const start = readCounts(countFile).find((e) => e.event === "start");
      assert.ok(start, "child start was not counted");
      const childDump = JSON.stringify({ argv: start.argv, env: start.env });
      for (const token of spy.tokens) {
        assert.equal(printed.includes(token), false, "token leaked to output");
        assert.equal(childDump.includes(token), false, "token leaked to the child");
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
      assert.equal(/authorization/i.test(childDump), false, childDump);
    } finally {
      spy.restore();
      removeDir(dir);
      removeDir(dirname(countFile));
    }
  });

  it("K9: NODE_ENV=production with the flag exits 1 and never starts the child", { timeout: 5_000 }, async () => {
    const countFile = join(mkdtempSync(join(tmpdir(), "verax-conarium-count-")), "count.jsonl");
    const io = ioFor();
    try {
      const code = await runDemo(["demo", "--with-conarium"], { NODE_ENV: "production" }, io, {
        conariumChild: childFor(countFile),
      });
      assert.notEqual(code, 0);
      assert.equal(existsSync(countFile), false, "child count file was created");
    } finally {
      removeDir(dirname(countFile));
    }
  });

  // The body tells the caller that a downstream tool answered with an error, not
  // what it said. A child that dies mid-call must not be reported as an answer.
  it("K11: a child that dies on the secrets query is not reported as Conarium's answer", { timeout: DEMO_MS }, async () => {
    const countFile = join(mkdtempSync(join(tmpdir(), "verax-conarium-count-")), "count.jsonl");
    const io = ioFor();
    const code = await runDemo(["demo", "--with-conarium"], {}, io, {
      conariumChild: childFor(countFile, ["--die-on-secrets"]),
    });
    try {
      assert.equal(code, 1, io.out());
      assert.equal(/Conarium answered with an error/.test(io.out()), false, io.out());
      assert.match(io.out(), /the call to Conarium failed before it answered/);
    } finally {
      removeDir(dirname(countFile));
    }
  });

  // The README carries both outputs as text. They are copies, so each is held
  // against a run: same words, same order, the ref id aside.
  it("K12: the two output blocks under See it run are what the two runs print", { timeout: DEMO_MS * 2 }, async () => {
    const words = (text: string) =>
      text
        .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, "<ref>")
        .split(/\s+/)
        .filter((w) => w !== "")
        .join(" ");
    const readme = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "README.md"), "utf8");
    const section = readme.slice(readme.indexOf("## See it run"), readme.indexOf("## What ships"));
    const blocks = [...section.matchAll(/```text\r?\n([\s\S]*?)```/g)].map((m) => m[1]!);
    assert.equal(blocks.length, 2, "See it run should carry two text blocks");

    const plain = ioFor();
    assert.equal(await runDemo(["demo"], {}, plain), 0, plain.err());
    assert.equal(words(blocks[0]!), words(plain.out()));

    const countFile = join(mkdtempSync(join(tmpdir(), "verax-conarium-count-")), "count.jsonl");
    const flagged = ioFor();
    try {
      const code = await runDemo(["demo", "--with-conarium"], {}, flagged, { conariumChild: childFor(countFile) });
      assert.equal(code, 0, flagged.err());
      assert.equal(words(blocks[1]!), words(flagged.out()));
    } finally {
      removeDir(dirname(countFile));
    }
  });

  it("K10: --with-conarium --keep then runVerify returns 0", { timeout: DEMO_MS }, async () => {
    const countFile = join(mkdtempSync(join(tmpdir(), "verax-conarium-count-")), "count.jsonl");
    const io = ioFor();
    const code = await runDemo(["demo", "--with-conarium", "--keep"], {}, io, {
      conariumChild: childFor(countFile),
    });
    const dir = keepDir(io.out());
    try {
      assert.equal(code, 0, io.err());
      assert.ok(dir && existsSync(dir), io.out());
      const verified = await runVerify([dir!], () => undefined);
      assert.equal(verified, 0);
    } finally {
      removeDir(dir);
      removeDir(dirname(countFile));
    }
  });
});
