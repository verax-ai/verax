// Text the body did not write itself (a downstream child's error message, a
// path, an argument) reaches the operator's terminal as escapes, never as
// the code points DISPLAY_ESCAPE_CLASS names. Measured on 57df933: a child
// answering `initialize` with an error put ESC, BEL, U+009B, U+202E and
// U+0338 on `verax serve`'s stderr through Node's uncaught-exception printer,
// with a stack trace, and the process ended with exit 1 or a crash code.
// The hostile text is built with String.fromCodePoint so this file stays ASCII.

import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { createServer, type Server as HttpServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import * as proxy from "@verax-ai/proxy";
import { DISPLAY_ESCAPE_CLASS } from "@verax-ai/proxy";
import { runDemo } from "../packages/body/src/demo.ts";
import { runInitLocal } from "../packages/body/src/init-local.ts";
import { skipIfElevated } from "./elevated-refusal.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");
const hostileStdioChild = join(root, "tests", "fixtures", "hostile-error-child.mjs");

const cp = (...points: number[]) => String.fromCodePoint(...points);
const HOSTILE =
  `boom${cp(0x1b)}]0;pwned${cp(0x07)}${cp(0x1b)}[2J${cp(0x9b)}2J${cp(0x202e)}KO${cp(0x338)}${cp(0xfe0f)}` +
  `${cp(0x0d)}${cp(0x0a)}listening 127.0.0.1:1`;
const ESCAPED = ["\\u001b", "\\u0007", "\\u009b", "\\u202e", "\\u0338", "\\ufe0f", "\\u000d", "\\u000a"];
const DRAWS_NOTHING = new RegExp(`[${DISPLAY_ESCAPE_CLASS}]`, "u");

const terminalText = (proxy as Record<string, unknown>).terminalText as ((text: string) => string) | undefined;
const terminalLines = (proxy as Record<string, unknown>).terminalLines as ((text: string) => string) | undefined;
const WRAPPERS = ["terminalText(", "terminalLines("];

const servers: HttpServer[] = [];
const dirs: string[] = [];
after(async () => {
  await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const hex = (n: number) => n.toString(16).padStart(4, "0");

/** Lines of what was written, the line ends removed. A line holds no code point of the class. */
function linesOf(text: string): string[] {
  return text.split(/\r?\n/).filter((line) => line !== "");
}

function rawCodePointsIn(text: string): string[] {
  const found: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    for (const ch of line) {
      if (DRAWS_NOTHING.test(ch)) found.push(`U+${hex(ch.codePointAt(0) ?? 0)}`);
    }
  }
  return found;
}

describe("terminalText (@verax-ai/proxy)", () => {
  it("is exported next to DISPLAY_ESCAPE_CLASS", () => {
    assert.equal(typeof terminalText, "function", "terminalText is not exported from @verax-ai/proxy");
  });

  it("writes every code point of the class as \\uXXXX, one escape per UTF-16 unit", () => {
    assert.equal(typeof terminalText, "function");
    for (const point of [0x00, 0x07, 0x09, 0x0a, 0x0d, 0x1b, 0x7f, 0x9b, 0xa0, 0x200b, 0x202e, 0x2028, 0x338, 0x3164, 0x2800, 0xfe0f]) {
      assert.equal(terminalText!(`a${cp(point)}b`), `a\\u${hex(point)}b`, `U+${hex(point)}`);
    }
    assert.equal(terminalText!(`a${cp(0xe0101)}b`), "a\\udb40\\udd01b", "a supplementary variation selector");
    assert.equal(terminalText!(`a${cp(0xf0000)}b`), "a\\udb80\\udc00b", "a supplementary private-use code point");
    assert.equal(terminalText!(`a${String.fromCharCode(0xd800)}b`), "a\\ud800b", "a lone surrogate");
  });

  it("leaves ASCII, a Windows path, quotes, Turkish letters and an emoji as they are", () => {
    assert.equal(typeof terminalText, "function");
    const plain = `downstream-attach-failed:rea: C:\\Users\\x "q" 'a' {b} ${cp(0xdc)}nl${cp(0xfc)} ${cp(0x131)}${cp(0x15f)}${cp(0x131)}k ${cp(0x1f642)}`;
    assert.equal(terminalText!(plain), plain);
  });

  it("leaves no code point of the class in its output, for every code point", () => {
    assert.equal(typeof terminalText, "function");
    for (let start = 0; start <= 0x10ffff; start += 0x1000) {
      let chunk = "";
      for (let point = start; point < Math.min(start + 0x1000, 0x110000); point += 1) {
        chunk += point >= 0xd800 && point <= 0xdfff ? String.fromCharCode(point) : cp(point);
      }
      const out = terminalText!(chunk);
      assert.equal(DRAWS_NOTHING.test(out), false, `a code point of the class is left in block U+${hex(start)}`);
      assert.equal(terminalText!(out), out, `not stable on its own output in block U+${hex(start)}`);
    }
  });
});

describe("terminalLines (@verax-ai/proxy)", () => {
  it("keeps the line breaks a message the body wrote on purpose has, and escapes everything else", () => {
    assert.equal(typeof terminalLines, "function", "terminalLines is not exported from @verax-ai/proxy");
    assert.equal(terminalLines!(`refusing: x\nfix it${cp(0x1b)}[2J${cp(0x0d)}\n${cp(0x202e)}y`), "refusing: x\nfix it\\u001b[2J\\u000d\n\\u202ey");
    assert.equal(terminalLines!("one line"), "one line");
    assert.equal(terminalLines!("ends\n"), "ends\n");
  });
});

function hostileHttpChild(fail: "initialize" | "tools/list"): Promise<string> {
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    let msg: { id?: unknown; method?: string } = {};
    try {
      msg = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as typeof msg;
    } catch {
      /* empty body */
    }
    const method = String(msg.method ?? "");
    if (method.startsWith("notifications/")) {
      res.writeHead(202).end();
      return;
    }
    const id = msg.id ?? 1;
    res.writeHead(200, { "content-type": "application/json" });
    if (method === fail) {
      res.end(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32000, message: HOSTILE } }));
    } else if (method === "initialize") {
      res.end(JSON.stringify({ jsonrpc: "2.0", id, result: {
        protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "hostile", version: "1" },
      } }));
    } else {
      res.end(JSON.stringify({ jsonrpc: "2.0", id, result: { tools: [] } }));
    }
  });
  servers.push(server);
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () =>
    resolve(`http://127.0.0.1:${(server.address() as { port: number }).port}/mcp`)));
}

function ownerDir(prefix: string): string {
  const dir = realpathSync.native(mkdtempSync(join(tmpdir(), prefix)));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  dirs.push(dir);
  return dir;
}

const sink = { write: () => true };

function envFromFile(stateDir: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.toUpperCase().startsWith("VERAX_")) delete env[key];
  }
  for (const line of readFileSync(join(stateDir, "verax.env"), "utf8").split(/\r?\n/)) {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line);
    if (match?.[1] && match[2] !== undefined) env[match[1]] = match[2];
  }
  env.VERAX_BIND = "127.0.0.1:0";
  return env;
}

async function serveAgainst(url: string): Promise<{ code: number | null; signal: string | null; stderr: string }> {
  const dir = ownerDir("verax-a1-serve-");
  const initCode = await runInitLocal(["--local", dir], { stdout: sink, stderr: sink }, { quiet: true, noOwnerGrant: true });
  assert.equal(initCode, 0);
  const doc = join(dir, "downstream.json");
  writeFileSync(doc, JSON.stringify([{ prefix: "rea", url, timeoutMs: 5000 }]), "utf8");
  const env = { ...envFromFile(dir), VERAX_DOWNSTREAM: doc };
  const child = spawn(process.execPath, ["--experimental-strip-types", cli, "serve"], {
    env,
    stdio: ["ignore", "ignore", "pipe"],
    windowsHide: true,
  });
  let stderr = "";
  child.stderr?.on("data", (chunk: Buffer | string) => {
    stderr += String(chunk);
  });
  const timer = setTimeout(() => child.kill(), 30_000);
  const [code, signal] = await new Promise<[number | null, string | null]>((resolve) =>
    child.once("exit", (c, s) => resolve([c, s])));
  clearTimeout(timer);
  return { code, signal, stderr };
}

describe("verax serve with a downstream child whose error carries controls", () => {
  for (const fail of ["initialize", "tools/list"] as const) {
    it(`a child failing ${fail}: one escaped line, no stack, exit 78`, { timeout: 45_000 }, async (t) => {
      if (skipIfElevated(t)) return;
      const run = await serveAgainst(await hostileHttpChild(fail));
      const shown = JSON.stringify(run.stderr.slice(0, 600));
      assert.deepEqual(rawCodePointsIn(run.stderr), [], `raw on the terminal: ${shown}`);
      const lines = linesOf(run.stderr);
      assert.equal(lines.some((line) => /^\s+at /.test(line)), false, `a stack trace was printed: ${shown}`);
      assert.equal(lines.length, 1, `expected one line: ${shown}`);
      assert.match(lines[0]!, /^downstream-attach-failed:rea:/);
      for (const esc of ESCAPED) assert.ok(lines[0]!.includes(esc), `${esc} missing from ${shown}`);
      assert.equal(run.signal, null, `ended by signal ${run.signal}`);
      assert.equal(run.code, 78, `exit ${run.code}: ${shown}`);
    });
  }
});

describe("verax demo --with-conarium with a child whose error carries controls", () => {
  it("says it could not start the child, with the child's text escaped", { timeout: 30_000 }, async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const io = {
      stdout: { write: (s: string) => stdout.push(s) },
      stderr: { write: (s: string) => stderr.push(s) },
      stdin: new Readable({ read() { this.push(null); } }),
      isTTY: false,
    };
    const code = await runDemo(["demo", "--with-conarium"], {}, io, {
      conariumChild: { command: process.execPath, args: [hostileStdioChild] },
      statePrefix: "verax-a1-demo-",
    });
    const err = stderr.join("");
    const shown = JSON.stringify(err.slice(0, 600));
    assert.equal(code, 1);
    assert.match(err, /could not start the Conarium child/);
    assert.deepEqual(rawCodePointsIn(`${stdout.join("")}${err}`), [], `raw on the terminal: ${shown}`);
    for (const esc of ["\\u001b", "\\u202e", "\\u000a"]) assert.ok(err.includes(esc), `${esc} missing from ${shown}`);
  });
});

// The serve process, the start path and the demo. Every value a stderr write
// interpolates there goes through terminalText, except the few named below,
// which are numbers or an address the body bound itself.
const GUARDED = [
  "packages/body/src/cli.ts",
  "packages/body/src/main.ts",
  "packages/body/src/server.ts",
  "packages/body/src/operator-door.ts",
  "packages/body/src/operator-handlers.ts",
  "packages/body/src/downstream.ts",
  "packages/body/src/demo.ts",
  "packages/proxy/src/approvals.ts",
  "packages/proxy/src/proxy.ts",
];
const ALLOWED_VALUES: Record<string, string[]> = {
  "packages/body/src/main.ts": [
    "(addr as AddressInfo).address", "(addr as AddressInfo).port", "doorAddr.address", "doorAddr.port",
    "loaded.value.operatorDoor.origin",
  ],
  "packages/proxy/src/approvals.ts": ["code", "drainMetrics.renameBusy"],
};
// A whole argument that is a fixed text, or the pass-through of a write hook.
const ALLOWED_ARGUMENTS: Record<string, string[]> = {
  "packages/body/src/cli.ts": ["HELP", "usage", "s"],
  "packages/body/src/demo.ts": ["redact(s, token)", "NPX_DOWNLOAD_LINE"],
};

/** From an opening bracket at `open`, the index just past its partner. Strings and templates are skipped. */
function closeOf(src: string, open: number): number {
  const pairs: Record<string, string> = { "(": ")", "{": "}", "[": "]" };
  const stack: string[] = [pairs[src[open]!]!];
  let i = open + 1;
  while (i < src.length && stack.length > 0) {
    const ch = src[i]!;
    if (ch === '"' || ch === "'") {
      i += 1;
      while (i < src.length && src[i] !== ch) i += src[i] === "\\" ? 2 : 1;
      i += 1;
      continue;
    }
    if (ch === "`") {
      i = templateEnd(src, i);
      continue;
    }
    if (ch === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n") i += 1;
      continue;
    }
    if (ch in pairs) stack.push(pairs[ch]!);
    else if (ch === stack[stack.length - 1]) stack.pop();
    i += 1;
  }
  return i;
}

/** From a backtick at `start`, the index just past the closing backtick. */
function templateEnd(src: string, start: number): number {
  let i = start + 1;
  while (i < src.length && src[i] !== "`") {
    if (src[i] === "\\") i += 2;
    else if (src[i] === "$" && src[i + 1] === "{") i = closeOf(src, i + 1);
    else i += 1;
  }
  return i + 1;
}

/** What in one write argument is not fixed text and not passed through terminalText. */
function unescapedParts(arg: string, allowedValues: readonly string[]): string[] {
  const bad: string[] = [];
  let rest = "";
  let i = 0;
  while (i < arg.length) {
    const wrapper = WRAPPERS.find((w) => arg.startsWith(w, i));
    if (wrapper !== undefined) {
      i = closeOf(arg, i + wrapper.length - 1);
      rest += " ";
      continue;
    }
    const ch = arg[i]!;
    if (ch === '"' || ch === "'") {
      i += 1;
      while (i < arg.length && arg[i] !== ch) i += arg[i] === "\\" ? 2 : 1;
      i += 1;
      rest += " ";
      continue;
    }
    if (ch === "`") {
      const end = templateEnd(arg, i);
      let j = i + 1;
      while (j < end - 1) {
        if (arg[j] === "\\") { j += 2; continue; }
        if (arg[j] === "$" && arg[j + 1] === "{") {
          const close = closeOf(arg, j + 1);
          const expr = arg.slice(j + 2, close - 1).trim();
          const wrapper = WRAPPERS.find((w) => expr.startsWith(w));
          const wrapped = wrapper !== undefined && closeOf(expr, wrapper.length - 1) === expr.length;
          if (!wrapped && !allowedValues.includes(expr)) bad.push(`\${${expr}}`);
          j = close;
          continue;
        }
        j += 1;
      }
      i = end;
      rest += " ";
      continue;
    }
    rest += ch;
    i += 1;
  }
  const left = rest.replace(/[\s+,]/g, "");
  if (left !== "") bad.push(arg.trim());
  return bad;
}

describe("stderr writes in the serve process escape what they did not write", () => {
  it("every interpolated value goes through terminalText", () => {
    const unescaped: string[] = [];
    for (const file of GUARDED) {
      const src = readFileSync(join(root, file), "utf8");
      const call = /\b(?:stderr\.write|writeErr)\(/g;
      let m: RegExpExecArray | null;
      while ((m = call.exec(src)) !== null) {
        const open = m.index + m[0].length - 1;
        const arg = src.slice(open + 1, closeOf(src, open) - 1);
        const line = src.slice(0, m.index).split("\n").length;
        if ((ALLOWED_ARGUMENTS[file] ?? []).includes(arg.trim())) continue;
        for (const part of unescapedParts(arg, ALLOWED_VALUES[file] ?? [])) unescaped.push(`${file}:${line} ${part}`);
      }
    }
    assert.deepEqual(unescaped, [], `not passed through terminalText:\n${unescaped.join("\n")}`);
  });

  it("the check finds an unescaped value (the check's own red)", () => {
    assert.deepEqual(unescapedParts("`verax-door: ${err.message}\\n`", []), ["${err.message}"]);
    assert.deepEqual(unescapedParts("message", []), ["message"]);
    assert.deepEqual(unescapedParts("`a ${terminalText(x)} ${terminalText(y)}\\n`", []), []);
    assert.deepEqual(unescapedParts("terminalText(x) + \"\\n\"", []), []);
    assert.deepEqual(unescapedParts("`${terminalLines(refusal.replace(/\\n+$/, \"\"))}\\n`", []), []);
    assert.deepEqual(unescapedParts("`${terminalTextual(x)}`", []), ["${terminalTextual(x)}"]);
    assert.deepEqual(unescapedParts("`${terminalText(x) + y}\\n`", []), ["${terminalText(x) + y}"]);
    assert.deepEqual(unescapedParts("\n      \"fixed text\\n\",\n    ", []), []);
    assert.deepEqual(unescapedParts("a ? b : `${terminalText(b)}\\n`", []), ["a ? b : `${terminalText(b)}\\n`"]);
  });
});
