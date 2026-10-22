// Memory integrity at rest, measured the way draft-khandelwal-bmwg-agent-memory-integrity-02
// measures it: seed through the write path, stop the body, change files with plain fs,
// start the body again on the same state directory, read through MCP memory.get only.
// Files are located by unique markers in their content, not by layout, so the tests stay
// valid if the storage layout changes. Objects must live under <state>/tenants/.
import { strict as assert } from "node:assert";
import { createHash, randomBytes } from "node:crypto";
import { canonical } from "@cedulon/core";
import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const audience = "http://127.0.0.1/verax-test";
const policyFile = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "proxy", "policy", "default.json");
const IDS = ["n1", "n2", "n3", "n4", "n5"];
const UNTIL = Date.now() + 30 * 86_400_000;

type Served = { isError: boolean; data: Record<string, unknown> };
type Store = {
  put: (ctx: "A" | "B", id: string, fact: string, src?: string) => Promise<Served>;
  get: (ctx: "A" | "B", id: string) => Promise<Served>;
  stop: () => Promise<void>;
  start: () => Promise<void>;
  state: string;
  fact: (ctx: "A" | "B", id: string, v?: number) => string;
  src: (ctx: "A" | "B", id: string) => string;
};

async function withStore(run: (s: Store) => Promise<void>, profile: { keysOutside?: boolean } = {}): Promise<void> {
  const state = mkdtempSync(join(tmpdir(), "verax-memint-"));
  const keysDir = profile.keysOutside ? mkdtempSync(join(tmpdir(), "verax-memint-keys-")) : undefined;
  const issuer = await startDevIssuer(0, audience);
  const scope = "verax:read verax:memory";
  const tokens = { A: await issuer.sign({ scope, sub: "agent-a" }), B: await issuer.sign({ scope, sub: "agent-b" }) };
  const opts = {
    issuer: issuer.issuer,
    jwksUrl: issuer.jwksUrl,
    audience,
    stateDir: state,
    ...(keysDir ? { keysDir } : {}),
    bindHost: "127.0.0.1",
    bindPort: 0,
    policyFile,
    tlsTerminated: false,
  };
  let server: Awaited<ReturnType<typeof listen>> | null = await listen(opts);
  let rpcId = 0;
  const call = async (ctx: "A" | "B", name: string, args: Record<string, unknown>): Promise<Served> => {
    assert.ok(server, "body is stopped");
    const port = (server.address() as { port: number }).port;
    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${tokens[ctx]}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method: "tools/call", params: { name, arguments: args } }),
    });
    const body = (await res.json()) as { result?: { isError?: boolean; content?: { text?: string }[] }; error?: unknown };
    assert.ok(body.result, `no result for ${name}: ${JSON.stringify(body).slice(0, 300)}`);
    const text = body.result.content?.[0]?.text ?? "{}";
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(text) as Record<string, unknown>;
    } catch {
      data = { raw: text };
    }
    return { isError: body.result.isError === true, data };
  };
  const tag = randomBytes(4).toString("hex");
  const s: Store = {
    state,
    fact: (ctx: "A" | "B", id: string, v = 1) => `fact-${ctx}-${id}-v${v}-${tag}`,
    src: (ctx: "A" | "B", id: string) => `file://source-${ctx}-${id}-${tag}`,
    put: (ctx: "A" | "B", id: string, fact: string, src = s.src(ctx, id)) =>
      call(ctx, "memory.put", { id, body: { fact }, source: { uri: src, retrievedAtMs: 1 }, validUntilMs: UNTIL }),
    get: (ctx: "A" | "B", id: string) => call(ctx, "memory.get", { id }),
    stop: async () => {
      if (!server) return;
      const srv = server;
      server = null;
      srv.closeAllConnections();
      await new Promise<void>((resolve, reject) => srv.close((err) => (err ? reject(err) : resolve())));
    },
    start: async () => {
      server = await listen(opts);
    },
  };
  try {
    for (const ctx of ["A", "B"] as const) {
      for (const id of IDS) {
        const r = await s.put(ctx, id, s.fact(ctx, id));
        assert.equal(r.isError, false, `seed ${ctx}/${id}: ${JSON.stringify(r.data)}`);
      }
    }
    await run(s);
  } finally {
    await s.stop();
    await issuer.close?.();
    rmSync(state, { recursive: true, force: true });
    if (keysDir) rmSync(keysDir, { recursive: true, force: true });
  }
}

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...filesUnder(p));
    else out.push(p);
  }
  return out;
}

/** The one stored object under tenants/ whose bytes contain `marker`. */
function objectWith(state: string, marker: string): string {
  const hits = filesUnder(join(state, "tenants")).filter((f) => readFileSync(f, "utf8").includes(marker));
  assert.equal(hits.length, 1, `expected exactly one object holding ${marker}, found ${hits.length}`);
  return hits[0]!;
}

/** C3: the edit landed. */
function landed(path: string, mustContain: string): void {
  assert.ok(readFileSync(path, "utf8").includes(mustContain), `edit did not land in ${path}`);
}

function servedText(r: Served): string {
  return JSON.stringify(r.data);
}

/** The read path refused with an integrity-specific code and did not serve the given text. */
function refused(r: Served, notServed: string[], label: string): void {
  for (const t of notServed) assert.ok(!servedText(r).includes(t), `${label}: served ${t}`);
  assert.equal(r.isError, true, `${label}: served without error: ${servedText(r).slice(0, 200)}`);
  const code = String(r.data.error ?? "");
  assert.ok(code.startsWith("memory-integrity"), `${label}: error code ${JSON.stringify(code)} is not an integrity code`);
}

function servedFact(r: Served, fact: string, label: string): void {
  assert.equal(r.isError, false, `${label}: ${servedText(r).slice(0, 200)}`);
  assert.ok(servedText(r).includes(fact), `${label}: expected ${fact}, got ${servedText(r).slice(0, 200)}`);
}

/** After the first integrity failure the body is halted; later calls are signed denies. */
function halted(r: Served, label: string): void {
  assert.equal(r.isError, true, `${label}: ${servedText(r).slice(0, 200)}`);
  const text = typeof r.data.raw === "string" ? r.data.raw : servedText(r);
  assert.match(text, /denied:halted/, `${label}: ${text}`);
}

describe("memory integrity at rest (BPM T1-T9, controls C1-C2)", () => {
  it("C1: a restart with no edit serves every record unchanged", async () => {
    await withStore(async (s) => {
      await s.stop();
      await s.start();
      for (const ctx of ["A", "B"] as const) {
        for (const id of IDS) servedFact(await s.get(ctx, id), s.fact(ctx, id), `C1 ${ctx}/${id}`);
      }
    });
  });

  it("C2: a genuine write after restart is served", async () => {
    await withStore(async (s) => {
      await s.stop();
      await s.start();
      assert.equal((await s.put("A", "n1", s.fact("A", "n1", 2))).isError, false);
      assert.equal((await s.put("A", "n6", s.fact("A", "n6"))).isError, false);
      servedFact(await s.get("A", "n1"), s.fact("A", "n1", 2), "C2 update");
      servedFact(await s.get("A", "n6"), s.fact("A", "n6"), "C2 new");
    });
  });

  it("T1: content tamper in place is refused", async () => {
    await withStore(async (s) => {
      await s.stop();
      const p = objectWith(s.state, s.fact("A", "n3"));
      writeFileSync(p, readFileSync(p, "utf8").replaceAll(s.fact("A", "n3"), "attacker-fact"));
      landed(p, "attacker-fact");
      await s.start();
      refused(await s.get("A", "n3"), ["attacker-fact"], "T1");
      halted(await s.get("A", "n2"), "T1 neighbour");
    });
  });

  // B/n5 is the last commit written, so no later prevCommitHash covers it: only the signature can.
  it("T1b: content tamper with every unkeyed hash recomputed is refused", async () => {
    await withStore(async (s) => {
      await s.stop();
      const p = objectWith(s.state, s.fact("B", "n5"));
      const obj = JSON.parse(readFileSync(p, "utf8")) as Record<string, unknown> & { body: { fact: string } };
      const oldHash = String(obj.versionHash ?? "");
      obj.body.fact = "attacker-fact";
      // The v2 envelope is public and unkeyed, so an attacker without the signing key can recompute it.
      const newHash = createHash("sha256")
        .update(
          canonical({
            purpose: "verax.memory.v2",
            hashSchema: 2,
            tenantKey: obj.tenantKey,
            id: obj.id,
            revision: obj.revision,
            body: obj.body,
            source: obj.source,
            validFromMs: obj.validFromMs,
            validUntilMs: obj.validUntilMs,
          }),
          "utf8",
        )
        .digest("hex");
      obj.versionHash = newHash;
      writeFileSync(p, JSON.stringify(obj) + "\n");
      landed(p, "attacker-fact");
      for (const f of filesUnder(s.state).filter((f) => !f.includes(`${join(s.state, "tenants")}`))) {
        const text = readFileSync(f, "utf8");
        if (oldHash !== "" && text.includes(oldHash)) writeFileSync(f, text.replaceAll(oldHash, newHash));
      }
      await s.start();
      refused(await s.get("B", "n5"), ["attacker-fact"], "T1b");
    });
  });

  it("T2: deleting the newest version does not make an older one current", async () => {
    await withStore(async (s) => {
      assert.equal((await s.put("A", "n5", s.fact("A", "n5", 2))).isError, false);
      await s.stop();
      unlinkSync(objectWith(s.state, s.fact("A", "n5", 2)));
      await s.start();
      refused(await s.get("A", "n5"), [s.fact("A", "n5", 1)], "T2");
    });
  });

  it("T3: deleting a stored record is reported, not answered as never written", async () => {
    await withStore(async (s) => {
      await s.stop();
      unlinkSync(objectWith(s.state, s.fact("A", "n3")));
      await s.start();
      // Read the never-written id first: an integrity failure halts the body, so this check must come before it.
      const never = await s.get("A", "never-written");
      assert.equal(never.isError, true);
      assert.equal(never.data.error, "not-found", "an id that was never written stays not-found");
      refused(await s.get("A", "n3"), [], "T3");
      halted(await s.get("A", "n2"), "T3 after halt");
    });
  });

  it("T4: swapping two records between their slots is refused", async () => {
    await withStore(async (s) => {
      await s.stop();
      const p2 = objectWith(s.state, s.fact("A", "n2"));
      const p4 = objectWith(s.state, s.fact("A", "n4"));
      const b2 = readFileSync(p2);
      const b4 = readFileSync(p4);
      writeFileSync(p2, b4);
      writeFileSync(p4, b2);
      landed(p2, s.fact("A", "n4"));
      await s.start();
      refused(await s.get("A", "n2"), [s.fact("A", "n4")], "T4 n2");
      halted(await s.get("A", "n4"), "T4 n4");
    });
  });

  it("T5: a record forged in the store format is not served", async () => {
    await withStore(async (s) => {
      await s.stop();
      const model = objectWith(s.state, s.fact("A", "n1"));
      const tenants = join(s.state, "tenants");
      const rel = model.slice(tenants.length);
      const forgedPath = tenants + rel.replace(/n1(?!.*n1)/, "n9");
      assert.notEqual(forgedPath, model, "could not derive a sibling path for the forged record");
      mkdirSync(dirname(forgedPath), { recursive: true });
      writeFileSync(
        forgedPath,
        readFileSync(model, "utf8").replaceAll('"n1"', '"n9"').replaceAll(s.fact("A", "n1"), "forged-fact"),
      );
      landed(forgedPath, "forged-fact");
      await s.start();
      const r = await s.get("A", "n9");
      assert.ok(!servedText(r).includes("forged-fact"), "T5: forged record served");
      assert.equal(r.isError, true, "T5: forged id answered without error");
      assert.ok(String(r.data.error ?? "").startsWith("memory-integrity"), `T5: error ${JSON.stringify(r.data.error)}`);
    });
  });

  it("T6: a genuine record of context A copied over context B is refused", async () => {
    await withStore(async (s) => {
      await s.stop();
      const a = objectWith(s.state, s.fact("A", "n1"));
      const b = objectWith(s.state, s.fact("B", "n1"));
      writeFileSync(b, readFileSync(a));
      landed(b, s.fact("A", "n1"));
      await s.start();
      refused(await s.get("B", "n1"), [s.fact("A", "n1")], "T6");
      halted(await s.get("A", "n1"), "T6 after halt");
    });
  });

  it("T7: an older genuine version restored over the newest is refused", async () => {
    await withStore(async (s) => {
      await s.stop();
      const v1 = readFileSync(objectWith(s.state, s.fact("A", "n4")));
      await s.start();
      assert.equal((await s.put("A", "n4", s.fact("A", "n4", 2))).isError, false);
      await s.stop();
      const newest = objectWith(s.state, s.fact("A", "n4", 2));
      writeFileSync(newest, v1);
      landed(newest, s.fact("A", "n4", 1));
      await s.start();
      refused(await s.get("A", "n4"), [s.fact("A", "n4", 1)], "T7");
    });
  });

  it("T8: changing only the source of a record is refused", async () => {
    await withStore(async (s) => {
      await s.stop();
      const p = objectWith(s.state, s.src("A", "n2"));
      writeFileSync(p, readFileSync(p, "utf8").replaceAll(s.src("A", "n2"), "file://attacker-source"));
      landed(p, "file://attacker-source");
      await s.start();
      refused(await s.get("A", "n2"), ["attacker-source"], "T8");
    });
  });

  it(
    "T9: restoring an earlier copy of the whole store is refused",
    { todo: "needs a head anchored outside the state directory; reported as ACCEPTED in the local profile" },
    async () => {
      await withStore(async (s) => {
        await s.stop();
        const snap = mkdtempSync(join(tmpdir(), "verax-memint-snap-"));
        cpSync(s.state, snap, { recursive: true });
        await s.start();
        assert.equal((await s.put("A", "n1", s.fact("A", "n1", 2))).isError, false);
        await s.stop();
        for (const name of readdirSync(s.state)) rmSync(join(s.state, name), { recursive: true, force: true });
        cpSync(snap, s.state, { recursive: true });
        rmSync(snap, { recursive: true, force: true });
        await s.start();
        refused(await s.get("A", "n1"), [s.fact("A", "n1", 1)], "T9");
      });
    },
  );
});

// Hardened profile: the record key and the memory head live outside the state directory, so an attacker who can
// write the state directory cannot roll back what the body last committed.
describe("memory integrity at rest, keys and head outside the state directory", () => {
  it("C1h: a restart with no edit serves every record unchanged", async () => {
    await withStore(
      async (s) => {
        await s.stop();
        await s.start();
        for (const ctx of ["A", "B"] as const) {
          for (const id of IDS) servedFact(await s.get(ctx, id), s.fact(ctx, id), `C1h ${ctx}/${id}`);
        }
      },
      { keysOutside: true },
    );
  });

  it("T9h: restoring an earlier copy of the whole state directory is refused", async () => {
    await withStore(
      async (s) => {
        await s.stop();
        const snap = mkdtempSync(join(tmpdir(), "verax-memint-snap-"));
        cpSync(s.state, snap, { recursive: true });
        await s.start();
        assert.equal((await s.put("A", "n1", s.fact("A", "n1", 2))).isError, false);
        await s.stop();
        for (const name of readdirSync(s.state)) rmSync(join(s.state, name), { recursive: true, force: true });
        cpSync(snap, s.state, { recursive: true });
        rmSync(snap, { recursive: true, force: true });
        await s.start();
        refused(await s.get("A", "n1"), [s.fact("A", "n1", 1)], "T9h");
      },
      { keysOutside: true },
    );
  });

  it("T2h: cutting the newest commit line with the object it names is refused, not read as never written", async () => {
    await withStore(
      async (s) => {
        assert.equal((await s.put("A", "n7", s.fact("A", "n7"))).isError, false);
        await s.stop();
        const commits = join(s.state, "memory-commits.jsonl");
        const lines = readFileSync(commits, "utf8").split("\n").filter((l) => l.trim() !== "");
        writeFileSync(commits, lines.slice(0, -1).join("\n") + "\n");
        unlinkSync(objectWith(s.state, s.fact("A", "n7")));
        await s.start();
        refused(await s.get("A", "n7"), [], "T2h");
      },
      { keysOutside: true },
    );
  });
});
