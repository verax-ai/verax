import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { request } from "node:http";
import { connect, createServer as createNetServer, type AddressInfo, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { Script } from "node:vm";

import { decisionRecordHash, type SignedDecisionRecord } from "@cedulon/core";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { approvalsLogFor, approvePending, DISPLAY_ESCAPE_CLASS, FileLedger, listPieceFiles, verifyLedger } from "@verax-ai/proxy";
import { exportJWK, generateKeyPair } from "jose";

import { verifyApprovalSignatures } from "../packages/body/src/approval-signature.ts";
import { nextControlChallenge, verifyControlSignatures } from "../packages/body/src/control-signature.ts";
import { haltBody } from "../packages/body/src/halt.ts";
import { loadOrCreateSigners } from "../packages/body/src/keys.ts";
import { runVerify } from "../packages/body/src/verify-cli.ts";
import { readOperatorDoor, type OperatorDoorConfig } from "../packages/body/src/config.ts";
import { heldSpend } from "../packages/body/src/held-spend.ts";
import { lookWithoutFollowing, pairingWriter, runOperator, type OperatorSys } from "../packages/body/src/operator-cli.ts";
import {
  credentialsPath,
  hasRegisteredOperator,
  readCredentials,
  readCredentialsAt,
  readRemoved,
  removedPath,
  saveCredential,
} from "../packages/body/src/operator-credentials.ts";
import {
  DOOR_CHALLENGE_TTL_MS,
  DOOR_SESSION_TTL_MS,
  doorHostAllowed,
  openOperatorDoor,
} from "../packages/body/src/operator-door.ts";
import { DOOR_CSS, DOOR_HTML, DOOR_JS } from "../packages/body/src/operator-door-page.ts";
import {
  beginPairing,
  checkPairing,
  hashPairingCode,
  PAIRING_TTL_MS,
  pairingPath,
  readPairing,
  writePairing,
} from "../packages/body/src/operator-pairing.ts";
import { listen, operatorDoorOf } from "../packages/body/src/server.ts";
import {
  approvePolicyFile,
  AUDIENCE,
  DOOR_HOST,
  DOOR_ORIGIN,
  hold,
  holdSpend,
  ISSUER,
  openBody,
  RP_ID,
} from "./operator-door-fixture.ts";
import {
  assertWithSoftwarePasskey,
  attestedAuthData,
  mintSoftwarePasskey,
  registerWithSoftwarePasskey,
  registrationFrom,
  type SoftwarePasskey,
} from "./software-passkey.ts";

// Written out here and not read from the door: a policy loosened there fails here.
const PAGE_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'";

type Answer = { status: number; body: Record<string, unknown>; headers: Record<string, string | string[] | undefined> };

/** `node:http` so the test can say exactly which Host and Origin arrive. */
function call(
  port: number,
  method: string,
  path: string,
  opts: { token?: string; body?: unknown; origin?: string | null; host?: string } = {},
): Promise<Answer> {
  const text = opts.body === undefined ? "" : JSON.stringify(opts.body);
  const origin = opts.origin === undefined ? (method === "POST" ? DOOR_ORIGIN : null) : opts.origin;
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port,
        method,
        path,
        headers: {
          host: opts.host ?? DOOR_HOST,
          ...(origin === null ? {} : { origin }),
          ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
          ...(text === "" ? {} : { "content-type": "application/json", "content-length": Buffer.byteLength(text) }),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          let body: Record<string, unknown> = {};
          try {
            body = raw === "" ? {} : (JSON.parse(raw) as Record<string, unknown>);
          } catch {
            body = { raw };
          }
          resolve({ status: res.statusCode ?? 0, body, headers: res.headers });
        });
      },
    );
    req.once("error", reject);
    req.end(text);
  });
}

async function signIn(port: number, passkey: SoftwarePasskey, over: { origin?: string; counter?: number } = {}): Promise<Answer> {
  const options = await call(port, "POST", "/api/signin/options");
  assert.equal(options.status, 200);
  const assertion = assertWithSoftwarePasskey(passkey, {
    challenge: options.body.challenge as string,
    rpID: RP_ID,
    origin: over.origin ?? DOOR_ORIGIN,
    ...(over.counter !== undefined ? { counter: over.counter } : {}),
  });
  return call(port, "POST", "/api/signin", { body: { assertion } });
}

/** What the door's page does with a code typed at it: ask for a challenge, make the passkey, send it back. */
async function enroll(port: number, code: string, passkey: SoftwarePasskey): Promise<Answer> {
  const options = await call(port, "POST", "/api/enroll/options", { body: { code } });
  if (options.status !== 200) return options;
  const response = registerWithSoftwarePasskey(passkey, {
    challenge: options.body.challenge as string,
    rpID: RP_ID,
    origin: DOOR_ORIGIN,
  });
  return call(port, "POST", "/api/enroll", { body: { code, response } });
}

/** Sends a request that never ends its body, and reports the answer and whether the door hung up. */
function unending(
  port: number,
  head: string,
  sockets: Socket[],
  over: { host?: string; framing?: string } = {},
): Promise<{ status: string; cut: boolean }> {
  return new Promise((resolve) => {
    // Half-open on this side: a door that only stopped writing and went on
    // reading would leave this socket up, and that is not being cut.
    const socket = connect({ port, host: "127.0.0.1", allowHalfOpen: true });
    sockets.push(socket);
    let status = "";
    let more: NodeJS.Timeout | undefined;
    const done = (cut: boolean) => {
      clearInterval(more);
      clearTimeout(patience);
      resolve({ status, cut });
    };
    const patience = setTimeout(() => done(false), 1500);
    socket.on("error", () => undefined);
    socket.once("data", (chunk: Buffer) => {
      status = (chunk.toString("utf8").split("\r\n")[0] ?? "").replace("HTTP/1.1 ", "").slice(0, 3);
    });
    socket.once("close", () => done(true));
    socket.write(
      `${head}Host: ${over.host ?? DOOR_HOST}\r\n${over.framing ?? "Transfer-Encoding: chunked"}\r\nContent-Type: application/json\r\n\r\n`,
    );
    more = setInterval(() => {
      if (!socket.destroyed) socket.write(`400\r\n${"x".repeat(1024)}\r\n`);
    }, 20);
  });
}

/** Runs a CLI entry and hands back what it wrote in place of writing it. */
async function quiet(run: () => Promise<number>): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const write = { out: process.stdout.write, err: process.stderr.write };
  process.stdout.write = ((chunk: string) => (out.push(String(chunk)), true)) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string) => (err.push(String(chunk)), true)) as typeof process.stderr.write;
  try {
    return { code: await run(), out: out.join(""), err: err.join("") };
  } finally {
    process.stdout.write = write.out;
    process.stderr.write = write.err;
  }
}

type Waiting = { ref: string; requestHash: string; tool: string; args: Record<string, unknown> };

async function waitingAt(port: number, token: string): Promise<Waiting[]> {
  const listed = await call(port, "GET", "/api/waiting", { token });
  assert.equal(listed.status, 200);
  return listed.body.waiting as Waiting[];
}

async function approvalAssertion(port: number, token: string, passkey: SoftwarePasskey, ref: string) {
  const challenge = await call(port, "GET", `/api/approve/challenge?ref=${encodeURIComponent(ref)}`, { token });
  assert.equal(challenge.status, 200);
  assert.equal(challenge.body.rpId, RP_ID);
  return assertWithSoftwarePasskey(passkey, {
    challenge: challenge.body.challenge as string,
    rpID: RP_ID,
    origin: DOOR_ORIGIN,
  });
}

describe("operator door", () => {
  it("D1 is shut unless the body is told an origin for it", async () => {
    const body = await openBody(mintSoftwarePasskey(), false);
    try {
      assert.equal(operatorDoorOf(body.server), null);
    } finally {
      await body.close();
    }
  });

  it("D2 serves its own list and nothing else: no /mcp, no ledger, no inventory, no health", async () => {
    const passkey = mintSoftwarePasskey();
    const body = await openBody(passkey);
    try {
      const signed = await signIn(body.doorPort, passkey);
      const token = signed.body.token as string;
      const agent = await body.local("verax:memory");
      for (const bearer of [undefined, token, agent]) {
        for (const [method, path] of [
          ["POST", "/mcp"],
          ["GET", "/mcp"],
          ["GET", "/api/ledger"],
          ["GET", "/api/inventory"],
          ["GET", "/api/agents"],
          ["POST", "/api/contest/x"],
          ["GET", "/healthz"],
          ["GET", "/.well-known/oauth-protected-resource"],
          ["POST", "/"],
          ["GET", "/index.html"],
          ["GET", "/door.js.map"],
          ["POST", "/door.js"],
          ["GET", "/door.css/"],
          ["GET", "/favicon.ico"],
          ["GET", "/api/signin"],
          ["DELETE", "/api/approve"],
        ] as const) {
          const res = await call(body.doorPort, method, path, bearer ? { token: bearer } : {});
          assert.equal(res.status, 404, `${method} ${path}`);
          assert.deepEqual(res.body, { error: "not-found" });
        }
      }
    } finally {
      await body.close();
    }
  });

  it("D3 answers for its own name only, and a POST must name the door's origin", async () => {
    const passkey = mintSoftwarePasskey();
    const body = await openBody(passkey);
    try {
      const other = await call(body.doorPort, "POST", "/api/signin/options", { host: "evil.example:4174" });
      assert.equal(other.status, 400);
      assert.deepEqual(other.body, { error: "host-not-allowed" });
      // The proxy may forward the door's own loopback address instead of the name.
      const loopback = await call(body.doorPort, "POST", "/api/signin/options", { host: `127.0.0.1:${body.doorPort}` });
      assert.equal(loopback.status, 200);
      const wrongPort = await call(body.doorPort, "POST", "/api/signin/options", { host: "127.0.0.1:1" });
      assert.equal(wrongPort.status, 400);

      const foreign = await call(body.doorPort, "POST", "/api/signin/options", { origin: "https://evil.example" });
      assert.equal(foreign.status, 403);
      assert.deepEqual(foreign.body, { error: "origin-not-allowed" });
      const none = await call(body.doorPort, "POST", "/api/signin/options", { origin: null });
      assert.equal(none.status, 403);
      assert.deepEqual(none.body, { error: "origin-required" });
      const foreignGet = await call(body.doorPort, "GET", "/api/waiting", { origin: "https://evil.example" });
      assert.equal(foreignGet.status, 403);

      assert.equal(doorHostAllowed(undefined, { origin: DOOR_ORIGIN } as OperatorDoorConfig, 1), false);
      assert.equal(doorHostAllowed("LOCALHOST:4174", { origin: DOOR_ORIGIN } as OperatorDoorConfig, 1), true);
    } finally {
      await body.close();
    }
  });

  it("D4 stays shut while no operator is enrolled", async () => {
    const body = await openBody(null);
    try {
      for (const [method, path] of [
        ["POST", "/api/signin/options"],
        ["POST", "/api/signin"],
        ["GET", "/api/waiting"],
        ["POST", "/api/approve"],
        ["POST", "/api/halt"],
        ["POST", "/api/resume"],
      ] as const) {
        const res = await call(body.doorPort, method, path, method === "POST" ? { body: {} } : {});
        assert.equal(res.status, 403, `${method} ${path}`);
        assert.deepEqual(res.body, { error: "no-operator" });
      }
    } finally {
      await body.close();
    }
  });

  it("D5 a passkey opens a session that sees what is waiting, and only that", async () => {
    const passkey = mintSoftwarePasskey();
    const body = await openBody(passkey);
    try {
      const closed = await call(body.doorPort, "GET", "/api/waiting");
      assert.equal(closed.status, 401);
      await hold(body, "door-d5");
      const signed = await signIn(body.doorPort, passkey);
      assert.equal(signed.status, 200);
      assert.equal(signed.body.sub, "operator-1");
      assert.equal(signed.headers["cache-control"], "no-store");
      const listed = await call(body.doorPort, "GET", "/api/waiting", { token: signed.body.token as string });
      assert.deepEqual(Object.keys(listed.body), ["waiting"]);
      const rows = listed.body.waiting as Waiting[];
      assert.equal(rows.length, 1);
      assert.equal(rows[0]!.tool, "memory.put");
      assert.equal(rows[0]!.args.id, "door-d5");
      assert.equal(typeof rows[0]!.requestHash, "string");

      const out = await call(body.doorPort, "POST", "/api/signout", { token: signed.body.token as string });
      assert.equal(out.status, 200);
      const after = await call(body.doorPort, "GET", "/api/waiting", { token: signed.body.token as string });
      assert.equal(after.status, 401);
    } finally {
      await body.close();
    }
  });

  it("D6 a session does not approve: each approval needs an assertion made for that request", async () => {
    const passkey = mintSoftwarePasskey();
    const body = await openBody(passkey);
    try {
      await hold(body, "door-d6-a");
      await hold(body, "door-d6-b");
      const token = (await signIn(body.doorPort, passkey)).body.token as string;
      const rows = await waitingAt(body.doorPort, token);
      const a = rows.find((row) => row.args.id === "door-d6-a")!;
      const b = rows.find((row) => row.args.id === "door-d6-b")!;

      const bare = await call(body.doorPort, "POST", "/api/approve", { token, body: { ref: a.ref, requestHash: a.requestHash } });
      assert.equal(bare.status, 403);
      assert.equal(bare.body.error, "approve-signature-required");

      const forA = await approvalAssertion(body.doorPort, token, passkey, a.ref);
      const crossed = await call(body.doorPort, "POST", "/api/approve", {
        token,
        body: { ref: b.ref, requestHash: b.requestHash, assertion: forA },
      });
      assert.equal(crossed.status, 403);
      assert.equal(crossed.body.error, "approve-signature-invalid");

      const stale = await call(body.doorPort, "POST", "/api/approve", {
        token,
        body: { ref: a.ref, requestHash: b.requestHash, assertion: forA },
      });
      assert.equal(stale.status, 409);
      assert.equal(stale.body.error, "stale");

      const ok = await call(body.doorPort, "POST", "/api/approve", {
        token,
        body: { ref: a.ref, requestHash: a.requestHash, assertion: forA },
      });
      assert.equal(ok.status, 200, JSON.stringify(ok.body));
      assert.equal(ok.body.approver, "operator-1");

      const replay = await call(body.doorPort, "POST", "/api/approve", {
        token,
        body: { ref: a.ref, requestHash: a.requestHash, assertion: forA },
      });
      assert.notEqual(replay.status, 200);
      assert.deepEqual((await waitingAt(body.doorPort, token)).map((row) => row.ref), [b.ref]);
    } finally {
      await body.close();
    }
  });

  it("D6b a row edited on disk is not listed and not approved: the body would approve its own copy", async () => {
    const passkey = mintSoftwarePasskey();
    const body = await openBody(passkey);
    try {
      await hold(body, "door-d6b");
      const token = (await signIn(body.doorPort, passkey)).body.token as string;
      const [row] = await waitingAt(body.doorPort, token);
      assert.ok(row, "nothing was waiting");
      const path = join(body.stateDir, "approvals.jsonl");
      const lines = readFileSync(path, "utf8")
        .split("\n")
        .filter((line) => line !== "")
        .map((line) => JSON.parse(line) as { ref: string; args: Record<string, unknown> });
      const onDisk = lines.filter((line) => line.ref === row.ref).at(-1);
      assert.ok(onDisk);
      onDisk.args = { ...onDisk.args, id: "harmless" };
      writeFileSync(path, `${lines.map((line) => JSON.stringify(line)).join("\n")}\n`);

      assert.deepEqual(await waitingAt(body.doorPort, token), []);
      const assertion = await approvalAssertion(body.doorPort, token, passkey, row.ref);
      const refused = await call(body.doorPort, "POST", "/api/approve", {
        token,
        body: { ref: row.ref, requestHash: row.requestHash, assertion },
      });
      assert.equal(refused.status, 409, JSON.stringify(refused.body));
      assert.equal(refused.body.error, "row-unbound");
    } finally {
      await body.close();
    }
  });

  it("D7 an approval through the door verifies from the files alone and names the door's origin", async () => {
    const passkey = mintSoftwarePasskey();
    const body = await openBody(passkey);
    let open = true;
    const shut = async () => {
      if (!open) return;
      open = false;
      await new Promise<void>((resolve) => body.server.close(() => resolve()));
    };
    try {
      await hold(body, "door-d7");
      const token = (await signIn(body.doorPort, passkey)).body.token as string;
      const [row] = await waitingAt(body.doorPort, token);
      const assertion = await approvalAssertion(body.doorPort, token, passkey, row!.ref);
      const ok = await call(body.doorPort, "POST", "/api/approve", {
        token,
        body: { ref: row!.ref, requestHash: row!.requestHash, assertion },
      });
      assert.equal(ok.status, 200, JSON.stringify(ok.body));
      // No body is running when the files are read back.
      await shut();
      const report = await verifyApprovalSignatures(body.stateDir);
      assert.equal(report.signedVerified, 1);
      assert.equal(report.signedFailed, 0);
      assert.equal(report.unsignedHttp, 0);
      assert.match(report.line, /origin http:\/\/localhost:4174/);
    } finally {
      await shut();
      rmSync(body.stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D8 the two listeners take none of each other's tokens", async () => {
    const passkey = mintSoftwarePasskey();
    const body = await openBody(passkey);
    try {
      await hold(body, "door-d8");
      const session = (await signIn(body.doorPort, passkey)).body.token as string;
      const [row] = await waitingAt(body.doorPort, session);
      const minted = await body.local("verax:approve verax:audit", "operator-1");

      // Local mode still refuses operator scopes from the local key, door or no door.
      const atMain = await fetch(`${body.main}/api/approve`, {
        method: "POST",
        headers: { authorization: `Bearer ${minted}`, "content-type": "application/json" },
        body: JSON.stringify({ ref: row!.ref, requestHash: row!.requestHash }),
      });
      assert.equal(atMain.status, 403);
      assert.deepEqual(await atMain.json(), { error: "local-mode-operator-scope" });

      // A token the local key signed is not a session at the door.
      for (const [method, path] of [
        ["GET", "/api/waiting"],
        ["POST", "/api/approve"],
        ["POST", "/api/halt"],
        ["GET", "/api/approve/challenge?ref=x"],
      ] as const) {
        const res = await call(body.doorPort, method, path, { token: minted, ...(method === "POST" ? { body: {} } : {}) });
        assert.equal(res.status, 401, `${method} ${path}`);
      }

      // A door session is not a bearer at the main listener.
      for (const path of ["/api/ledger", "/api/halt", "/mcp"]) {
        const res = await fetch(`${body.main}${path}`, { headers: { authorization: `Bearer ${session}` } });
        assert.equal(res.status, 401, path);
      }
      assert.equal((await waitingAt(body.doorPort, session)).length, 1);
    } finally {
      await body.close();
    }
  });

  it("D9 sign-in refuses another origin, a used challenge, an unknown passkey and a counter that went back", async () => {
    const passkey = mintSoftwarePasskey();
    const body = await openBody(passkey);
    try {
      const elsewhere = await signIn(body.doorPort, passkey, { origin: "https://evil.example" });
      assert.equal(elsewhere.status, 403);
      assert.deepEqual(elsewhere.body, { error: "signin-refused" });

      const options = await call(body.doorPort, "POST", "/api/signin/options");
      const assertion = assertWithSoftwarePasskey(passkey, {
        challenge: options.body.challenge as string,
        rpID: RP_ID,
        origin: DOOR_ORIGIN,
      });
      assert.equal((await call(body.doorPort, "POST", "/api/signin", { body: { assertion } })).status, 200);
      const again = await call(body.doorPort, "POST", "/api/signin", { body: { assertion } });
      assert.equal(again.status, 403);
      // A fresh signature over the challenge that was already used: the counter is fine, the challenge is spent.
      const fresh = assertWithSoftwarePasskey(passkey, {
        challenge: options.body.challenge as string,
        rpID: RP_ID,
        origin: DOOR_ORIGIN,
      });
      const spent = await call(body.doorPort, "POST", "/api/signin", { body: { assertion: fresh } });
      assert.equal(spent.status, 403);
      assert.deepEqual(spent.body, { error: "signin-refused" });

      const own = assertWithSoftwarePasskey(passkey, { challenge: "made-up-by-the-caller", rpID: RP_ID, origin: DOOR_ORIGIN });
      assert.equal((await call(body.doorPort, "POST", "/api/signin", { body: { assertion: own } })).status, 403);
      // The right shape and a time still ahead, but not a challenge this door made.
      const forged = Buffer.alloc(56);
      forged.writeBigUInt64BE(BigInt(Date.now() + 60_000), 0);
      randomBytes(48).copy(forged, 8);
      const shaped = assertWithSoftwarePasskey(passkey, {
        challenge: forged.toString("base64url"),
        rpID: RP_ID,
        origin: DOOR_ORIGIN,
      });
      const refused = await call(body.doorPort, "POST", "/api/signin", { body: { assertion: shaped } });
      assert.equal(refused.status, 403);
      assert.deepEqual(refused.body, { error: "signin-refused" });

      const stranger = await signIn(body.doorPort, mintSoftwarePasskey());
      assert.equal(stranger.status, 403);
      assert.deepEqual(stranger.body, { error: "signin-refused" });

      const back = await signIn(body.doorPort, passkey, { counter: 1 });
      assert.equal(back.status, 403);
      assert.deepEqual(back.body, { error: "cloned-authenticator" });

      assert.equal((await call(body.doorPort, "POST", "/api/signin", { body: {} })).status, 403);
      assert.equal((await call(body.doorPort, "POST", "/api/signin", { body: { assertion: "x" } })).status, 403);
    } finally {
      await body.close();
    }
  });

  it("D10 a challenge and a session both run out, and a removed passkey ends its sessions", async () => {
    const passkey = mintSoftwarePasskey();
    const stateDir = mkdtempSync(join(tmpdir(), "verax-operator-door-clock-"));
    saveCredential(stateDir, {
      id: passkey.id,
      publicKey: isoBase64URL.fromBuffer(passkey.publicKeyCose.slice()),
      counter: 0,
      sub: "operator-1",
    });
    let clock = 1_000_000;
    // Sign-in and the waiting list read the state directory only; the body's services are not reached.
    const door = await openOperatorDoor({
      door: { origin: DOOR_ORIGIN, rpID: RP_ID, bindHost: "127.0.0.1", bindPort: 0 },
      stateDir,
      services: undefined as never,
      now: () => clock,
    });
    const port = (door.address() as AddressInfo).port;
    try {
      const options = await call(port, "POST", "/api/signin/options");
      clock += DOOR_CHALLENGE_TTL_MS;
      const late = assertWithSoftwarePasskey(passkey, { challenge: options.body.challenge as string, rpID: RP_ID, origin: DOOR_ORIGIN });
      assert.equal((await call(port, "POST", "/api/signin", { body: { assertion: late } })).status, 403);

      const signed = await signIn(port, passkey);
      assert.equal(signed.status, 200);
      const token = signed.body.token as string;
      assert.equal(signed.body.expiresAtMs, clock + DOOR_SESSION_TTL_MS);
      clock += DOOR_SESSION_TTL_MS - 1;
      assert.equal((await call(port, "GET", "/api/waiting", { token })).status, 200);
      clock += 1;
      assert.equal((await call(port, "GET", "/api/waiting", { token })).status, 401);

      const second = (await signIn(port, passkey)).body.token as string;
      assert.equal((await call(port, "GET", "/api/waiting", { token: second })).status, 200);
      writeFileSync(credentialsPath(stateDir), `${JSON.stringify({ credentials: [] })}\n`);
      assert.equal((await call(port, "GET", "/api/waiting", { token: second })).status, 401);
    } finally {
      await new Promise<void>((resolve) => door.close(() => resolve()));
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D11 stops the body on a session's word, and resumes it only on a signed one", async () => {
    const passkey = mintSoftwarePasskey();
    const body = await openBody(passkey);
    try {
      const token = (await signIn(body.doorPort, passkey)).body.token as string;
      const halted = await call(body.doorPort, "POST", "/api/halt", { token, body: {} });
      assert.equal(halted.status, 200);
      assert.equal(halted.body.halted, true);
      assert.equal((await call(body.doorPort, "GET", "/api/halt", { token })).body.halted, true);

      const bare = await call(body.doorPort, "POST", "/api/resume", { token, body: {} });
      assert.equal(bare.status, 403);
      assert.equal(bare.body.error, "resume-signature-required");

      const challenge = await call(body.doorPort, "GET", "/api/resume/challenge", { token });
      assert.equal(challenge.status, 200);
      const assertion = assertWithSoftwarePasskey(passkey, {
        challenge: challenge.body.challenge as string,
        rpID: RP_ID,
        origin: DOOR_ORIGIN,
      });
      const resumed = await call(body.doorPort, "POST", "/api/resume", { token, body: { assertion } });
      assert.equal(resumed.status, 200, JSON.stringify(resumed.body));
      assert.equal(resumed.body.halted, false);
    } finally {
      await body.close();
    }
  });

  it("D13 a stranger who asks for challenges takes nothing from the operator who asked for one", async () => {
    const passkey = mintSoftwarePasskey();
    const body = await openBody(passkey);
    try {
      const options = await call(body.doorPort, "POST", "/api/signin/options");
      const seen = new Set<string>([options.body.challenge as string]);
      for (let i = 0; i < 200; i += 1) {
        const other = await call(body.doorPort, "POST", "/api/signin/options");
        assert.equal(other.status, 200);
        seen.add(other.body.challenge as string);
      }
      assert.equal(seen.size, 201);
      const assertion = assertWithSoftwarePasskey(passkey, {
        challenge: options.body.challenge as string,
        rpID: RP_ID,
        origin: DOOR_ORIGIN,
      });
      const signed = await call(body.doorPort, "POST", "/api/signin", { body: { assertion } });
      assert.equal(signed.status, 200, JSON.stringify(signed.body));
    } finally {
      await body.close();
    }
  });

  it("D14 a sign-in body nobody has vouched for is small, few are read at once, and a slow one is dropped", async () => {
    const passkey = mintSoftwarePasskey();
    const stateDir = mkdtempSync(join(tmpdir(), "verax-operator-door-slow-"));
    saveCredential(stateDir, {
      id: passkey.id,
      publicKey: isoBase64URL.fromBuffer(passkey.publicKeyCose.slice()),
      counter: 0,
      sub: "operator-1",
    });
    const door = await openOperatorDoor({
      door: { origin: DOOR_ORIGIN, rpID: RP_ID, bindHost: "127.0.0.1", bindPort: 0 },
      stateDir,
      services: undefined as never,
      signinBodyMs: 600,
    });
    const port = (door.address() as AddressInfo).port;
    const sockets: Socket[] = [];
    try {
      const big = await call(port, "POST", "/api/signin", { body: { assertion: "x".repeat(17 * 1024) } });
      assert.equal(big.status, 413);

      // A length that is only announced is refused before any of the body is waited for.
      const announced = await new Promise<string>((resolve, reject) => {
        const socket = connect(port, "127.0.0.1");
        sockets.push(socket);
        const waited = setTimeout(() => reject(new Error("no answer to an announced length")), 400);
        socket.on("error", () => undefined);
        socket.once("data", (chunk: Buffer) => {
          clearTimeout(waited);
          resolve(chunk.toString("utf8").split("\r\n")[0] ?? "");
        });
        socket.write(
          `POST /api/signin HTTP/1.1\r\nHost: ${DOOR_HOST}\r\nOrigin: ${DOOR_ORIGIN}\r\n` +
            `Content-Type: application/json\r\nContent-Length: 20000\r\n\r\n`,
        );
      });
      assert.match(announced, /^HTTP\/1\.1 413 /);

      // A body with no announced length is counted as it arrives.
      const streamed = await new Promise<number>((resolve, reject) => {
        const req = request(
          {
            host: "127.0.0.1",
            port,
            method: "POST",
            path: "/api/signin",
            headers: { host: DOOR_HOST, origin: DOOR_ORIGIN, "content-type": "application/json", "transfer-encoding": "chunked" },
          },
          (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          },
        );
        req.once("error", reject);
        req.write(`{"assertion":"`);
        req.write("x".repeat(17 * 1024));
        req.end(`"}`);
      });
      assert.equal(streamed, 413);

      // Thirty-two requests that each send the start of a body and then nothing.
      for (let i = 0; i < 32; i += 1) {
        const socket = connect(port, "127.0.0.1");
        socket.on("error", () => undefined);
        socket.write(
          `POST /api/signin HTTP/1.1\r\nHost: ${DOOR_HOST}\r\nOrigin: ${DOOR_ORIGIN}\r\n` +
            `Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{"assertio`,
        );
        sockets.push(socket);
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
      const busy = await signIn(port, passkey);
      assert.equal(busy.status, 503);
      assert.deepEqual(busy.body, { error: "busy" });
      assert.equal(busy.headers["retry-after"], "5");

      // Nobody closes those sockets: the door stops waiting for them by itself.
      await new Promise((resolve) => setTimeout(resolve, 900));
      const after = await signIn(port, passkey);
      assert.equal(after.status, 200, JSON.stringify(after.body));
    } finally {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => door.close(() => resolve()));
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D15 with no operator the door opens for enrolment with a code, and for nothing else", async () => {
    const body = await openBody(null);
    try {
      // No code was asked for at the machine, so there is nothing to guess at.
      for (const sent of [{}, { code: "00000000" }, { code: 7 }, "00000000", null]) {
        for (const path of ["/api/enroll/options", "/api/enroll"]) {
          const res = await call(body.doorPort, "POST", path, { body: sent });
          assert.equal(res.status, 403, `${path} ${JSON.stringify(sent)}`);
          assert.deepEqual(res.body, { error: "pairing-refused" });
        }
      }
      const { code } = beginPairing(body.stateDir);
      const options = await call(body.doorPort, "POST", "/api/enroll/options", { body: { code } });
      assert.equal(options.status, 200);
      assert.deepEqual(options.body.rp, { id: RP_ID, name: "Verax" });
      assert.equal(options.body.attestation, "none");
      assert.deepEqual(options.body.authenticatorSelection, { userVerification: "required", residentKey: "preferred" });
      assert.deepEqual(options.body.excludeCredentials, []);
      // A live code opens enrolment. The rest of the door is as shut as it was.
      for (const [method, path] of [
        ["POST", "/api/signin/options"],
        ["POST", "/api/signin"],
        ["GET", "/api/waiting"],
        ["POST", "/api/approve"],
        ["POST", "/api/halt"],
        ["POST", "/api/resume"],
      ] as const) {
        const res = await call(body.doorPort, method, path, method === "POST" ? { body: { code } } : {});
        assert.deepEqual(res.body, { error: "no-operator" }, `${method} ${path}`);
      }
      // Asking for a challenge enrolled nobody.
      assert.equal(existsSync(credentialsPath(body.stateDir)), false);
    } finally {
      await body.close();
    }
  });

  it("D16 a code from the machine enrolls one passkey, which then signs in and approves", async () => {
    const passkey = mintSoftwarePasskey();
    const body = await openBody(null);
    let open = true;
    const shut = async () => {
      if (!open) return;
      open = false;
      await new Promise<void>((resolve) => body.server.close(() => resolve()));
    };
    try {
      const { code } = beginPairing(body.stateDir);
      const done = await enroll(body.doorPort, code, passkey);
      assert.equal(done.status, 200, JSON.stringify(done.body));
      // Enrolling is not signing in: the answer carries no session.
      assert.deepEqual(done.body, { enrolled: true, sub: "operator-1" });
      assert.deepEqual(readCredentials(body.stateDir), [
        { id: passkey.id, publicKey: isoBase64URL.fromBuffer(passkey.publicKeyCose.slice()), counter: 0, sub: "operator-1" },
      ]);
      assert.equal((await call(body.doorPort, "GET", "/api/waiting")).status, 401);

      // The code bought one enrolment.
      const again = await enroll(body.doorPort, code, mintSoftwarePasskey());
      assert.equal(again.status, 403);
      assert.deepEqual(again.body, { error: "pairing-refused" });
      assert.equal(readCredentials(body.stateDir).length, 1);

      await hold(body, "door-d16");
      const signed = await signIn(body.doorPort, passkey);
      assert.equal(signed.status, 200, JSON.stringify(signed.body));
      const token = signed.body.token as string;
      const [row] = await waitingAt(body.doorPort, token);
      const unsigned = await call(body.doorPort, "POST", "/api/approve", {
        token,
        body: { ref: row!.ref, requestHash: row!.requestHash },
      });
      assert.equal(unsigned.status, 403, JSON.stringify(unsigned.body));
      const assertion = await approvalAssertion(body.doorPort, token, passkey, row!.ref);
      const ok = await call(body.doorPort, "POST", "/api/approve", {
        token,
        body: { ref: row!.ref, requestHash: row!.requestHash, assertion },
      });
      assert.equal(ok.status, 200, JSON.stringify(ok.body));
      await shut();
      const report = await verifyApprovalSignatures(body.stateDir);
      assert.equal(report.signedVerified, 1);
      assert.equal(report.signedFailed, 0);
    } finally {
      await shut();
      rmSync(body.stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D17 five wrong codes spend the pairing wherever they arrive, a code that ran out is refused, and the door does not say which", async () => {
    const body = await openBody(null);
    const refused = { error: "pairing-refused" };
    const ask = (path: string, code: string) => call(body.doorPort, "POST", path, { body: { code } });
    try {
      const { code } = beginPairing(body.stateDir);
      const wrong = code === "00000000" ? "11111111" : "00000000";
      for (const path of ["/api/enroll/options", "/api/enroll", "/api/enroll/options", "/api/enroll"]) {
        const res = await ask(path, wrong);
        assert.equal(res.status, 403);
        assert.deepEqual(res.body, refused);
      }
      // Four wrong tries leave the code good. The fifth ends it, and the right
      // code is then answered as the wrong one was.
      assert.equal(readPairing(body.stateDir)?.attempts, 4);
      assert.equal((await ask("/api/enroll/options", code)).status, 200);
      assert.deepEqual((await ask("/api/enroll/options", wrong)).body, refused);
      const late = await enroll(body.doorPort, code, mintSoftwarePasskey());
      assert.equal(late.status, 403);
      assert.deepEqual(late.body, refused);

      // Callers who arrive together have five tries between them, not five each.
      const next = beginPairing(body.stateDir).code;
      const miss = next === "00000000" ? "11111111" : "00000000";
      const together = await Promise.all(Array.from({ length: 12 }, () => ask("/api/enroll/options", miss)));
      for (const res of together) assert.deepEqual(res.body, refused);
      assert.equal(readPairing(body.stateDir)?.attempts, 5);
      assert.deepEqual((await enroll(body.doorPort, next, mintSoftwarePasskey())).body, refused);

      // The same code and the same passkey, a moment too late and then in time.
      const passkey = mintSoftwarePasskey();
      writePairing(body.stateDir, { hash: hashPairingCode("12345678"), expiresAtMs: Date.now() - 1, attempts: 0 });
      assert.deepEqual((await enroll(body.doorPort, "12345678", passkey)).body, refused);
      assert.equal(existsSync(credentialsPath(body.stateDir)), false);
      writePairing(body.stateDir, { hash: hashPairingCode("12345678"), expiresAtMs: Date.now() + 60_000, attempts: 0 });
      assert.equal((await enroll(body.doorPort, "12345678", passkey)).status, 200);
    } finally {
      await body.close();
    }
  });

  it("D18 enrolment refuses an answer made elsewhere, a used challenge and a passkey it already has", async () => {
    const first = mintSoftwarePasskey();
    const second = mintSoftwarePasskey();
    const third = mintSoftwarePasskey();
    const body = await openBody(first);
    const answer = (code: string, response: unknown) => call(body.doorPort, "POST", "/api/enroll", { body: { code, response } });
    const fresh = async (code: string) =>
      (await call(body.doorPort, "POST", "/api/enroll/options", { body: { code } })).body.challenge as string;
    try {
      const { code } = beginPairing(body.stateDir);
      const options = await call(body.doorPort, "POST", "/api/enroll/options", { body: { code } });
      assert.deepEqual(options.body.excludeCredentials, [{ id: first.id, type: "public-key" }]);

      // A sign-in challenge is not an enrolment challenge, and the other way round.
      const signinChallenge = (await call(body.doorPort, "POST", "/api/signin/options")).body.challenge as string;
      const crossed = await answer(code, registerWithSoftwarePasskey(second, { challenge: signinChallenge, rpID: RP_ID, origin: DOOR_ORIGIN }));
      assert.deepEqual(crossed.body, { error: "enroll-refused", reason: "challenge" });
      const enrollChallenge = await fresh(code);
      const backwards = await call(body.doorPort, "POST", "/api/signin", {
        body: { assertion: assertWithSoftwarePasskey(first, { challenge: enrollChallenge, rpID: RP_ID, origin: DOOR_ORIGIN }) },
      });
      assert.deepEqual(backwards.body, { error: "signin-refused" });

      const invented = randomBytes(56).toString("base64url");
      const forged = await answer(code, registerWithSoftwarePasskey(second, { challenge: invented, rpID: RP_ID, origin: DOOR_ORIGIN }));
      assert.deepEqual(forged.body, { error: "enroll-refused", reason: "challenge" });
      for (const response of [undefined, null, "x", {}, { response: {} }, { response: { clientDataJSON: 7 } }]) {
        assert.deepEqual((await answer(code, response)).body, { error: "enroll-refused", reason: "challenge" });
      }

      const elsewhere = await answer(
        code,
        registerWithSoftwarePasskey(second, { challenge: await fresh(code), rpID: RP_ID, origin: "https://evil.example" }),
      );
      assert.deepEqual(elsewhere.body, { error: "enroll-refused", reason: "origin" });
      const otherParty = await answer(
        code,
        registerWithSoftwarePasskey(second, { challenge: await fresh(code), rpID: "evil.example", origin: DOOR_ORIGIN }),
      );
      assert.deepEqual(otherParty.body, { error: "enroll-refused", reason: "rp-id" });
      const asSignIn = await answer(
        code,
        registrationFrom(second.id, attestedAuthData(second, RP_ID), { challenge: await fresh(code), origin: DOOR_ORIGIN, type: "webauthn.get" }),
      );
      assert.deepEqual(asSignIn.body, { error: "enroll-refused", reason: "type" });

      // None of those spent the code: it was right every time, the answers were not.
      const used = await fresh(code);
      const done = await answer(code, registerWithSoftwarePasskey(second, { challenge: used, rpID: RP_ID, origin: DOOR_ORIGIN }));
      assert.equal(done.status, 200, JSON.stringify(done.body));

      const another = beginPairing(body.stateDir).code;
      const replayed = await answer(another, registerWithSoftwarePasskey(third, { challenge: used, rpID: RP_ID, origin: DOOR_ORIGIN }));
      assert.deepEqual(replayed.body, { error: "enroll-refused", reason: "challenge" });
      const twice = await answer(another, registerWithSoftwarePasskey(second, { challenge: await fresh(another), rpID: RP_ID, origin: DOOR_ORIGIN }));
      assert.deepEqual(twice.body, { error: "enroll-refused", reason: "already-enrolled" });
      assert.equal((await enroll(body.doorPort, another, third)).status, 200);

      assert.deepEqual(
        readCredentials(body.stateDir).map((row) => row.id),
        [first.id, second.id, third.id],
      );
      for (const passkey of [first, second, third]) assert.equal((await signIn(body.doorPort, passkey)).status, 200);
    } finally {
      await body.close();
    }
  });

  it("D19 an enrolment challenge runs out, and an enrolment body is held to what a sign-in body is", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-operator-door-enroll-"));
    let clock = Date.now();
    const door = await openOperatorDoor({
      door: { origin: DOOR_ORIGIN, rpID: RP_ID, bindHost: "127.0.0.1", bindPort: 0 },
      stateDir,
      services: undefined as never,
      now: () => clock,
    });
    const port = (door.address() as AddressInfo).port;
    try {
      const { code } = beginPairing(stateDir, clock);
      const passkey = mintSoftwarePasskey();
      const options = await call(port, "POST", "/api/enroll/options", { body: { code } });
      assert.equal(options.body.timeout, DOOR_CHALLENGE_TTL_MS);
      const response = registerWithSoftwarePasskey(passkey, { challenge: options.body.challenge as string, rpID: RP_ID, origin: DOOR_ORIGIN });
      clock += DOOR_CHALLENGE_TTL_MS;
      const late = await call(port, "POST", "/api/enroll", { body: { code, response } });
      assert.deepEqual(late.body, { error: "enroll-refused", reason: "challenge" });
      // The door's clock is the one the code is read against.
      clock += PAIRING_TTL_MS;
      const stale = await call(port, "POST", "/api/enroll/options", { body: { code } });
      assert.deepEqual(stale.body, { error: "pairing-refused" });

      for (const path of ["/api/enroll/options", "/api/enroll"]) {
        const big = await call(port, "POST", path, { body: { code, response: "x".repeat(17 * 1024) } });
        assert.equal(big.status, 413, path);
        const foreign = await call(port, "POST", path, { body: { code }, origin: "https://evil.example" });
        assert.deepEqual(foreign.body, { error: "origin-not-allowed" }, path);
        const unnamed = await call(port, "POST", path, { body: { code }, origin: null });
        assert.deepEqual(unnamed.body, { error: "origin-required" }, path);
        assert.equal((await call(port, "GET", path)).status, 404, path);
      }
      assert.equal(existsSync(credentialsPath(stateDir)), false);
    } finally {
      await new Promise<void>((resolve) => door.close(() => resolve()));
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D20 a wrong code that cannot be counted ends the code, on disk and in the running body", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-operator-door-full-"));
    // A full disk: the right code is read, a wrong one cannot be counted.
    const door = await openOperatorDoor({
      door: { origin: DOOR_ORIGIN, rpID: RP_ID, bindHost: "127.0.0.1", bindPort: 0 },
      stateDir,
      services: undefined as never,
      checkPairing: (dir, code, nowMs) => {
        const open = readPairing(dir);
        if (open && hashPairingCode(code) !== open.hash) throw new Error("ENOSPC: no space left on device");
        return checkPairing(dir, code, nowMs);
      },
    });
    const port = (door.address() as AddressInfo).port;
    const refused = { error: "pairing-refused" };
    try {
      // Four wrong tries were counted while there was room. The fifth cannot be.
      const code = "24681357";
      const record = { hash: hashPairingCode(code), expiresAtMs: Date.now() + 60_000, attempts: 4 };
      writePairing(stateDir, record);
      assert.equal((await call(port, "POST", "/api/enroll/options", { body: { code } })).status, 200);
      const fifth = await call(port, "POST", "/api/enroll/options", { body: { code: "00000000" } });
      assert.equal(fifth.status, 403);
      assert.deepEqual(fifth.body, refused);
      // The code is gone from the disk, so a body started later does not take it either.
      assert.equal(existsSync(pairingPath(stateDir)), false);
      assert.deepEqual((await enroll(port, code, mintSoftwarePasskey())).body, refused);

      // Had the file been one that could not be removed, this body still refuses the code.
      writePairing(stateDir, { ...record, attempts: 0 });
      assert.deepEqual((await enroll(port, code, mintSoftwarePasskey())).body, refused);
      assert.equal(existsSync(credentialsPath(stateDir)), false);

      // A code asked for afresh is another code.
      assert.equal((await enroll(port, beginPairing(stateDir).code, mintSoftwarePasskey())).status, 200);
    } finally {
      await new Promise<void>((resolve) => door.close(() => resolve()));
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D21 enrolment bodies wait in the same short line as sign-in bodies, and a slow one is dropped", async () => {
    const passkey = mintSoftwarePasskey();
    const stateDir = mkdtempSync(join(tmpdir(), "verax-operator-door-line-"));
    saveCredential(stateDir, {
      id: passkey.id,
      publicKey: isoBase64URL.fromBuffer(passkey.publicKeyCose.slice()),
      counter: 0,
      sub: "operator-1",
    });
    const door = await openOperatorDoor({
      door: { origin: DOOR_ORIGIN, rpID: RP_ID, bindHost: "127.0.0.1", bindPort: 0 },
      stateDir,
      services: undefined as never,
      signinBodyMs: 600,
    });
    const port = (door.address() as AddressInfo).port;
    const sockets: Socket[] = [];
    try {
      const { code } = beginPairing(stateDir);
      // Thirty-two enrolment requests that each send the start of a body and then nothing.
      for (let i = 0; i < 32; i += 1) {
        // Half-open on this side, as in `unending`: a door that only stopped writing leaves these up.
        const socket = connect({ port, host: "127.0.0.1", allowHalfOpen: true });
        socket.on("error", () => undefined);
        socket.write(
          `POST ${i % 2 === 0 ? "/api/enroll" : "/api/enroll/options"} HTTP/1.1\r\nHost: ${DOOR_HOST}\r\nOrigin: ${DOOR_ORIGIN}\r\n` +
            `Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{"code":"1`,
        );
        sockets.push(socket);
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
      for (const path of ["/api/enroll/options", "/api/enroll"]) {
        const busy = await call(port, "POST", path, { body: { code } });
        assert.equal(busy.status, 503, path);
        assert.deepEqual(busy.body, { error: "busy" });
        assert.equal(busy.headers["retry-after"], "5");
      }
      // A caller told the line is full is not then read from for as long as it likes.
      assert.deepEqual(
        await unending(port, `POST /api/enroll HTTP/1.1\r\nOrigin: ${DOOR_ORIGIN}\r\n`, sockets),
        { status: "503", cut: true },
      );
      // The line is one line: a sign-in waits behind enrolment bodies too.
      assert.equal((await signIn(port, passkey)).status, 503);
      // A code that never arrived whole was not a wrong try.
      assert.equal(readPairing(stateDir)?.attempts, 0);

      // Nobody closes those sockets: the door stops waiting for them by itself.
      await new Promise((resolve) => setTimeout(resolve, 900));
      // Dropped means hung up on, not only no longer counted: what these go on to send finds nobody reading.
      for (let wrote = 0; wrote < 3; wrote += 1) {
        for (const socket of sockets.slice(0, 32)) if (!socket.destroyed) socket.write("0");
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.equal(sockets.slice(0, 32).filter((socket) => !socket.destroyed).length, 0);
      assert.equal((await call(port, "POST", "/api/enroll/options", { body: { code } })).status, 200);
      assert.equal((await signIn(port, passkey)).status, 200);
    } finally {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => door.close(() => resolve()));
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D22 a request the door answers without reading is cut, whatever it goes on sending", async () => {
    const passkey = mintSoftwarePasskey();
    const body = await openBody(passkey);
    const empty = await openBody(null);
    const sockets: Socket[] = [];
    try {
      const token = (await signIn(body.doorPort, passkey)).body.token as string;
      const named = `Origin: ${DOOR_ORIGIN}\r\n`;
      const session = `Authorization: Bearer ${token}\r\n`;
      const rows: [why: string, port: number, head: string, status: string, over?: { host?: string; framing?: string }][] = [
        ["another name", body.doorPort, `POST /api/signin HTTP/1.1\r\n${named}`, "400", { host: "evil.example" }],
        ["a target that is no address", body.doorPort, `GET http://x:99999/ HTTP/1.1\r\n`, "400"],
        ["an expectation the door does not meet", body.doorPort, `POST /api/signin HTTP/1.1\r\n${named}Expect: x\r\n`, "417"],
        // Node says go on, as the header asks. The door reads no further than any other body, and hangs up.
        ["an expectation Node meets", body.doorPort, `POST /api/signin HTTP/1.1\r\n${named}Expect: 100-continue\r\n`, "100"],
        ["the page takes no body", body.doorPort, `GET / HTTP/1.1\r\n`, "200"],
        ["nor do its files, enrolled or not", empty.doorPort, `GET /door.js HTTP/1.1\r\n`, "200"],
        ["not on the list", body.doorPort, `POST /mcp HTTP/1.1\r\n${named}`, "404"],
        ["another origin", body.doorPort, `POST /api/signin HTTP/1.1\r\nOrigin: https://evil.example\r\n`, "403"],
        ["no origin", body.doorPort, `POST /api/signin HTTP/1.1\r\n`, "403"],
        ["no operator", empty.doorPort, `POST /api/approve HTTP/1.1\r\n${named}`, "403"],
        ["no session", body.doorPort, `POST /api/approve HTTP/1.1\r\n${named}`, "401"],
        ["a length announced past the limit", body.doorPort, `POST /api/signin HTTP/1.1\r\n${named}`, "413", { framing: "Content-Length: 20000" }],
        ["a body that runs past the limit", body.doorPort, `POST /api/enroll HTTP/1.1\r\n${named}`, "413"],
        ["options take no body", body.doorPort, `POST /api/signin/options HTTP/1.1\r\n${named}`, "200"],
        ["a list read takes no body", body.doorPort, `GET /api/waiting HTTP/1.1\r\n${session}`, "200"],
        ["sign-out takes no body", body.doorPort, `POST /api/signout HTTP/1.1\r\n${named}${session}`, "200"],
      ];
      for (const [why, port, head, status, over] of rows) {
        const seen = await unending(port, head, sockets, over);
        assert.deepEqual(seen, { status, cut: true }, why);
      }
    } finally {
      for (const socket of sockets) socket.destroy();
      await body.close();
      await empty.close();
    }
  });

  it("D23 the door opens before the main listener, a taken port stops the start, and what did open is shut again", async () => {
    const hold = async () => {
      const server = createNetServer();
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
      return { server, port: (server.address() as AddressInfo).port };
    };
    const release = (server: ReturnType<typeof createNetServer>) => new Promise<void>((resolve) => server.close(() => resolve()));
    const doorSquatter = await hold();
    const mainSquatter = await hold();
    const stateDir = mkdtempSync(join(tmpdir(), "verax-operator-door-taken-"));
    const { publicKey } = await generateKeyPair("ES256", { extractable: true });
    const jwksFile = join(stateDir, "jwks.json");
    writeFileSync(jwksFile, JSON.stringify({ keys: [{ ...(await exportJWK(publicKey)), kid: "local-1", alg: "ES256", use: "sig" }] }));
    const start = (doorPort: number, mainPort: number) =>
      listen({
        issuer: ISSUER,
        jwksUrl: "",
        jwksFile,
        audience: AUDIENCE,
        stateDir,
        bindHost: "127.0.0.1",
        bindPort: mainPort,
        policyFile: approvePolicyFile(stateDir),
        tlsTerminated: false,
        operatorDoor: { origin: DOOR_ORIGIN, rpID: RP_ID, bindHost: "127.0.0.1", bindPort: doorPort },
      });
    try {
      // Both ports are taken. The one the start names is the one it tried first.
      await assert.rejects(start(doorSquatter.port, mainSquatter.port), new RegExp(`EADDRINUSE.*:${doorSquatter.port}\\b`));

      // The door's port is free and the main one is not: the door opened, then had to shut.
      await release(doorSquatter.server);
      await assert.rejects(start(doorSquatter.port, mainSquatter.port), new RegExp(`EADDRINUSE.*:${mainSquatter.port}\\b`));
      const again = createNetServer();
      await new Promise<void>((resolve, reject) => {
        again.once("error", reject);
        again.listen(doorSquatter.port, "127.0.0.1", () => resolve());
      });
      await release(again);

      // Nothing of the refused starts is left holding the ledger: the same state starts once both ports are free.
      const server = await start(0, 0);
      assert.notEqual(operatorDoorOf(server), null);
      await new Promise<void>((resolve) => server.close(() => resolve()));
    } finally {
      if (doorSquatter.server.listening) await release(doorSquatter.server);
      await release(mainSquatter.server);
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D24 root asks for a pairing code, a list or a removal as the owner of the state directory, or not at all", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-operator-enroll-"));
    const service = { uid: 997, gid: 995, isDirectory: true };
    type Disk = Record<string, typeof service | undefined>;
    type Fake = { sys: OperatorSys; calls: string[] };
    /** A process that says it is root, over a disk the test describes. */
    const root = (disk: Disk, over: Partial<OperatorSys> = {}): Fake => {
      const calls: string[] = [];
      let uid = 0;
      let gid = 0;
      const sys: OperatorSys = {
        platform: "linux",
        getuid: () => uid,
        getgid: () => gid,
        setgroups: (groups) => void calls.push(`setgroups ${groups.join(",")}`),
        setgid: (next) => {
          calls.push(`setgid ${next}`);
          gid = next;
        },
        setuid: (next) => {
          calls.push(`setuid ${next}`);
          uid = next;
        },
        look: (path) => disk[path] ?? null,
        ...over,
      };
      return { sys, calls };
    };
    const enroll = (fake: Fake, dir = stateDir) => quiet(() => runOperator(["operator", "enroll", "--state", dir], fake.sys));
    try {
      // The service's directory: root becomes the service, in this order, and only then writes.
      const drop = root({ [stateDir]: service });
      const done = await enroll(drop);
      assert.equal(done.code, 0, done.err);
      assert.match(done.out, /^\d{8}\n$/);
      assert.deepEqual(drop.calls, ["setgroups 995", "setgid 995", "setuid 997"]);
      assert.equal(readPairing(stateDir)?.attempts, 0);
      rmSync(pairingPath(stateDir));

      // A list and a removal go in the same way: a file root left here is one the service cannot read.
      saveCredential(stateDir, { id: "passkey-a", publicKey: "", counter: 0, sub: "operator-1" });
      saveCredential(stateDir, { id: "passkey-b", publicKey: "", counter: 0, sub: "operator-1" });
      for (const rest of [["list"], ["remove", "--id", "passkey-a"]]) {
        const as = root({ [stateDir]: service });
        const ran = await quiet(() => runOperator(["operator", rest[0]!, "--state", stateDir, ...rest.slice(1)], as.sys));
        assert.equal(ran.code, 0, ran.err);
        assert.deepEqual(as.calls, ["setgroups 995", "setgid 995", "setuid 997"], rest[0]);
      }
      const held = root({ [stateDir]: service }, { setuid: undefined });
      const kept = await quiet(() => runOperator(["operator", "remove", "--state", stateDir, "--id", "passkey-b"], held.sys));
      assert.equal(kept.code, 78);
      assert.match(kept.err, /cannot-change-account/);
      const marked = readRemoved(stateDir);
      assert.deepEqual([marked?.has("passkey-a"), marked?.has("passkey-b")], [true, false]);

      // A drop that cannot be made, or that did not take in either half, writes nothing.
      for (const [why, over, said] of [
        ["no setuid", { setuid: undefined }, /cannot-change-account/],
        ["setgid throws", { setgid: () => { throw new Error("EPERM"); } }, /cannot-change-account/],
        ["setuid changes nothing", { setuid: () => undefined }, /account-did-not-change/],
        ["setgid changes nothing", { setgid: () => undefined }, /account-did-not-change/],
      ] as const) {
        const stuck = await enroll(root({ [stateDir]: service }, over as Partial<OperatorSys>));
        assert.equal(stuck.code, 78, why);
        assert.match(stuck.err, said, why);
        assert.equal(existsSync(pairingPath(stateDir)), false, why);
      }

      // Root makes no state directory, follows no link to one, and keeps no group of its own.
      const missing = join(stateDir, "not-there");
      const none = await enroll(root({}), missing);
      assert.equal(none.code, 78);
      assert.match(none.err, /state-dir-missing/);
      assert.equal(existsSync(missing), false);
      for (const [seen, said] of [
        [{ ...service, isDirectory: false }, /state-dir-not-a-directory/],
        [{ ...service, gid: 0 }, /state-dir-group-is-roots/],
      ] as const) {
        const refused = await enroll(root({ [stateDir]: seen }));
        assert.equal(refused.code, 78);
        assert.match(refused.err, said);
        assert.equal(existsSync(pairingPath(stateDir)), false);
      }
      // A slash after a link would have the link looked through. The path is resolved before it is looked at.
      const looked: string[] = [];
      const slashed = pairingWriter(`${stateDir}/`, { ...root({}).sys, look: (path) => (looked.push(path), null) });
      assert.equal(slashed.kind, "refuse");
      assert.deepEqual(looked.map((path) => /[\\/]$/.test(path)), [false]);

      // On the real disk: a link to a directory is seen as a link, so root is refused at it and not at the directory.
      const real = join(stateDir, "real");
      const link = join(stateDir, "link");
      mkdirSync(real);
      symlinkSync(real, link, "junction");
      assert.equal(lookWithoutFollowing(real)?.isDirectory, true);
      assert.equal(lookWithoutFollowing(link)?.isDirectory, false);
      assert.equal(lookWithoutFollowing(join(stateDir, "nothing")), null);
      const atLink = pairingWriter(link, { platform: "linux", getuid: () => 0, look: lookWithoutFollowing });
      assert.deepEqual(atLink, { kind: "refuse", reason: `state-dir-not-a-directory:${link}` });

      // Root's own directory is written as root, as before. Anyone but root, and anyone on Windows, writes as who they are.
      const own = root({ [stateDir]: { ...service, uid: 0, gid: 0 } });
      assert.equal((await enroll(own)).code, 0);
      assert.deepEqual(own.calls, []);
      assert.equal(pairingWriter(stateDir, { ...root({}).sys, getuid: () => 1000 }).kind, "as-is");
      assert.equal(pairingWriter(stateDir, { ...root({}).sys, platform: "win32" }).kind, "as-is");
      assert.equal(pairingWriter(stateDir, { ...root({}).sys, getuid: undefined }).kind, "as-is");
    } finally {
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D25 the page is three files handed to anyone who asks under the door's name, each sealed by its headers", async () => {
    const enrolled = await openBody(mintSoftwarePasskey());
    const empty = await openBody(null);
    try {
      for (const body of [enrolled, empty]) {
        for (const [path, type, text] of [
          ["/", "text/html; charset=utf-8", DOOR_HTML],
          ["/door.js", "text/javascript; charset=utf-8", DOOR_JS],
          ["/door.css", "text/css; charset=utf-8", DOOR_CSS],
        ] as const) {
          const res = await call(body.doorPort, "GET", path);
          assert.equal(res.status, 200, path);
          // The same bytes whether or not anyone is enrolled: the page says nothing about this body.
          assert.equal(res.body.raw, text, path);
          assert.equal(res.headers["content-type"], type, path);
          assert.equal(res.headers["content-security-policy"], PAGE_CSP, path);
          assert.equal(res.headers["x-frame-options"], "DENY", path);
          assert.equal(res.headers["referrer-policy"], "no-referrer", path);
          assert.equal(res.headers["cross-origin-opener-policy"], "same-origin", path);
          assert.equal(res.headers["cross-origin-resource-policy"], "same-origin", path);
          assert.equal(res.headers["x-content-type-options"], "nosniff", path);
          assert.equal(res.headers["cache-control"], "no-store", path);
          assert.equal(res.headers.connection, "close", path);
          // Under another name the page is not served, and a page elsewhere cannot read it.
          assert.equal((await call(body.doorPort, "GET", path, { host: "evil.example" })).status, 400, path);
          assert.equal((await call(body.doorPort, "GET", path, { origin: "https://evil.example" })).status, 403, path);
        }
      }
      // The policy lets the page load its own two files and call its own origin. Nothing else.
      const policy = new Map(PAGE_CSP.split("; ").map((part) => [part.split(" ")[0]!, part.split(" ").slice(1).join(" ")]));
      assert.equal(policy.get("default-src"), "'none'");
      assert.equal(policy.get("script-src"), "'self'");
      assert.equal(policy.get("style-src"), "'self'");
      assert.equal(policy.get("connect-src"), "'self'");
      assert.equal(policy.get("frame-ancestors"), "'none'");
      assert.equal(policy.get("form-action"), "'none'");
      assert.equal(policy.get("base-uri"), "'none'");
      assert.equal(policy.get("require-trusted-types-for"), "'script'");
      assert.equal(policy.get("trusted-types"), "'none'");
      assert.equal(policy.size, 9);
    } finally {
      await enrolled.close();
      await empty.close();
    }
  });

  it("D26 the page carries no script or style of its own in the markup, and its script has no way to write markup or keep a token", () => {
    for (const text of [DOOR_HTML, DOOR_JS, DOOR_CSS]) {
      assert.ok(Buffer.byteLength(text) < 48 * 1024);
    }
    // The script compiles. Nothing here runs it.
    new Script(DOOR_JS, { filename: "door.js" });
    // What it escapes before it shows a held call is the class the terminal escapes, not a copy of it.
    assert.ok(DOOR_JS.includes(`new RegExp("[" + ${JSON.stringify(DISPLAY_ESCAPE_CLASS)} + "]", "gu")`));
    assert.equal(DOOR_JS.includes("@@"), false);
    for (const banned of [
      /innerHTML/,
      /outerHTML/,
      /insertAdjacentHTML/,
      /document\s*\.\s*write/,
      /\beval\b/,
      /Function\s*\(/,
      /localStorage/,
      /sessionStorage/,
      /indexedDB/,
      /\.cookie\b/,
      /console\s*\./,
      /https?:\/\//,
      /importScripts/,
      /postMessage/,
      /\bwindow\s*\.\s*[A-Za-z_$][\w$]*\s*=[^=]/,
      /globalThis/,
    ]) {
      assert.equal(banned.test(DOOR_JS), false, `door.js: ${banned}`);
    }
    // The markup loads the two files by path and holds nothing a strict policy would have to excuse.
    const scripts = [...DOOR_HTML.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    assert.equal(scripts.length, 1);
    assert.match(scripts[0]![1]!, /\bsrc="\/door\.js"/);
    assert.equal(scripts[0]![2]!.trim(), "");
    const links = [...DOOR_HTML.matchAll(/<link\b([^>]*)>/gi)];
    assert.equal(links.length, 1);
    assert.match(links[0]![1]!, /\bhref="\/door\.css"/);
    for (const banned of [/<style\b/i, /\sstyle\s*=/i, /\son[a-z]+\s*=/i, /<form\b/i, /<iframe\b/i, /<img\b/i, /<base\b/i, /https?:\/\//i, /javascript:/i]) {
      assert.equal(banned.test(DOOR_HTML), false, `page: ${banned}`);
    }
    for (const banned of [/url\s*\(/i, /@import/i, /expression\s*\(/i, /https?:\/\//i]) {
      assert.equal(banned.test(DOOR_CSS), false, `door.css: ${banned}`);
    }
  });

  // D26 checks the class is the one the terminal uses; this runs the page's own
  // plain() on the characters that draw nothing or draw over their neighbour,
  // and on a backslash, so a written escape and the character it stands for
  // read differently on the page.
  it("D26b the page's plain() shows what the terminal escapes, and a written escape differs from the character", () => {
    const start = DOOR_JS.indexOf("var CONTROL");
    const end = DOOR_JS.indexOf("function clock");
    assert.ok(start >= 0 && end > start, "plain() not found in door.js");
    const plain = new Script(`${DOOR_JS.slice(start, end)}; plain;`).runInNewContext({}) as (t: string, k?: boolean) => string;
    for (const [raw, esc] of [
      ["\ufe0f", "\\ufe0f"],
      ["\u{e0101}", "\\udb40\\udd01"],
      ["\u3164", "\\u3164"],
      ["\u2800", "\\u2800"],
      ["\u0338", "\\u0338"],
      ["\u1cbb", "\\u1cbb"],
      ["\ue000", "\\ue000"],
    ]) {
      const shown = plain(`inv${raw}`);
      assert.equal(shown.includes(raw), false, `left as it is: ${esc}`);
      assert.ok(shown.includes(esc), esc);
    }
    assert.notEqual(plain("inv\\u3164"), plain("inv\u3164"));
    // The argument block is JSON, shown with line breaks kept; the class is escaped there too.
    const block = plain(JSON.stringify({ reference: "inv-4\u0338\ufe0f" }, null, 2), true);
    assert.equal(block.includes("\u0338") || block.includes("\ufe0f"), false, block);
    assert.ok(block.includes("\\u0338") && block.includes("\\ufe0f") && block.includes("\n"), block);
    assert.equal(plain("inv-7"), "inv-7");
    assert.equal(plain("Ünlü ışık"), "Ünlü ışık");
  });

  it("D27 a held spend is listed with the payee and the amount `verax approve` prints, and no other call is", async () => {
    const passkey = mintSoftwarePasskey();
    const body = await openBody(passkey);
    try {
      await hold(body, "door-d27");
      await holdSpend(body, { amountMinor: 1250, currency: "USD", payee: "sample-merchant", reference: "inv-7" });
      const token = (await signIn(body.doorPort, passkey)).body.token as string;
      const listed = (await call(body.doorPort, "GET", "/api/waiting", { token })).body.waiting as Array<{
        tool: string;
        spend?: unknown;
      }>;
      assert.equal(listed.length, 2);
      assert.deepEqual(listed.find((row) => row.tool === "spend")?.spend, {
        payee: "sample-merchant",
        amountMinor: 1250,
        currency: "USD",
        reference: "inv-7",
      });
      assert.equal("spend" in listed.find((row) => row.tool === "memory.put")!, false);
    } finally {
      await body.close();
    }
    const row = {
      ref: "r",
      requestHash: "h",
      ruleId: null,
      ruleText: null,
      inputsSummary: { count: 0, ids: [] },
      expiresAtMs: 1,
      status: "pending" as const,
      brain: "b",
    };
    // An amount that is not a whole number of minor units is not an amount, here as at the terminal.
    assert.deepEqual(heldSpend({ ...row, subject: "spend", amount: "1250", payee: 7, args: { payee: 7, currency: "USD" } }), {
      payee: "7",
      amountMinor: null,
      currency: "USD",
      reference: "",
    });
    assert.equal(heldSpend({ ...row, subject: "spend", amount: 12.5, args: {} })?.amountMinor, null);
    assert.equal(heldSpend({ ...row, subject: "spend", args: { amountMinor: "1250" } })?.amountMinor, null);
    // What will be sent is what is shown, as at the terminal.
    assert.equal(heldSpend({ ...row, subject: "spend", payee: "stored", args: { payee: "argued" } })?.payee, "argued");
    assert.equal(heldSpend({ ...row, subject: "spend", currency: "EUR", args: { currency: "USD" } })?.currency, "USD");
    assert.equal(
      heldSpend({
        ...row,
        subject: "spend",
        args: { payee: "argued" },
        forwardedArgs: { payee: "sent", currency: "TRY", amountMinor: 40, reference: "r" },
      })?.payee,
      "sent",
    );
    assert.equal(heldSpend({ ...row, subject: "spend", args: { amountMinor: 40 } })?.amountMinor, 40);
    assert.equal(heldSpend({ ...row, subject: "memory.put", amount: 5, payee: "x", args: {} }), null);
  });

  it("D28 a passkey taken out of use ends its sessions and signs nothing more, and what it signed still verifies", async () => {
    const phone = mintSoftwarePasskey();
    const spare = mintSoftwarePasskey();
    const publicKeyOf = (passkey: SoftwarePasskey) => isoBase64URL.fromBuffer(passkey.publicKeyCose.slice());
    const body = await openBody(phone);
    saveCredential(body.stateDir, { id: spare.id, publicKey: publicKeyOf(spare), counter: 0, sub: "operator-1" });
    let open = true;
    const shut = async () => {
      if (!open) return;
      open = false;
      await new Promise<void>((resolve) => body.server.close(() => resolve()));
    };
    /** Approves the one call waiting, in `token`'s session, with an assertion `signer` makes. */
    const approve = async (token: string, signer: SoftwarePasskey): Promise<Answer> => {
      const [row] = await waitingAt(body.doorPort, token);
      const assertion = await approvalAssertion(body.doorPort, token, signer, row!.ref);
      return call(body.doorPort, "POST", "/api/approve", {
        token,
        body: { ref: row!.ref, requestHash: row!.requestHash, assertion },
      });
    };
    try {
      await hold(body, "door-d28-before");
      const phoneToken = (await signIn(body.doorPort, phone)).body.token as string;
      assert.equal((await approve(phoneToken, phone)).status, 200);
      const spareToken = (await signIn(body.doorPort, spare)).body.token as string;

      const gone = await quiet(() => runOperator(["operator", "remove", "--state", body.stateDir, "--id", phone.id]));
      assert.deepEqual([gone.code, gone.out], [0, "removed\n"], gone.err);

      // The session it opened is over, and it opens no other.
      assert.equal((await call(body.doorPort, "GET", "/api/waiting", { token: phoneToken })).status, 401);
      const options = await call(body.doorPort, "POST", "/api/signin/options");
      assert.deepEqual(options.body.allowCredentials, [{ id: spare.id, type: "public-key" }]);
      assert.equal((await signIn(body.doorPort, phone)).status, 403);

      // The other passkey goes on as before. Inside its session the removed one still signs for nothing.
      await hold(body, "door-d28-after");
      const lent = await approve(spareToken, phone);
      assert.equal(lent.status, 403, JSON.stringify(lent.body));
      assert.equal((await approve(spareToken, spare)).status, 200);

      // Its row is where it was. The body has rewritten the file twice since,
      // for the other passkey's counter and for a new enrolment, and no
      // enrolment can take the id.
      const over = await enroll(body.doorPort, beginPairing(body.stateDir).code, phone);
      assert.deepEqual(over.body, { error: "enroll-refused", reason: "already-enrolled" });
      assert.equal((await enroll(body.doorPort, beginPairing(body.stateDir).code, mintSoftwarePasskey())).status, 200);
      const rows = readCredentialsAt(credentialsPath(body.stateDir));
      assert.equal(rows.length, 3);
      assert.equal(rows.find((row) => row.id === phone.id)?.publicKey, publicKeyOf(phone));

      // Both approvals read back from the files, the removed passkey's among them.
      await shut();
      const report = await verifyApprovalSignatures(body.stateDir);
      assert.equal(report.signedVerified, 2);
      assert.equal(report.signedFailed, 0);
    } finally {
      await shut();
      rmSync(body.stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D29 `verax operator` lists and removes by id, and a list of the removed that does not read leaves no passkey in use", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-operator-remove-"));
    const run = (...rest: string[]) => quiet(() => runOperator(["operator", ...rest]));
    try {
      for (const id of ["passkey-a", "passkey-b"]) saveCredential(stateDir, { id, publicKey: "", counter: 0, sub: "operator-1" });
      const before = readFileSync(credentialsPath(stateDir), "utf8");
      assert.deepEqual(await run("list", "--state", stateDir), {
        code: 0,
        out: "passkey-a\toperator-1\tin use\npasskey-b\toperator-1\tin use\n",
        err: "",
      });

      // What it is not asked plainly it does not do, and it removes nothing it was not shown.
      for (const [rest, said] of [
        [["remove", "--state", stateDir], /^verax operator enroll/],
        [["remove", "--id", "passkey-a"], /^verax operator enroll/],
        [["list", "--state", stateDir, "--id", "passkey-a"], /^flag-unknown:--id\n$/],
        [["remove", "--state", stateDir, "--all"], /^flag-unknown:--all\n$/],
        [["remove", "--state", stateDir, "--id", "passkey-c"], /^passkey-unknown\n$/],
        [["forget", "--state", stateDir], /^verax operator enroll/],
      ] as const) {
        const refused = await run(...rest);
        assert.equal(refused.code, 78, rest.join(" "));
        assert.match(refused.err, said, rest.join(" "));
      }
      assert.equal(existsSync(removedPath(stateDir)), false);

      assert.equal((await run("remove", "--state", stateDir, "--id", "passkey-a")).out, "removed\n");
      assert.equal((await run("remove", "--state", stateDir, "--id", "passkey-a")).out, "already-removed\n");
      const marks = () => readdirSync(removedPath(stateDir)).sort();
      const first = marks();
      assert.equal(first.length, 1);
      assert.deepEqual(readCredentials(stateDir).map((row) => row.id), ["passkey-b"]);
      assert.equal((await run("list", "--state", stateDir)).out, "passkey-a\toperator-1\tremoved\npasskey-b\toperator-1\tin use\n");

      // The last one out says so. Its removal adds a mark and leaves the
      // first where it was: nothing two removals share is written twice.
      const stamp = statSync(join(removedPath(stateDir), first[0]!)).mtimeMs;
      const last = await run("remove", "--state", stateDir, "--id", "passkey-b");
      assert.equal(last.code, 0);
      assert.match(last.out, /^removed\nno passkey is left in use: /);
      assert.equal(marks().length, 2);
      assert.ok(marks().includes(first[0]!));
      assert.equal(statSync(join(removedPath(stateDir), first[0]!)).mtimeMs, stamp);
      assert.deepEqual(readCredentials(stateDir), []);

      // The credentials file is not touched by any of this, and it is still
      // there: with nobody left, the body does not go back to approving
      // without a passkey. An id it holds keeps the key it has.
      assert.equal(saveCredential(stateDir, { id: "passkey-a", publicKey: "another", counter: 0, sub: "operator-1" }), false);
      assert.equal(readFileSync(credentialsPath(stateDir), "utf8"), before);
      assert.equal(hasRegisteredOperator(stateDir), true);

      // A name in the directory that is no passkey's mark removes nobody.
      rmSync(removedPath(stateDir), { recursive: true });
      mkdirSync(removedPath(stateDir));
      writeFileSync(join(removedPath(stateDir), "passkey-a"), "");
      assert.deepEqual(readCredentials(stateDir).map((row) => row.id), ["passkey-a", "passkey-b"]);

      // Something at the path that cannot be listed is not "none removed":
      // any passkey might have a mark there.
      rmSync(removedPath(stateDir), { recursive: true });
      writeFileSync(removedPath(stateDir), "");
      assert.equal(readRemoved(stateDir), null);
      assert.deepEqual(readCredentials(stateDir), []);
      for (const rest of [["list", "--state", stateDir], ["remove", "--state", stateDir, "--id", "passkey-a"]]) {
        const stopped = await run(...rest);
        assert.equal(stopped.code, 78);
        assert.match(stopped.err, /^removed-list-unreadable:/);
        assert.equal(stopped.out, "");
      }
      assert.equal(statSync(removedPath(stateDir)).isFile(), true);
      rmSync(removedPath(stateDir));

      // A credentials file that does not parse is said to be that, not listed as empty.
      for (const text of ["", "{", "[]", '{"credentials":"none"}']) {
        writeFileSync(credentialsPath(stateDir), text);
        for (const rest of [["list", "--state", stateDir], ["remove", "--state", stateDir, "--id", "passkey-a"]]) {
          const stopped = await run(...rest);
          assert.equal(stopped.code, 78, text);
          assert.match(stopped.err, /^credentials-unreadable:/, text);
          assert.equal(stopped.out, "", text);
        }
        assert.equal(existsSync(removedPath(stateDir)), false, text);
      }
    } finally {
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D30 removals made at the same moment all hold", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-operator-remove-race-"));
    // Each child runs the operator entry itself. Through cli.ts an elevated
    // process refuses code its user can change, which is every checkout on a
    // runner that is an administrator, and no removal would be reached.
    const entry = new URL("../packages/body/src/operator-cli.ts", import.meta.url).href;
    const script =
      `const { runOperator } = await import(${JSON.stringify(entry)});` +
      `process.exit(await runOperator(["operator", "remove", "--state", process.argv[1], "--id", process.argv[2]]));`;
    const ids = Array.from({ length: 12 }, (_, i) => `passkey-${i}`);
    try {
      for (const id of ids) saveCredential(stateDir, { id, publicKey: "", counter: 0, sub: "operator-1" });
      // Twelve processes, one passkey each, started together. With one list
      // read, changed and written back, the later writers undid the earlier.
      const codes = await Promise.all(
        ids.map(
          (id) =>
            new Promise<number | null>((resolve) => {
              const child = spawn(
                process.execPath,
                ["--experimental-strip-types", "--input-type=module", "-e", script, stateDir, id],
                { stdio: "ignore" },
              );
              child.once("exit", (code) => resolve(code));
            }),
        ),
      );
      assert.deepEqual(codes, ids.map(() => 0));
      assert.equal(readdirSync(removedPath(stateDir)).length, ids.length);
      assert.deepEqual(readCredentials(stateDir), []);
    } finally {
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  /** The ledger's decisions in chain order, read from the files. */
  const decisionsIn = (stateDir: string): SignedDecisionRecord[] =>
    listPieceFiles(stateDir).flatMap((piece) =>
      existsSync(piece.decisions)
        ? readFileSync(piece.decisions, "utf8").split("\n").filter((line) => line !== "").map((line) => JSON.parse(line) as SignedDecisionRecord)
        : [],
    );

  it("D33 a removal the CLI filed is in the ledger before the next approval over the door", async () => {
    const phone = mintSoftwarePasskey();
    const spare = mintSoftwarePasskey();
    const body = await openBody(phone);
    saveCredential(body.stateDir, { id: spare.id, publicKey: isoBase64URL.fromBuffer(spare.publicKeyCose.slice()), counter: 0, sub: "operator-1" });
    let open = true;
    const shut = async () => {
      if (!open) return;
      open = false;
      await new Promise<void>((resolve) => body.server.close(() => resolve()));
    };
    try {
      // The call is held before the removal; nothing reaches the proxy between the removal and the approval.
      await hold(body, "door-d33");
      const spareToken = (await signIn(body.doorPort, spare)).body.token as string;
      const gone = await quiet(() => runOperator(["operator", "remove", "--state", body.stateDir, "--id", phone.id]));
      assert.equal(gone.code, 0, gone.err);
      const [row] = await waitingAt(body.doorPort, spareToken);
      const assertion = await approvalAssertion(body.doorPort, spareToken, spare, row!.ref);
      const approved = await call(body.doorPort, "POST", "/api/approve", {
        token: spareToken,
        body: { ref: row!.ref, requestHash: row!.requestHash, assertion },
      });
      assert.equal(approved.status, 200, JSON.stringify(approved.body));
      await shut();
      const order = decisionsIn(body.stateDir)
        .map((record) => (record.claims.subject === "verax.operator" ? "removed" : record.claims.decision === "allow" ? "allow" : null))
        .filter((kind) => kind !== null);
      assert.deepEqual(order, ["removed", "allow"]);
    } finally {
      await shut();
      rmSync(body.stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D34 verify does not count an approval or a halt a passkey signed after the ledger recorded its removal", async () => {
    const phone = mintSoftwarePasskey();
    const spare = mintSoftwarePasskey();
    const body = await openBody(phone);
    saveCredential(body.stateDir, { id: spare.id, publicKey: isoBase64URL.fromBuffer(spare.publicKeyCose.slice()), counter: 0, sub: "operator-1" });
    let open = true;
    const shut = async () => {
      if (!open) return;
      open = false;
      await new Promise<void>((resolve) => body.server.close(() => resolve()));
    };
    try {
      // Signed while the passkey was in use: an approval for the call already held.
      await hold(body, "door-d34");
      const phoneToken = (await signIn(body.doorPort, phone)).body.token as string;
      const [row] = await waitingAt(body.doorPort, phoneToken);
      const approval = await approvalAssertion(body.doorPort, phoneToken, phone, row!.ref);
      const gone = await quiet(() => runOperator(["operator", "remove", "--state", body.stateDir, "--id", phone.id]));
      assert.equal(gone.code, 0, gone.err);
      await hold(body, "door-d34-sync");
      assert.ok(decisionsIn(body.stateDir).some((record) => record.claims.reasonCode === "passkey-removed"));

      // What a body would write if the removal landed between its signature check
      // and its ledger write: the same signature objects the gates return.
      const { challenge, prev } = nextControlChallenge(body.stateDir, "halt");
      const halt = assertWithSoftwarePasskey(phone, { challenge, rpID: RP_ID, origin: DOOR_ORIGIN, counter: 7 });
      haltBody(body.stateDir, "operator-1", "http", Date.now(), {
        credentialId: phone.id,
        sub: "operator-1",
        authenticatorData: halt.response.authenticatorData,
        clientDataJSON: halt.response.clientDataJSON,
        signature: halt.response.signature,
        rpId: RP_ID,
        prev,
      });
      // A second halt writes no line (the body is already halted) and copies the history into the ledger.
      const spareToken = (await signIn(body.doorPort, spare)).body.token as string;
      const again = await call(body.doorPort, "POST", "/api/halt", { token: spareToken, body: {} });
      assert.equal(again.status, 200, JSON.stringify(again.body));
      assert.ok(decisionsIn(body.stateDir).some((record) => record.claims.subject === "verax.halt"));
      // The passkey still in use resumes, signed, so the approval below is not refused for a halt.
      const resumeChallenge = await call(body.doorPort, "GET", "/api/resume/challenge", { token: spareToken });
      assert.equal(resumeChallenge.status, 200);
      const resumeAssertion = assertWithSoftwarePasskey(spare, {
        challenge: resumeChallenge.body.challenge as string,
        rpID: RP_ID,
        origin: DOOR_ORIGIN,
      });
      const resumed = await call(body.doorPort, "POST", "/api/resume", { token: spareToken, body: { assertion: resumeAssertion } });
      assert.equal(resumed.status, 200, JSON.stringify(resumed.body));
      await shut();

      const defer = decisionsIn(body.stateDir).find((record) => record.claims.ref === row!.ref && record.claims.decision === "defer")!;
      const ledger = new FileLedger(body.stateDir);
      try {
        const outcome = await approvePending({
          ledger,
          recordSigner: loadOrCreateSigners(body.stateDir).recordSigner,
          now: () => Date.now(),
          nonce: () => crypto.randomUUID(),
          ref: row!.ref,
          approverId: "operator-1",
          via: "http",
          policyHash: defer.claims.policyHash,
          approvals: approvalsLogFor(ledger),
          signature: {
            credentialId: phone.id,
            sub: "operator-1",
            authenticatorData: approval.response.authenticatorData,
            clientDataJSON: approval.response.clientDataJSON,
            signature: approval.response.signature,
            deferRecordHash: decisionRecordHash(defer),
            rpId: RP_ID,
          },
        });
        assert.equal(outcome.ok, true, JSON.stringify(outcome));
      } finally {
        ledger.close();
      }

      // The chain is whole: only the order of the removal and the signatures speaks.
      const chain = await verifyLedger(body.stateDir);
      assert.equal(chain.ok, true, chain.problems.join("\n"));
      const approvals = await verifyApprovalSignatures(body.stateDir);
      assert.equal(approvals.signedVerified, 0, approvals.line);
      assert.equal(approvals.ok, false, approvals.line);
      assert.match(approvals.line, /signed-after-removal 1/);
      const controls = await verifyControlSignatures(body.stateDir);
      assert.equal(controls.ok, false, controls.line);
      assert.match(controls.line, /signed-after-removal 1/);
      // And `verax verify` says so: the whole result is not verified.
      const printed: string[] = [];
      const code = await runVerify([body.stateDir], (s) => printed.push(s));
      const out = printed.join("\n");
      assert.notEqual(code, 0, out);
      assert.match(out, /signed-after-removal 1/);
      assert.match(out, /\nNOT VERIFIED$/);
    } finally {
      await shut();
      rmSync(body.stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D12 the origin is a name over HTTPS, and the door binds loopback", () => {
    const ok = readOperatorDoor({ VERAX_OPERATOR_DOOR: "https://approve.example.com" });
    assert.deepEqual(ok, {
      ok: true,
      value: { origin: "https://approve.example.com", rpID: "approve.example.com", bindHost: "127.0.0.1", bindPort: 8788 },
    });
    assert.deepEqual(readOperatorDoor({}), { ok: true, value: null });
    assert.equal(readOperatorDoor({ VERAX_OPERATOR_DOOR: "http://localhost:4174" }).ok, true);
    for (const bad of [
      "http://approve.example.com",
      "https://192.0.2.7",
      "https://[::1]",
      "https://approve.example.com/door",
      "https://approve.example.com/",
      "approve.example.com",
    ]) {
      assert.equal(readOperatorDoor({ VERAX_OPERATOR_DOOR: bad }).ok, false, bad);
    }
    assert.equal(
      readOperatorDoor({ VERAX_OPERATOR_DOOR: "https://approve.example.com", VERAX_OPERATOR_BIND: "0.0.0.0:8788" }).ok,
      false,
    );
  });
});
