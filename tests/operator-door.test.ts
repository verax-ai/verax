import { strict as assert } from "node:assert";
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request, type Server } from "node:http";
import { connect, createServer as createNetServer, type AddressInfo, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

import { verifyApprovalSignatures } from "../packages/body/src/approval-signature.ts";
import { readOperatorDoor, type OperatorDoorConfig } from "../packages/body/src/config.ts";
import { stateOwnerToBecome } from "../packages/body/src/operator-cli.ts";
import { credentialsPath, readCredentials, saveCredential } from "../packages/body/src/operator-credentials.ts";
import {
  DOOR_CHALLENGE_TTL_MS,
  DOOR_SESSION_TTL_MS,
  doorHostAllowed,
  openOperatorDoor,
} from "../packages/body/src/operator-door.ts";
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
  assertWithSoftwarePasskey,
  attestedAuthData,
  mintSoftwarePasskey,
  registerWithSoftwarePasskey,
  registrationFrom,
  type SoftwarePasskey,
} from "./software-passkey.ts";

// The door's name is what the operator's proxy answers for. The port the door
// itself listens on is another matter, so the two differ here as they would there.
const DOOR_ORIGIN = "http://localhost:4174";
const DOOR_HOST = "localhost:4174";
const RP_ID = "localhost";
const ISSUER = "https://issuer.local.test";
const AUDIENCE = "http://127.0.0.1/verax-operator-door";

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

function approvePolicyFile(dir: string): string {
  const path = join(dir, "approve-policy.json");
  writeFileSync(
    path,
    JSON.stringify({
      version: 1,
      default: "deny",
      approvalTtlMs: 86_400_000,
      rules: [
        {
          id: "put-approve",
          tool: "memory.put",
          requires: ["verax:memory"],
          mode: "approve",
          text: "Writes need operator approval.",
        },
      ],
    }),
    "utf8",
  );
  return path;
}

type Body = {
  stateDir: string;
  main: string;
  doorPort: number;
  server: Server;
  /** A token the local key signs, as an installed body's agent token is. */
  local: (scope: string, sub?: string) => Promise<string>;
  close: () => Promise<void>;
};

/** A body as `verax install` sets one up: local mode, the door on. */
async function openBody(passkey: SoftwarePasskey | null, door = true): Promise<Body> {
  const stateDir = mkdtempSync(join(tmpdir(), "verax-operator-door-"));
  if (passkey) {
    saveCredential(stateDir, {
      id: passkey.id,
      publicKey: isoBase64URL.fromBuffer(passkey.publicKeyCose.slice()),
      counter: 0,
      sub: "operator-1",
    });
  }
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const jwksFile = join(stateDir, "jwks.json");
  writeFileSync(jwksFile, JSON.stringify({ keys: [{ ...(await exportJWK(publicKey)), kid: "local-1", alg: "ES256", use: "sig" }] }));
  const server = await listen({
    issuer: ISSUER,
    jwksUrl: "",
    jwksFile,
    audience: AUDIENCE,
    stateDir,
    bindHost: "127.0.0.1",
    bindPort: 0,
    policyFile: approvePolicyFile(stateDir),
    tlsTerminated: false,
    operatorDoor: door ? { origin: DOOR_ORIGIN, rpID: RP_ID, bindHost: "127.0.0.1", bindPort: 0 } : null,
  });
  const doorServer = operatorDoorOf(server);
  return {
    stateDir,
    main: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    doorPort: doorServer ? (doorServer.address() as AddressInfo).port : 0,
    server,
    local: (scope, sub = "agent-1") =>
      new SignJWT({ scope })
        .setProtectedHeader({ alg: "ES256", kid: "local-1" })
        .setIssuer(ISSUER)
        .setAudience(AUDIENCE)
        .setSubject(sub)
        .setIssuedAt()
        .setExpirationTime("5m")
        .setJti(randomUUID())
        .sign(privateKey),
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    },
  };
}

async function hold(body: Body, id: string): Promise<void> {
  const res = await fetch(`${body.main}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${await body.local("verax:memory")}`,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "memory.put",
        arguments: { id, body: { t: 1 }, source: { uri: "file://t", retrievedAtMs: 1 }, validUntilMs: Date.now() + 60_000 },
      },
    }),
  });
  assert.equal(res.status, 200);
  assert.match(await res.text(), /deferred:approval-required/);
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
          ["GET", "/"],
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
        const socket = connect(port, "127.0.0.1");
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
      // Dropped means hung up on, not only no longer counted.
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

  it("D23 a door whose port is taken stops the start and leaves the state for the next one", async () => {
    const squatter = createNetServer();
    await new Promise<void>((resolve) => squatter.listen(0, "127.0.0.1", () => resolve()));
    const taken = (squatter.address() as AddressInfo).port;
    const stateDir = mkdtempSync(join(tmpdir(), "verax-operator-door-taken-"));
    const { publicKey } = await generateKeyPair("ES256", { extractable: true });
    const jwksFile = join(stateDir, "jwks.json");
    writeFileSync(jwksFile, JSON.stringify({ keys: [{ ...(await exportJWK(publicKey)), kid: "local-1", alg: "ES256", use: "sig" }] }));
    const start = (doorPort: number) =>
      listen({
        issuer: ISSUER,
        jwksUrl: "",
        jwksFile,
        audience: AUDIENCE,
        stateDir,
        bindHost: "127.0.0.1",
        bindPort: 0,
        policyFile: approvePolicyFile(stateDir),
        tlsTerminated: false,
        operatorDoor: { origin: DOOR_ORIGIN, rpID: RP_ID, bindHost: "127.0.0.1", bindPort: doorPort },
      });
    try {
      await assert.rejects(start(taken), /EADDRINUSE/);
      // Nothing of the refused start is left holding the ledger: the same state starts once the port is free.
      const server = await start(0);
      assert.notEqual(operatorDoorOf(server), null);
      await new Promise<void>((resolve) => server.close(() => resolve()));
    } finally {
      await new Promise<void>((resolve) => squatter.close(() => resolve()));
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it("D24 root asks for a pairing code as the owner of the state directory, and as nobody else", () => {
    const service = { uid: 997, gid: 995, isDirectory: true };
    assert.deepEqual(stateOwnerToBecome("linux", 0, service), { uid: 997, gid: 995 });
    assert.deepEqual(stateOwnerToBecome("darwin", 0, service), { uid: 997, gid: 995 });
    // Not root, so there is nothing to give up; and nothing is given to root's own directory.
    assert.equal(stateOwnerToBecome("linux", 1000, service), null);
    assert.equal(stateOwnerToBecome("linux", 0, { ...service, uid: 0 }), null);
    // A file or a link where the directory should be names no owner to become.
    assert.equal(stateOwnerToBecome("linux", 0, { ...service, isDirectory: false }), null);
    assert.equal(stateOwnerToBecome("linux", 0, null), null);
    assert.equal(stateOwnerToBecome("win32", 0, service), null);
    assert.equal(stateOwnerToBecome("win32", undefined, service), null);
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
