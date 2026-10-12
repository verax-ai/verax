/**
 * The operator door: a second listener that serves only what an operator
 * needs away from the machine. Sign in with a passkey, see what is waiting,
 * approve one request, stop and resume the body. It never serves `/mcp`, the
 * ledger or the inventory, and it takes no token the main listener takes.
 *
 * A passkey is enrolled through the door only with a pairing code that
 * `verax operator enroll` printed at the machine. Enrolling opens no session
 * and approves nothing.
 *
 * A session is a random value this process remembers and nothing else: there
 * is no key on disk that could sign one, and a restart ends them all. The
 * session lets the operator look. An approval still needs a passkey
 * assertion made for that one request.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import { loadApprovalsFromDir } from "@verax-ai/proxy";

import { asAssertion } from "./approval-signature.ts";
import { readBearer } from "./auth.ts";
import type { OperatorDoorConfig } from "./config.ts";
import { contentLengthOverLimit, readJsonBody, send } from "./http-io.ts";
import {
  DEFAULT_OPERATOR_SUB,
  findCredential,
  hasRegisteredOperator,
  readCredentials,
  saveCredential,
  updateCounter,
} from "./operator-credentials.ts";
import { handleApprove, handleApproveChallenge, handleControl, type OperatorRequest } from "./operator-handlers.ts";
import { checkPairing, consumePairing } from "./operator-pairing.ts";
import { COSE_ALGORITHMS, verifyAssertion, verifyRegistration, type PostedRegistration } from "./webauthn-verify.ts";
import type { createBodyServices } from "./wiring.ts";

export const DOOR_SESSION_TTL_MS = 10 * 60_000;
export const DOOR_CHALLENGE_TTL_MS = 2 * 60_000;
const MAX_SESSIONS = 8;
const SIGNIN_BODY_BYTES = 16 * 1024;
const SIGNIN_BODY_MS = 5_000;
const MAX_SIGNINS_IN_FLIGHT = 32;
const REQUEST_TIMEOUT_MS = 30_000;
const HEADERS_TIMEOUT_MS = 20_000;
const SESSION_SCOPES: ReadonlySet<string> = new Set(["verax:approve", "verax:audit"]);

type Session = { sub: string; credentialId: string; expiresAtMs: number };

/** Method and path, exactly. Anything else on the door is not found. */
const ROUTES = new Set([
  "POST /api/enroll/options",
  "POST /api/enroll",
  "POST /api/signin/options",
  "POST /api/signin",
  "POST /api/signout",
  "GET /api/waiting",
  "GET /api/approve/challenge",
  "POST /api/approve",
  "GET /api/halt",
  "POST /api/halt",
  "GET /api/halt/challenge",
  "POST /api/resume",
  "GET /api/resume/challenge",
]);

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/**
 * The door answers for its own name, and for its own loopback address so the
 * operator's proxy may forward either. A page on another name that resolves
 * to this machine carries that other name here and is refused.
 */
export function doorHostAllowed(hostHeader: string | undefined, door: OperatorDoorConfig, listenPort: number): boolean {
  const raw = (hostHeader ?? "").trim().toLowerCase();
  if (raw === "") return false;
  if (raw === new URL(door.origin).host) return true;
  return raw === `127.0.0.1:${listenPort}` || raw === `localhost:${listenPort}` || raw === `[::1]:${listenPort}`;
}

/** One operator, one name on the device, however many times it enrolls. */
function operatorUserId(sub: string): string {
  return createHash("sha256").update(`verax-operator:${sub}`, "utf8").digest("base64url");
}

function sessionKey(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

function challengeInClientData(clientDataJSON: string): string | null {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(clientDataJSON, "base64url").toString("utf8"));
    if (!parsed || typeof parsed !== "object") return null;
    const challenge = (parsed as { challenge?: unknown }).challenge;
    return typeof challenge === "string" && challenge !== "" ? challenge : null;
  } catch {
    return null;
  }
}

/** The answer goes out, then the rest of what was being sent is not waited for. */
function refuseTooLarge(req: IncomingMessage, res: ServerResponse): void {
  res.once("finish", () => req.destroy());
  send(res, 413, { error: "payload-too-large" }, { connection: "close" });
}

/** Oldest out first: a Map keeps insertion order. */
function capped<K, V>(map: Map<K, V>, max: number): void {
  while (map.size > max) {
    const oldest = map.keys().next();
    if (oldest.done) return;
    map.delete(oldest.value);
  }
}

export async function openOperatorDoor(opts: {
  door: OperatorDoorConfig;
  stateDir: string;
  services: ReturnType<typeof createBodyServices>;
  now?: () => number;
  /** How long an unauthenticated sign-in body may take to arrive. */
  signinBodyMs?: number;
}): Promise<Server> {
  const { door, stateDir, services } = opts;
  const now = opts.now ?? (() => Date.now());
  const sessions = new Map<string, Session>();
  const signinBodyMs = opts.signinBodyMs ?? SIGNIN_BODY_MS;
  let signinsInFlight = 0;
  // A challenge is its own expiry and a random part under a MAC this process
  // keys. Nothing is stored when one is handed out, so a caller who asks for
  // a thousand takes nothing from the operator who asked for one. Sign-in and
  // enrolment have a key each: a challenge made for one is not one for the other.
  const signinKey = randomBytes(32);
  const enrollKey = randomBytes(32);
  const spent = new Map<string, number>();
  const mintChallenge = (key: Buffer): string => {
    const head = Buffer.alloc(24);
    head.writeBigUInt64BE(BigInt(now() + DOOR_CHALLENGE_TTL_MS), 0);
    randomBytes(16).copy(head, 8);
    return Buffer.concat([head, createHmac("sha256", key).update(head).digest()]).toString("base64url");
  };
  /** When a challenge this door made runs out, or null for one it did not make, one that ran out, or one already used. */
  const challengeExpiry = (key: Buffer, challenge: string): number | null => {
    const bytes = Buffer.from(challenge, "base64url");
    if (bytes.length !== 56 || bytes.toString("base64url") !== challenge) return null;
    const head = bytes.subarray(0, 24);
    const mac = createHmac("sha256", key).update(head).digest();
    if (!timingSafeEqual(mac, bytes.subarray(24))) return null;
    const expiresAtMs = Number(head.readBigUInt64BE(0));
    if (now() >= expiresAtMs || spent.has(challenge)) return null;
    return expiresAtMs;
  };
  /** Good once. Only a verified answer gets a challenge onto this list, so a stranger cannot fill it. */
  const spend = (challenge: string, expiresAtMs: number): void => {
    for (const [known, until] of spent) if (now() >= until) spent.delete(known);
    spent.set(challenge, expiresAtMs);
  };
  /**
   * A body from a caller who has proved nothing yet: small, few are read at
   * once, and one that dawdles is dropped. Null when the answer has gone out.
   */
  const readUnvouched = async (req: IncomingMessage, res: ServerResponse): Promise<{ value: unknown } | null> => {
    const declared = Number(first(req.headers["content-length"]) ?? "0");
    if (Number.isFinite(declared) && declared > SIGNIN_BODY_BYTES) {
      refuseTooLarge(req, res);
      return null;
    }
    if (signinsInFlight >= MAX_SIGNINS_IN_FLIGHT) {
      send(res, 503, { error: "busy" }, { "retry-after": "5" });
      req.resume();
      return null;
    }
    signinsInFlight += 1;
    const dawdling = setTimeout(() => req.destroy(), signinBodyMs);
    let parsed: Awaited<ReturnType<typeof readJsonBody>>;
    try {
      parsed = await readJsonBody(req, SIGNIN_BODY_BYTES);
    } finally {
      clearTimeout(dawdling);
      signinsInFlight -= 1;
    }
    if (!parsed.ok) {
      if ("tooLarge" in parsed) {
        refuseTooLarge(req, res);
        return null;
      }
      send(res, 400, { error: "bad-body" });
      return null;
    }
    return { value: parsed.value };
  };
  // The handlers read the relying party from an environment. The door's is
  // its own origin, whatever the process environment says.
  const rpEnv: NodeJS.ProcessEnv = { VERAX_RP_ID: door.rpID, VERAX_RP_ORIGINS: door.origin };

  const liveSession = (token: string | null): Session | null => {
    if (!token) return null;
    const key = sessionKey(token);
    const row = sessions.get(key);
    if (!row) return null;
    // A credential taken off the machine ends the sessions it opened.
    if (now() >= row.expiresAtMs || !findCredential(stateDir, row.credentialId)) {
      sessions.delete(key);
      return null;
    }
    return row;
  };

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      // What the door says names payees and amounts; no cache keeps a copy.
      res.setHeader("cache-control", "no-store");
      const listenPort = (server.address() as AddressInfo).port;
      if (!doorHostAllowed(first(req.headers.host), door, listenPort)) {
        send(res, 400, { error: "host-not-allowed" });
        req.resume();
        return;
      }
      const origin = first(req.headers.origin);
      if (origin !== undefined && origin !== door.origin) {
        send(res, 403, { error: "origin-not-allowed" });
        req.resume();
        return;
      }
      const url = new URL(req.url ?? "/", door.origin);
      if (!ROUTES.has(`${req.method} ${url.pathname}`)) {
        send(res, 404, { error: "not-found" });
        req.resume();
        return;
      }
      // A browser names the origin on every POST. One that does not is not the door's page.
      if (req.method === "POST" && origin === undefined) {
        send(res, 403, { error: "origin-required" });
        req.resume();
        return;
      }
      if (req.method === "POST" && contentLengthOverLimit(req)) {
        send(res, 413, { error: "payload-too-large" });
        req.resume();
        return;
      }
      if (url.pathname === "/api/enroll/options" || url.pathname === "/api/enroll") {
        const read = await readUnvouched(req, res);
        if (!read) return;
        const posted =
          read.value && typeof read.value === "object" ? (read.value as { code?: unknown; response?: unknown }) : {};
        // Nothing is awaited from here to the answer. The count of wrong codes
        // is read and written in one turn, so callers who arrive together
        // still have five tries between them.
        const pairing = checkPairing(stateDir, typeof posted.code === "string" ? posted.code : "", now());
        if (!pairing.ok) {
          send(res, 403, { error: "pairing-refused", reason: pairing.reason });
          return;
        }
        if (url.pathname === "/api/enroll/options") {
          send(res, 200, {
            challenge: mintChallenge(enrollKey),
            rp: { id: door.rpID, name: "Verax" },
            user: {
              id: operatorUserId(DEFAULT_OPERATOR_SUB),
              name: DEFAULT_OPERATOR_SUB,
              displayName: DEFAULT_OPERATOR_SUB,
            },
            pubKeyCredParams: COSE_ALGORITHMS.map((alg) => ({ type: "public-key" as const, alg })),
            authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
            attestation: "none",
            excludeCredentials: readCredentials(stateDir).map((row) => ({ id: row.id, type: "public-key" as const })),
            timeout: DOOR_CHALLENGE_TTL_MS,
          });
          return;
        }
        // The caller holds the code, so the reason is theirs to read.
        const refuse = (reason: string): void => send(res, 403, { error: "enroll-refused", reason });
        const registration =
          posted.response && typeof posted.response === "object" ? (posted.response as PostedRegistration) : null;
        const clientData = registration?.response?.clientDataJSON;
        const made = typeof clientData === "string" ? challengeInClientData(clientData) : null;
        const madeUntilMs = made ? challengeExpiry(enrollKey, made) : null;
        if (!registration || !made || madeUntilMs === null) {
          refuse("challenge");
          return;
        }
        const enrolled = verifyRegistration({
          response: registration,
          expectedChallenge: made,
          expectedOrigins: [door.origin],
          rpId: door.rpID,
        });
        if (!enrolled.ok) {
          refuse(enrolled.reason);
          return;
        }
        if (findCredential(stateDir, enrolled.credentialId)) {
          refuse("already-enrolled");
          return;
        }
        spend(made, madeUntilMs);
        // The code goes first: if the write after it fails, the operator asks
        // for another code, and no code outlives an enrolment it paid for.
        consumePairing(stateDir);
        saveCredential(stateDir, {
          id: enrolled.credentialId,
          publicKey: enrolled.publicKeyCose,
          counter: enrolled.counter,
          sub: DEFAULT_OPERATOR_SUB,
        });
        send(res, 200, { enrolled: true, sub: DEFAULT_OPERATOR_SUB });
        return;
      }

      // With no operator enrolled an approval over HTTP needs no signature.
      // That path must not be reachable from here, so past enrolment the door stays shut.
      if (!hasRegisteredOperator(stateDir)) {
        send(res, 403, { error: "no-operator" });
        req.resume();
        return;
      }

      if (url.pathname === "/api/signin/options") {
        req.resume();
        send(res, 200, {
          challenge: mintChallenge(signinKey),
          rpId: door.rpID,
          allowCredentials: readCredentials(stateDir).map((row) => ({ id: row.id, type: "public-key" as const })),
          userVerification: "required",
          timeout: DOOR_CHALLENGE_TTL_MS,
        });
        return;
      }

      if (url.pathname === "/api/signin") {
        const read = await readUnvouched(req, res);
        if (!read) return;
        const assertion = asAssertion((read.value as { assertion?: unknown } | undefined)?.assertion);
        const challenge = assertion ? challengeInClientData(assertion.response.clientDataJSON) : null;
        const expiresAtMs = challenge ? challengeExpiry(signinKey, challenge) : null;
        const stored = assertion ? findCredential(stateDir, assertion.id) : null;
        if (!assertion || !challenge || expiresAtMs === null || !stored) {
          send(res, 403, { error: "signin-refused" });
          return;
        }
        const verified = verifyAssertion({
          response: assertion,
          expectedChallenge: challenge,
          expectedOrigins: [door.origin],
          rpId: door.rpID,
          publicKeyCose: stored.publicKey,
        });
        if (!verified.ok) {
          send(res, 403, { error: "signin-refused" });
          return;
        }
        spend(challenge, expiresAtMs);
        if (!updateCounter(stateDir, stored.id, verified.counter)) {
          send(res, 403, { error: "cloned-authenticator" });
          return;
        }
        const token = randomBytes(32).toString("base64url");
        const session: Session = { sub: stored.sub, credentialId: stored.id, expiresAtMs: now() + DOOR_SESSION_TTL_MS };
        sessions.set(sessionKey(token), session);
        capped(sessions, MAX_SESSIONS);
        send(res, 200, { token, sub: session.sub, expiresAtMs: session.expiresAtMs });
        return;
      }

      const token = readBearer(req.headers.authorization);
      const session = liveSession(token);
      if (!session) {
        send(res, 401, { error: "unauthorized" });
        req.resume();
        return;
      }

      if (url.pathname === "/api/signout") {
        req.resume();
        sessions.delete(sessionKey(token!));
        send(res, 200, { ok: true });
        return;
      }

      if (url.pathname === "/api/waiting") {
        const at = now();
        const waiting = loadApprovalsFromDir(stateDir)
          .filter((row) => row.status === "pending" && row.expiresAtMs > at)
          .map((row) => ({
            ref: row.ref,
            requestHash: row.requestHash,
            tool: row.subject,
            args: row.args,
            agent: row.brain,
            rule: row.ruleText,
            ...(row.createdAtMs !== undefined ? { createdAtMs: row.createdAtMs } : {}),
            expiresAtMs: row.expiresAtMs,
          }));
        send(res, 200, { waiting });
        return;
      }

      const operatorRequest: OperatorRequest = {
        req,
        res,
        url,
        stateDir,
        services,
        subject: session.sub,
        scopes: SESSION_SCOPES,
        refuseStale: async () => {
          if (liveSession(token)) return false;
          send(res, 401, { error: "unauthorized" });
          return true;
        },
        env: rpEnv,
      };
      if (url.pathname === "/api/approve/challenge") {
        await handleApproveChallenge(operatorRequest);
        return;
      }
      if (url.pathname === "/api/approve") {
        await handleApprove(operatorRequest);
        return;
      }
      await handleControl(operatorRequest, {
        resuming: url.pathname.startsWith("/api/resume"),
        challenge: url.pathname.endsWith("/challenge"),
      });
    } catch (err) {
      if (res.headersSent) return;
      if (err instanceof TypeError) {
        send(res, 400, { error: "bad-request" });
        return;
      }
      process.stderr.write(`verax-door: ${err instanceof Error ? err.message : "fault"}\n`);
      send(res, 500, { error: "fault" });
    }
  });
  server.requestTimeout = REQUEST_TIMEOUT_MS;
  server.headersTimeout = HEADERS_TIMEOUT_MS;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(door.bindPort, door.bindHost, () => resolve());
  });
  return server;
}
