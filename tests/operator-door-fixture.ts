/**
 * A body with the operator door on, as `verax install --operator-door` sets
 * one up, and a call held in it for an operator. Shared by the door's tests.
 */
import { strict as assert } from "node:assert";
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

import type { OperatorDoorConfig } from "../packages/body/src/config.ts";
import { saveCredential } from "../packages/body/src/operator-credentials.ts";
import { listen, operatorDoorOf } from "../packages/body/src/server.ts";
import type { SoftwarePasskey } from "./software-passkey.ts";

// The door's name is what the operator's proxy answers for. The port the door
// itself listens on is another matter, so the two differ here as they would there.
export const DOOR_ORIGIN = "http://localhost:4174";
export const DOOR_HOST = "localhost:4174";
export const RP_ID = "localhost";
export const ISSUER = "https://issuer.local.test";
export const AUDIENCE = "http://127.0.0.1/verax-operator-door";

export function approvePolicyFile(dir: string): string {
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
        {
          id: "spend-approve",
          tool: "spend",
          requires: ["verax:pay"],
          mode: "approve",
          text: "A payment is held for an operator.",
          spend: { maxAmountMinor: 500_000, currency: "USD", payees: ["sample-merchant"], dailyMaxMinor: 1_000_000 },
        },
      ],
    }),
    "utf8",
  );
  return path;
}

export type Body = {
  stateDir: string;
  main: string;
  doorPort: number;
  server: Server;
  /** A token the local key signs, as an installed body's agent token is. */
  local: (scope: string, sub?: string) => Promise<string>;
  close: () => Promise<void>;
};

/**
 * A body as `verax install` sets one up: local mode, the door on. `door` is
 * false for a body without one, or the door's own settings for a test that
 * needs the name and the port to agree, as a browser does.
 */
export async function openBody(passkey: SoftwarePasskey | null, door: boolean | OperatorDoorConfig = true): Promise<Body> {
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
  let server: Server;
  try {
    server = await listen({
      issuer: ISSUER,
      jwksUrl: "",
      jwksFile,
      audience: AUDIENCE,
      stateDir,
      bindHost: "127.0.0.1",
      bindPort: 0,
      policyFile: approvePolicyFile(stateDir),
      tlsTerminated: false,
      operatorDoor:
        door === true ? { origin: DOOR_ORIGIN, rpID: RP_ID, bindHost: "127.0.0.1", bindPort: 0 } : door === false ? null : door,
    });
  } catch (err) {
    rmSync(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    throw err;
  }
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

/** A tool call the policy holds for the operator. */
export async function holdTool(body: Body, scope: string, name: string, args: Record<string, unknown>): Promise<void> {
  const res = await fetch(`${body.main}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${await body.local(scope)}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
  assert.equal(res.status, 200);
  assert.match(await res.text(), /deferred:approval-required/);
}

/** An agent's write, held for the operator. */
export async function hold(body: Body, id: string): Promise<void> {
  await holdTool(body, "verax:memory", "memory.put", {
    id,
    body: { t: 1 },
    source: { uri: "file://t", retrievedAtMs: 1 },
    validUntilMs: Date.now() + 60_000,
  });
}

/** An agent's payment, held for the operator. */
export async function holdSpend(
  body: Body,
  spend: { amountMinor: number; currency: string; payee: string; reference: string },
): Promise<void> {
  await holdTool(body, "verax:pay", "spend", spend);
}
