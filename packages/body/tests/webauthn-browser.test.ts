/**
 * One assertion from Chromium's virtual authenticator, checked by the body's
 * own verifier. The page is opened as localhost: that name is a secure context
 * and it is the RP ID. The socket is 127.0.0.1; Chromium is told to resolve
 * localhost there, so the origin the verifier sees is still the page origin.
 */
import { strict as assert } from "node:assert";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import { after, describe, it } from "node:test";
import { isoCBOR } from "@simplewebauthn/server/helpers";

import { killStragglers, launchBrowser, trackStraggler } from "../../../scripts/test-preview.ts";
import { verifyAssertion } from "../src/webauthn-verify.ts";

const PAGE_HTML = `<!doctype html>
<meta charset="utf-8">
<title>verax-approve</title>
<script>
  function bytesFromBase64Url(value) {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/");
    const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
    const binary = atob(padded + pad);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }
  function bytesToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).split("+").join("-").split("/").join("_").replace(/=+$/g, "");
  }
  window.signChallenge = async (challenge, credentialId) => {
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: bytesFromBase64Url(challenge),
        rpId: "localhost",
        allowCredentials: [{ type: "public-key", id: bytesFromBase64Url(credentialId) }],
        userVerification: "required",
      },
    });
    if (!cred) throw new Error("no-credential");
    const response = cred.response;
    return {
      id: bytesToBase64Url(cred.rawId),
      rawId: bytesToBase64Url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToBase64Url(response.clientDataJSON),
        authenticatorData: bytesToBase64Url(response.authenticatorData),
        signature: bytesToBase64Url(response.signature),
      },
      clientExtensionResults: cred.getClientExtensionResults(),
    };
  };
</script>
`;

after(killStragglers);

function listenOnLoopback(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("webauthn-page-port"));
        return;
      }
      resolve(addr.port);
    });
  });
}

function coseP256(x: Uint8Array, y: Uint8Array): string {
  const map = new Map<number, number | Uint8Array>();
  map.set(1, 2);
  map.set(3, -7);
  map.set(-1, 1);
  map.set(-2, x);
  map.set(-3, y);
  return Buffer.from(isoCBOR.encode(map)).toString("base64url");
}

function p256Material(): { privateKeyB64: string; publicKeyCose: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
  if (typeof pkcs8 === "string") throw new Error("pkcs8-der");
  const jwk = publicKey.export({ format: "jwk" });
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") throw new Error("p256-jwk");
  return {
    privateKeyB64: Buffer.from(pkcs8).toString("base64"),
    publicKeyCose: coseP256(Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")),
  };
}

type BrowserAssertion = {
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
  };
};

function asAssertion(value: unknown): BrowserAssertion {
  if (!value || typeof value !== "object") throw new Error("assertion-shape");
  const row = value as BrowserAssertion;
  if (typeof row.response?.clientDataJSON !== "string") throw new Error("assertion-shape");
  if (typeof row.response.authenticatorData !== "string") throw new Error("assertion-shape");
  if (typeof row.response.signature !== "string") throw new Error("assertion-shape");
  return row;
}

describe("chromium virtual authenticator", () => {
  it("verifies an assertion from the virtual authenticator and rejects a different challenge", { timeout: 120_000 }, async () => {
    const material = p256Material();
    const credentialId = randomBytes(16);
    const challenge = randomBytes(32);
    const challengeB64 = challenge.toString("base64url");
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      res.end(PAGE_HTML);
    });
    const stopServer = trackStraggler({
      kill: () => {
        server.close();
      },
    });
    let stopBrowser: (() => void) | undefined;
    try {
      const port = await listenOnLoopback(server);
      const origin = `http://localhost:${port}`;
      const launched = await launchBrowser(["--host-resolver-rules=MAP localhost 127.0.0.1"]);
      stopBrowser = launched.stopBrowser;
      const context = await launched.browser.newContext();
      const page = await context.newPage();
      const client = await context.newCDPSession(page);
      await client.send("WebAuthn.enable");
      const added = await client.send("WebAuthn.addVirtualAuthenticator", {
        options: {
          protocol: "ctap2",
          transport: "internal",
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          // Default is already immediate presence. Named so a later default
          // cannot leave credentials.get waiting until the test cap.
          automaticPresenceSimulation: true,
        },
      });
      await client.send("WebAuthn.addCredential", {
        authenticatorId: added.authenticatorId,
        credential: {
          credentialId: credentialId.toString("base64"),
          isResidentCredential: true,
          rpId: "localhost",
          privateKey: material.privateKeyB64,
          userHandle: Buffer.from("verax-operator").toString("base64"),
          signCount: 0,
        },
      });
      await page.goto(`${origin}/`, { waitUntil: "domcontentloaded" });
      const assertion = asAssertion(
        await page.evaluate(
          async (input: { challenge: string; credentialId: string }) => {
            const sign = (
              globalThis as unknown as {
                signChallenge: (challenge: string, credentialId: string) => Promise<unknown>;
              }
            ).signChallenge;
            return sign(input.challenge, input.credentialId);
          },
          { challenge: challengeB64, credentialId: credentialId.toString("base64url") },
        ),
      );
      const verdict = verifyAssertion({
        response: assertion,
        expectedChallenge: challengeB64,
        expectedOrigins: [origin],
        rpId: "localhost",
        publicKeyCose: material.publicKeyCose,
      });
      assert.equal(verdict.ok, true, JSON.stringify(verdict));
      const wrong = verifyAssertion({
        response: assertion,
        expectedChallenge: "bm90LXRoZS1jaGFsbGVuZ2U",
        expectedOrigins: [origin],
        rpId: "localhost",
        publicKeyCose: material.publicKeyCose,
      });
      assert.deepEqual(wrong, { ok: false, reason: "challenge" });
    } finally {
      stopBrowser?.();
      stopServer();
    }
  });
});
