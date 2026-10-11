// A stand-in OIDC issuer for a local end-to-end run. NOT FOR PRODUCTION and not
// an authorization server: it signs whatever client_credentials request carries
// the shared secret, and its signing key lives only as long as the process.
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const ISSUER = process.env.IDP_ISSUER;
const SECRET_FILE = process.env.IDP_CLIENT_SECRET_FILE;
if (!ISSUER || !SECRET_FILE) {
  process.stderr.write("IDP_ISSUER and IDP_CLIENT_SECRET_FILE are required\n");
  process.exit(78);
}
const secret = readFileSync(SECRET_FILE, "utf8").trim();
const { publicKey, privateKey } = await generateKeyPair("ES256");
const jwk = { ...(await exportJWK(publicKey)), kid: "idp-1", alg: "ES256", use: "sig" };

function send(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text) });
  res.end(text);
}

createServer((req, res) => {
  const url = new URL(req.url ?? "/", ISSUER);
  if (req.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
    send(res, 200, { issuer: ISSUER, jwks_uri: `${ISSUER}/jwks`, token_endpoint: `${ISSUER}/token` });
    return;
  }
  if (req.method === "GET" && url.pathname === "/jwks") {
    send(res, 200, { keys: [jwk] });
    return;
  }
  if (req.method === "POST" && url.pathname === "/token") {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
      if (form.get("grant_type") !== "client_credentials" || form.get("client_secret") !== secret) {
        send(res, 401, { error: "invalid_client" });
        return;
      }
      const sub = form.get("client_id") ?? "agent";
      const token = await new SignJWT({ scope: form.get("scope") ?? "" })
        .setProtectedHeader({ alg: "ES256", kid: "idp-1" })
        .setIssuer(ISSUER)
        .setAudience(form.get("audience") ?? "")
        .setSubject(sub)
        .setJti(randomUUID())
        .setIssuedAt()
        .setExpirationTime("10m")
        .sign(privateKey);
      send(res, 200, { access_token: token, token_type: "Bearer", expires_in: 600 });
    });
    return;
  }
  send(res, 404, { error: "not-found" });
}).listen(9000, "0.0.0.0", () => process.stderr.write(`idp listening as ${ISSUER}\n`));
