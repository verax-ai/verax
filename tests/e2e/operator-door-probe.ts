/**
 * Run by the install workflow against a body `verax install --operator-door`
 * set up, as the account that ran the install's shell, not the service's.
 *
 *   operator-door-probe.ts <origin> shut
 *     the door is up and serves its page, takes no made-up pairing code, and is shut past
 *     enrolment while nobody is enrolled.
 *   operator-door-probe.ts <origin> enrol <code>
 *     a code an elevated `verax operator enroll` printed enrols a passkey,
 *     which then signs in and reads what is waiting. This is the proof that
 *     the service account can read, count and spend a pairing file an
 *     administrator wrote.
 *
 * The origin is `http://localhost:<port>` and the door listens on that port.
 */
import { request } from "node:http";

import { assertWithSoftwarePasskey, mintSoftwarePasskey, registerWithSoftwarePasskey } from "../software-passkey.ts";

const [originArg = "", phase = "", code = ""] = process.argv.slice(2);
const origin = new URL(originArg).origin;
const port = Number(new URL(origin).port);
const rpID = new URL(origin).hostname;

type Answer = { status: number; body: Record<string, unknown> };

/** `node:http` to the loopback address the door binds, under the door's own name. */
function call(method: string, path: string, opts: { body?: unknown; token?: string } = {}): Promise<Answer> {
  const text = opts.body === undefined ? "" : JSON.stringify(opts.body);
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port,
        method,
        path,
        headers: {
          host: new URL(origin).host,
          ...(method === "POST" ? { origin } : {}),
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
          resolve({ status: res.statusCode ?? 0, body });
        });
      },
    );
    req.once("error", reject);
    req.end(text);
  });
}

function expect(what: string, got: Answer, status: number, error?: string): void {
  const ok = got.status === status && (error === undefined || got.body.error === error);
  if (ok) {
    process.stdout.write(`ok   ${what}: ${got.status}${error ? ` ${error}` : ""}\n`);
    return;
  }
  // The body of a refusal names no secret: a status and an error word.
  process.stderr.write(`FAIL ${what}: wanted ${status}${error ? ` ${error}` : ""}, got ${got.status} ${JSON.stringify(got.body)}\n`);
  process.exit(1);
}

if (phase === "shut") {
  // The screen that takes the code is served before anyone is enrolled.
  expect("the page", await call("GET", "/"), 200);
  expect("a made-up code", await call("POST", "/api/enroll/options", { body: { code: "00000000" } }), 403, "pairing-refused");
  expect("sign-in with nobody enrolled", await call("POST", "/api/signin/options"), 403, "no-operator");
} else if (phase === "enrol" && /^\d{8}$/.test(code)) {
  const passkey = mintSoftwarePasskey();
  const options = await call("POST", "/api/enroll/options", { body: { code } });
  expect("the code from the machine", options, 200);
  const response = registerWithSoftwarePasskey(passkey, { challenge: String(options.body.challenge), rpID, origin });
  expect("enrolment", await call("POST", "/api/enroll", { body: { code, response } }), 200);
  expect("the same code again", await call("POST", "/api/enroll/options", { body: { code } }), 403, "pairing-refused");
  const signin = await call("POST", "/api/signin/options");
  expect("sign-in options", signin, 200);
  const assertion = assertWithSoftwarePasskey(passkey, { challenge: String(signin.body.challenge), rpID, origin });
  const session = await call("POST", "/api/signin", { body: { assertion } });
  expect("sign-in", session, 200);
  const waiting = await call("GET", "/api/waiting", { token: String(session.body.token) });
  expect("the waiting list", waiting, 200);
  if (!Array.isArray(waiting.body.waiting)) {
    process.stderr.write("FAIL the waiting list is not a list\n");
    process.exit(1);
  }
} else {
  process.stderr.write("operator-door-probe.ts <origin> shut | enrol <8-digit code>\n");
  process.exit(64);
}
