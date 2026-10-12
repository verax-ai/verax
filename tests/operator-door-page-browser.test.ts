/**
 * The door's page in Chromium, against a body with the door on, with
 * Chromium's virtual authenticator as the operator's passkey. Nothing here
 * calls the door for the page: every enrolment, sign-in, approval, stop and
 * resume below is the page's own script, under the headers the door sends.
 *
 * A browser names its own origin on every POST and the door takes only its
 * own, so the door's name and the port it listens on are the same port here.
 */
import { strict as assert } from "node:assert";
import { randomInt } from "node:crypto";
import { rmSync } from "node:fs";
import { after, describe, it } from "node:test";

import type { Page } from "playwright";

import { verifyApprovalSignatures } from "../packages/body/src/approval-signature.ts";
import { verifyControlSignatures } from "../packages/body/src/control-signature.ts";
import { readCredentials } from "../packages/body/src/operator-credentials.ts";
import { beginPairing } from "../packages/body/src/operator-pairing.ts";
import { killStragglers, launchBrowser } from "../scripts/test-preview.ts";
import { holdSpend, holdTool, openBody, RP_ID, type Body } from "./operator-door-fixture.ts";
import { assertWithSoftwarePasskey, mintSoftwarePasskey, registerWithSoftwarePasskey } from "./software-passkey.ts";

after(killStragglers);

const SCREENS = ["loading", "enroll", "signin", "main"] as const;
// What an agent might put in an argument to get markup onto the operator's screen.
const MARKUP = `<img src=x onerror="document.title='written'"><script>document.title='written'</script>`;
// And what it might put there to turn a line around, break it in two, or hide in it.
const TRICK = "pay ‮ecalper‬ Rule: none​\u{E0001}";
const RTL = "אבג 100";

/** A body whose door answers for the port it listens on. A taken port is tried again elsewhere. */
async function openBodyOnOnePort(): Promise<{ body: Body; origin: string; port: number }> {
  let taken: unknown;
  for (let tries = 0; tries < 20; tries++) {
    const port = randomInt(20_000, 45_000);
    const origin = `http://localhost:${port}`;
    try {
      const body = await openBody(null, { origin, rpID: RP_ID, bindHost: "127.0.0.1", bindPort: port });
      return { body, origin, port };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EADDRINUSE") throw err;
      taken = err;
    }
  }
  throw taken;
}

const at = (page: Page, name: string) => page.locator(`[data-test="${name}"]`);

/** The named screen is up, and it is the only one. */
async function onScreen(page: Page, name: (typeof SCREENS)[number]): Promise<void> {
  await at(page, `screen-${name}`).waitFor({ state: "visible", timeout: 20_000 });
  for (const other of SCREENS) {
    if (other !== name) assert.equal(await at(page, `screen-${other}`).isVisible(), false, `${other} is up beside ${name}`);
  }
}

/** The page says so itself, by code. The wording is the page's own business. */
async function told(page: Page, kind: "ok" | "error", code: string): Promise<void> {
  try {
    await page
      .locator(`[data-test="notice"][data-kind="${kind}"][data-code="${code}"]`)
      .waitFor({ state: "visible", timeout: 20_000 });
  } catch {
    const notice = at(page, "notice");
    assert.fail(
      `wanted ${kind}/${code}, the page says ${await notice.getAttribute("data-kind")}/${await notice.getAttribute("data-code")}: ${await notice.textContent()}`,
    );
  }
}

describe("operator door page", () => {
  it(
    "P1 in a browser: a code enrolls a passkey, the passkey signs in, a held payment shows its payee and amount, each approval is signed, and stop, resume and a lost session all show",
    { timeout: 240_000 },
    async () => {
      const { body, origin, port } = await openBodyOnOnePort();
      let open = true;
      const shut = async () => {
        if (!open) return;
        open = false;
        await new Promise<void>((resolve) => body.server.close(() => resolve()));
      };
      let stopBrowser: (() => void) | undefined;
      try {
        const launched = await launchBrowser(["--host-resolver-rules=MAP localhost 127.0.0.1"]);
        stopBrowser = launched.stopBrowser;
        const context = await launched.browser.newContext();
        const page = await context.newPage();
        // A refused policy or a refused write of markup lands here. So does any fault in the script.
        const faults: string[] = [];
        page.on("pageerror", (err) => faults.push(`pageerror: ${err.message}`));
        page.on("console", (msg) => {
          // The browser logs every answer that is not a 2xx. Those are the door's, and they are asserted below.
          if (msg.type() === "error" && !msg.text().startsWith("Failed to load resource")) faults.push(`console: ${msg.text()}`);
        });
        const askedOf = new Set<string>();
        page.on("request", (req) => askedOf.add(new URL(req.url()).origin));

        const client = await context.newCDPSession(page);
        await client.send("WebAuthn.enable");
        await client.send("WebAuthn.addVirtualAuthenticator", {
          options: {
            protocol: "ctap2",
            transport: "internal",
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true,
          },
        });

        // Nobody is enrolled: the page comes up asking for a code, and there is no way round it to sign in.
        const landed = await page.goto(`${origin}/`, { waitUntil: "domcontentloaded" });
        assert.equal(landed?.status(), 200);
        assert.match(landed?.headers()["content-security-policy"] ?? "", /default-src 'none'/);
        await onScreen(page, "enroll");
        assert.equal(await at(page, "goto-signin").isVisible(), false);

        // A code nobody was given is refused, and a code of the wrong shape never leaves the page.
        await at(page, "enroll-code").fill("00000000");
        await at(page, "enroll-submit").click();
        await told(page, "error", "pairing-refused");
        await at(page, "enroll-code").fill("1234");
        await at(page, "enroll-submit").click();
        await told(page, "error", "code-format");
        assert.equal(readCredentials(body.stateDir).length, 0);

        // The code from the machine enrolls this browser's passkey. Enrolling signs nobody in.
        await at(page, "enroll-code").fill(beginPairing(body.stateDir).code);
        await at(page, "enroll-submit").click();
        await told(page, "ok", "enrolled");
        await onScreen(page, "signin");
        assert.equal(readCredentials(body.stateDir).length, 1);

        await at(page, "signin").click();
        await told(page, "ok", "signed-in");
        await onScreen(page, "main");
        assert.equal(await at(page, "session-sub").textContent(), "operator-1");
        assert.equal(await at(page, "halt-state").getAttribute("data-halted"), "false");
        assert.equal(await at(page, "waiting-count").textContent(), "0");
        assert.equal(await at(page, "waiting-empty").isVisible(), true);
        assert.equal(await at(page, "waiting-row").count(), 0);

        // An agent asks for a payment and for a write whose argument is markup. Both are held.
        await holdSpend(body, { amountMinor: 1250, currency: "USD", payee: "sample-merchant", reference: "inv-7" });
        await holdTool(body, "verax:memory", "memory.put", {
          id: "door-page-1",
          body: { note: MARKUP, trick: TRICK, rtl: RTL },
          source: { uri: "file://t", retrievedAtMs: 1 },
          validUntilMs: Date.now() + 60_000,
        });
        await at(page, "refresh").click();
        await at(page, "waiting-row").nth(1).waitFor({ state: "visible", timeout: 20_000 });
        assert.equal(await at(page, "waiting-count").textContent(), "2");
        assert.equal(await at(page, "waiting-empty").isVisible(), false);

        const payment = at(page, "waiting-row").filter({ has: at(page, "row-payee") });
        assert.equal(await payment.count(), 1);
        assert.equal(await payment.locator('[data-test="row-tool"]').textContent(), "spend");
        assert.equal(await payment.locator('[data-test="row-payee"]').textContent(), "sample-merchant");
        assert.equal(await payment.locator('[data-test="row-amount"]').textContent(), "1250");
        assert.equal(await payment.locator('[data-test="row-currency"]').textContent(), "USD");
        assert.equal(await payment.locator('[data-test="row-reference"]').textContent(), "inv-7");
        assert.equal(await payment.locator('[data-test="row-agent"]').textContent(), "agent-1");
        assert.equal(await payment.locator('[data-test="row-rule"]').textContent(), "A payment is held for an operator.");
        const paymentRef = await payment.getAttribute("data-ref");
        assert.equal(await payment.locator('[data-test="row-ref"]').textContent(), paymentRef);
        assert.match((await payment.locator('[data-test="row-hash"]').textContent()) ?? "", /^[A-Za-z0-9_-]{16,}$/);

        // The markup is shown as the text it is. Nothing was made of it and none of it ran.
        const write = at(page, "waiting-row").filter({ hasNot: at(page, "row-payee") });
        assert.equal(await write.count(), 1);
        assert.equal(await write.locator('[data-test="row-tool"]').textContent(), "memory.put");
        const held = (await write.locator('[data-test="row-args"]').textContent()) ?? "";
        const shown = JSON.parse(held) as { body?: { note?: unknown; trick?: unknown; rtl?: unknown } };
        assert.equal(shown.body?.note, MARKUP);
        // Characters that turn text around, break a line or cannot be seen are shown as their escapes,
        // as the terminal shows them. Read back as JSON, it is still the value the agent sent.
        assert.equal(/[\p{Cf}\p{Zl}\p{Zp}]/u.test(held), false);
        for (const escape of ["\\u202e", "\\u202c", "\\u2028", "\\u200b", "\\udb40\\udc01"]) {
          assert.ok(held.includes(escape), escape);
        }
        assert.equal(shown.body?.trick, TRICK);
        // Letters that run right to left need no control character to move the digits beside them.
        // The arguments are laid out one character after another, and every other value is kept to itself.
        assert.equal(shown.body?.rtl, RTL);
        const laidOut = (name: string) =>
          write.locator(`[data-test="${name}"]`).evaluate((el) => {
            const style = (globalThis as unknown as { getComputedStyle: (el: unknown) => { direction: string; unicodeBidi: string } }).getComputedStyle(el);
            return `${style.direction} ${style.unicodeBidi}`;
          });
        assert.equal(await laidOut("row-args"), "ltr bidi-override");
        assert.equal(await laidOut("row-ref"), "ltr bidi-override");
        assert.equal(await laidOut("row-hash"), "ltr bidi-override");
        assert.equal(await laidOut("row-tool"), "ltr bidi-override");
        assert.equal(await laidOut("row-agent"), "ltr isolate");
        assert.equal(await laidOut("row-rule"), "ltr isolate");
        for (const name of ["row-payee", "row-amount", "row-currency", "row-reference"]) {
          assert.equal(await payment.locator(`[data-test="${name}"]`).evaluate((el) => (el as unknown as { tagName: string }).tagName), "BDI", name);
        }
        // The question a tap answers is built the same way: three values, each in its own element.
        assert.deepEqual(await payment.locator('[data-test="approve-panel"] bdi').allTextContents(), ["1250", "USD", "sample-merchant"]);
        assert.deepEqual(await write.locator('[data-test="approve-panel"] bdi').allTextContents(), ["memory.put"]);
        assert.equal(await page.locator('[data-test="door"] img, [data-test="door"] script').count(), 0);
        assert.equal(await page.title(), "Verax operator door");

        // Approve asks once more on the page before it asks the passkey, and cancel is cancel.
        assert.equal(await payment.locator('[data-test="approve-panel"]').isVisible(), false);
        assert.equal(await write.locator('[data-test="approve-panel"]').isVisible(), false);
        await payment.locator('[data-test="approve"]').click();
        await payment.locator('[data-test="approve-panel"]').waitFor({ state: "visible" });
        await payment.locator('[data-test="approve-cancel"]').click();
        assert.equal(await payment.locator('[data-test="approve-panel"]').isVisible(), false);
        assert.equal(await at(page, "waiting-row").count(), 2);
        await payment.locator('[data-test="approve"]').click();
        await payment.locator('[data-test="approve-confirm"]').click();
        await told(page, "ok", "approved");
        assert.match((await at(page, "notice").getAttribute("data-allow-ref")) ?? "", /\S/);
        await at(page, "waiting-row").nth(1).waitFor({ state: "detached", timeout: 20_000 });
        assert.equal(await at(page, "waiting-count").textContent(), "1");

        // Stop is signed too. While the body is stopped nothing is approved.
        await at(page, "halt").click();
        await told(page, "ok", "halted");
        assert.equal(await at(page, "halt-state").getAttribute("data-halted"), "true");
        assert.equal(await at(page, "halt").isVisible(), false);
        assert.equal(await at(page, "resume").isVisible(), true);
        assert.match((await at(page, "halt-since").textContent()) ?? "", /operator-1/);
        assert.deepEqual(await at(page, "halt-since").locator("bdi").allTextContents(), ["operator-1"]);
        await write.locator('[data-test="approve"]').click();
        await write.locator('[data-test="approve-confirm"]').click();
        await told(page, "error", "approve-halted");
        assert.equal(await at(page, "waiting-row").count(), 1);

        await at(page, "resume").click();
        await told(page, "ok", "resumed");
        assert.equal(await at(page, "halt-state").getAttribute("data-halted"), "false");
        assert.equal(await at(page, "resume").isVisible(), false);
        // The refused approval left its question open on the row. Answering it again now goes through.
        assert.equal(await write.locator('[data-test="approve-panel"]').isVisible(), true);
        await write.locator('[data-test="approve-confirm"]').click();
        await told(page, "ok", "approved");
        await at(page, "waiting-row").first().waitFor({ state: "detached", timeout: 20_000 });
        assert.equal(await at(page, "waiting-empty").isVisible(), true);

        // The door keeps a few sessions. A second device that signs in often enough puts this one out,
        // and the page finds out on its next call and goes back to asking for the passkey.
        const post = async (path: string, sent?: unknown): Promise<Record<string, unknown>> => {
          const res = await fetch(`http://127.0.0.1:${port}${path}`, {
            method: "POST",
            headers: { origin, ...(sent === undefined ? {} : { "content-type": "application/json" }) },
            ...(sent === undefined ? {} : { body: JSON.stringify(sent) }),
          });
          assert.equal(res.status, 200, path);
          return (await res.json()) as Record<string, unknown>;
        };
        const second = mintSoftwarePasskey();
        const { code } = beginPairing(body.stateDir);
        const options = await post("/api/enroll/options", { code });
        await post("/api/enroll", {
          code,
          response: registerWithSoftwarePasskey(second, { challenge: String(options.challenge), rpID: RP_ID, origin }),
        });
        for (let i = 0; i < 8; i++) {
          const signin = await post("/api/signin/options");
          await post("/api/signin", {
            assertion: assertWithSoftwarePasskey(second, { challenge: String(signin.challenge), rpID: RP_ID, origin }),
          });
        }
        await at(page, "refresh").click();
        await told(page, "error", "session-ended");
        await onScreen(page, "signin");

        // Signing in again and out again. The page kept the token nowhere a later page could find it.
        await at(page, "signin").click();
        await told(page, "ok", "signed-in");
        await onScreen(page, "main");
        await at(page, "signout").click();
        await told(page, "ok", "signed-out");
        await onScreen(page, "signin");
        assert.deepEqual(
          await page.evaluate(() => {
            const win = globalThis as unknown as {
              localStorage: { length: number };
              sessionStorage: { length: number };
              document: { cookie: string };
              location: { href: string };
            };
            return [win.localStorage.length, win.sessionStorage.length, win.document.cookie, win.location.href];
          }),
          [0, 0, "", `${origin}/`],
        );

        // The page asked its own origin and nothing else, and the browser refused it nothing.
        assert.deepEqual([...askedOf], [origin]);
        assert.deepEqual(faults, []);

        // No body is running when the files are read back: two approvals, one stop and one resume,
        // each carrying a passkey signature made in this browser for that one thing.
        await shut();
        const approvals = await verifyApprovalSignatures(body.stateDir);
        assert.equal(approvals.signedVerified, 2, approvals.line);
        assert.equal(approvals.signedFailed, 0);
        assert.equal(approvals.unsignedHttp, 0);
        assert.ok(approvals.line.includes(`origin ${origin}`), approvals.line);
        const controls = await verifyControlSignatures(body.stateDir);
        assert.equal(controls.signedVerified, 2, controls.line);
        assert.equal(controls.signedFailed, 0);
        assert.equal(controls.unsignedHttp, 0);
      } finally {
        stopBrowser?.();
        await shut();
        rmSync(body.stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
      }
    },
  );
});
