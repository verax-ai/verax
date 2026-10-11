import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { describe, it } from "node:test";

import { runDoctor } from "../packages/body/src/doctor.ts";
import { anchorInTurn, witnessAnchorFromEnv } from "../packages/body/src/witness.ts";

/**
 * Found in the pre-release review of automatic anchoring.
 *
 * - The handler that records a failed registration could fail itself (a full
 *   disk fails both). Its rejection had no handler, and an unhandled rejection
 *   ends the witness process.
 * - Every checkpoint queued another run, and each run retries everything still
 *   pending, so a service that stayed down grew a queue of identical work.
 * - A service key file that held anything but whitespace passed the start
 *   check; STATUS says an unusable value stops the witness with exit 64.
 * - `VERAX_ANCHOR_SERVICE_KEY` names a file holding a public key. `verax doctor`
 *   read the name as a secret and failed.
 */

describe("anchoring in turn", () => {
  it("a run that fails, recorded by a handler that fails too, rejects nothing", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);
    try {
      const trigger = anchorInTurn(
        async () => {
          throw new Error("service unreachable");
        },
        () => {
          throw new Error("ENOSPC: no space left on device");
        },
      );
      trigger();
      trigger();
      await sleep(50);
      assert.deepEqual(unhandled, [], "the witness process would have ended here");
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });

  it("checkpoints that arrive during a run add one more run, not one each", async () => {
    let runs = 0;
    let release: () => void = () => undefined;
    const trigger = anchorInTurn(
      () =>
        new Promise<void>((resolve) => {
          runs += 1;
          release = resolve;
        }),
      () => undefined,
    );
    trigger();
    await sleep(5);
    assert.equal(runs, 1);
    for (let i = 0; i < 10; i += 1) trigger();
    release();
    await sleep(5);
    assert.equal(runs, 2, "ten checkpoints during one run queued more than one further run");
    release();
    await sleep(5);
    assert.equal(runs, 2);
    trigger();
    await sleep(5);
    assert.equal(runs, 3, "a checkpoint after the queue drained did not start a run");
    release();
  });
});

describe("the anchor service key at witness start", () => {
  it("a file that is not a public key stops the start", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-anchor-key-"));
    try {
      const keyFile = join(dir, "service.pub.pem");
      writeFileSync(keyFile, "not a public key\n", "utf8");
      const got = witnessAnchorFromEnv({
        VERAX_ANCHOR_SERVICE: "https://ts.example",
        VERAX_ANCHOR_SERVICE_KEY: keyFile,
      });
      assert.equal(got.ok, false, "a witness would have started and refused every receipt it was sent");
      if (!got.ok) assert.match(got.reason, /is not a public key/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a public key file is accepted", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-anchor-key-"));
    try {
      const keyFile = join(dir, "service.pub.pem");
      const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      writeFileSync(keyFile, publicKey.export({ type: "spki", format: "pem" }).toString(), "utf8");
      const got = witnessAnchorFromEnv({
        VERAX_ANCHOR_SERVICE: "https://ts.example",
        VERAX_ANCHOR_SERVICE_KEY: keyFile,
      });
      assert.equal(got.ok, true, got.ok ? "" : got.reason);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("doctor and the anchor service key path", () => {
  it("a path to a public key file is not a secret in the environment", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-anchor-doctor-"));
    try {
      const checks = runDoctor(
        { VERAX_STATE_DIR: dir, VERAX_ANCHOR_SERVICE_KEY: join(dir, "service.pub.pem") },
        [],
        { elevated: () => false },
      );
      const hit = checks.find((c) => c.id === "secrets-in-env");
      assert.equal(hit, undefined, hit?.detail);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a key written into that variable instead of a path is still named", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-anchor-doctor-"));
    try {
      const checks = runDoctor(
        { VERAX_STATE_DIR: dir, VERAX_ANCHOR_SERVICE_KEY: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----" },
        [],
        { elevated: () => false },
      );
      const hit = checks.find((c) => c.id === "secrets-in-env");
      assert.ok(hit, "PEM text in the environment was not named");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
