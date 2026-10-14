import { strict as assert } from "node:assert";
import { readdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { listPieceFiles, verifyLedger } from "@verax-ai/proxy";

import { readCredentials, removeCredential, removedPath, saveCredential } from "../packages/body/src/operator-credentials.ts";
import { OPERATOR_REMOVED_DIR, operatorRemovalMark } from "../packages/proxy/src/operator-removal-sync.ts";
import { hold, openBody } from "./operator-door-fixture.ts";
import { mintSoftwarePasskey } from "./software-passkey.ts";

type Claims = { subject?: string; reasonCode?: string; decision?: string; effectClass?: string; ref?: string };

/** Every decision and every inputs row under a state directory, read from the files. */
function ledgerOf(stateDir: string): { claims: Claims[]; inputs: Map<string, Record<string, unknown>> } {
  const claims: Claims[] = [];
  const inputs = new Map<string, Record<string, unknown>>();
  for (const piece of listPieceFiles(stateDir)) {
    for (const line of readFileSync(piece.decisions, "utf8").split("\n")) {
      if (line !== "") claims.push((JSON.parse(line) as { claims: Claims }).claims);
    }
    for (const line of readFileSync(piece.inputs, "utf8").split("\n")) {
      if (line === "") continue;
      const row = JSON.parse(line) as { ref?: string; inputs?: Record<string, unknown> };
      if (row.ref && row.inputs) inputs.set(row.ref, row.inputs);
    }
  }
  return { claims, inputs };
}

describe("a passkey removal reaches the ledger", () => {
  it("L1 what `verax operator remove` writes is what the ledger's account is kept from", async () => {
    const phone = mintSoftwarePasskey();
    const spare = mintSoftwarePasskey();
    const body = await openBody(phone);
    saveCredential(body.stateDir, {
      id: spare.id,
      publicKey: isoBase64URL.fromBuffer(spare.publicKeyCose.slice()),
      counter: 0,
      sub: "operator-1",
    });
    let open = true;
    const shut = async () => {
      if (!open) return;
      open = false;
      await new Promise<void>((resolve) => body.server.close(() => resolve()));
    };
    try {
      assert.equal(removeCredential(body.stateDir, phone.id), "removed");
      // One name for the directory and one for the mark, in both packages.
      assert.equal(removedPath(body.stateDir), join(body.stateDir, OPERATOR_REMOVED_DIR));
      assert.deepEqual(readdirSync(removedPath(body.stateDir)), [operatorRemovalMark(phone.id)]);
      assert.deepEqual(readCredentials(body.stateDir).map((row) => row.id), [spare.id]);

      // The CLI runs outside the body. The record is written when the next call reaches the proxy.
      await hold(body, "removal-l1-a");
      await hold(body, "removal-l1-b");
      await shut();

      const { claims, inputs } = ledgerOf(body.stateDir);
      const recorded = claims.filter((row) => row.subject === "verax.operator");
      assert.deepEqual(
        recorded.map((row) => [row.decision, row.reasonCode, row.effectClass]),
        [["deny", "passkey-removed", "verax.control"]],
      );
      assert.deepEqual(inputs.get(recorded[0]!.ref!)?.operatorRemoval, {
        action: "remove",
        mark: operatorRemovalMark(phone.id),
        by: "unknown",
        via: "file",
        atMs: (inputs.get(recorded[0]!.ref!)?.operatorRemoval as { atMs: number }).atMs,
      });
      const verified = await verifyLedger(body.stateDir);
      assert.equal(verified.ok, true, verified.problems.join("\n"));
    } finally {
      await shut();
      rmSync(body.stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });
});
