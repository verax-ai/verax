import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = join(pkgRoot, "..", "..");

const ALLOWED = new Set([
  "verifyLedger",
  "createProxy",
  // The downstream adapter validates the same dispatch descriptor as the proxy.
  "effectDescriptor",
  "sha256Canonical",
  "thirdPartyReceiptRejection",
  "samePublicKey",
  "LedgerDenyUnrecorded",
  "loadPolicy",
  // The spend gate refuses this class. The display class adds the characters
  // that draw nothing; approve-cli, the operator door and the pin command
  // escape it. Both live here so body does not grow a second copy.
  "TERMINAL_CONTROL_CLASS",
  "DISPLAY_ESCAPE_CLASS",
  // The printed form of text the process did not write: body's stderr lines
  // and the proxy's own both go through it.
  "terminalText",
  "terminalLines",
  "FileLedger",
  "MemoryLedger",
  "explain",
  "approvePending",
  "approvalsLogFor",
  // HTTP and CLI approve doors share the spend daily-max check; the factory
  // lives next to approvePending so both pass the same function.
  "createApprovalBudgetGuard",
  "enqueueApprovalCommand",
  "loadApprovalsFromDir",
  "loadEffectsFromDir",
  "parseChannelJsonl",
  "parseCardCsv",
  "reconcile",
  // reconcile-cli passes the decision-ref set; the loader lists the same
  // decision files verifyLedger reads, so it stays on this package's surface.
  "loadDecisionRefsFromDir",
  "tenantKey",
  "spokenReason",
  "checkpointsPath",
  "signEffectAttestation",
  "diskProbe",
  // The body reads inputs.jsonl from its end for a ledger window; the reader
  // goes through the ledgerFs seam, so it has to be this package's.
  "readLedgerTail",
  "lockHolderAlive",
  // The body walks the ledger pieces (doctor, inputs window, witness) and
  // the manifest that names them is this package's file to read.
  "listPieceFiles",
  // Doctor compares the ref index to the pieces; the count lives next to
  // the manifest reader and must stay this package's.
  "indexCoverage",
  // verax anchor reads the checkpoints and writes the anchor rows that
  // verifyLedger checks; the file formats and the receipt reader stay here.
  "readCheckpointFile",
  "anchorEntryHash",
  "appendAnchor",
  "readAnchors",
  "verifyReceipt",
  "lockState",
  "lockBeatOf",
  // The body files a removed passkey's mark and the proxy reads the marks
  // into the ledger: one name for the directory and one for the mark.
  "OPERATOR_REMOVED_DIR",
  "operatorRemovalMark",
]);

describe("B1 exports map", () => {
  it("package.json exports only the root entry", () => {
    const pkg = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8")) as {
      exports: Record<string, string>;
    };
    assert.deepEqual(Object.keys(pkg.exports), ["."]);
  });

  it("index.ts value exports are the allowed set", () => {
    const src = readFileSync(join(pkgRoot, "src", "index.ts"), "utf8");
    const names = [...src.matchAll(/export\s+\{([^}]+)\}/g)]
      .flatMap((m) => m[1].split(","))
      .map((s) => s.trim().split(/\s+/)[0])
      .filter((s) => s && s !== "type");
    for (const name of names) {
      assert.ok(ALLOWED.has(name), `unexpected export ${name}`);
    }
    for (const name of ALLOWED) {
      assert.ok(names.includes(name), `missing export ${name}`);
    }
  });

  it("npm pack --dry-run lists the package and no test fixtures", () => {
    // --ignore-scripts: prepack would rebuild dist while other test files,
    // running at the same time, load it.
    // --json puts the file list on stdout whatever npm's log level is. The
    // notices carry it too, but under `npm run --silent` there are none, and
    // a check that reads them has nothing to read.
    const packed = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts", "-w", "@verax-ai/proxy"], {
      cwd: repoRoot,
      encoding: "utf8",
      shell: true,
    });
    assert.equal(packed.status, 0, `${packed.stdout ?? ""}\n${packed.stderr ?? ""}`);
    type Listing = { name: string; files: { path: string }[] };
    // npm 10 answers with a list, npm 12 with an object keyed by workspace.
    const parsed = JSON.parse(packed.stdout) as Listing[] | Record<string, Listing>;
    const listings = Array.isArray(parsed) ? parsed : Object.values(parsed);
    assert.deepEqual(listings.map((listing) => listing.name), ["@verax-ai/proxy"]);
    const paths = listings[0]!.files.map((file) => file.path);
    assert.ok(paths.includes("dist/index.js"), paths.join("\n"));
    assert.deepEqual(paths.filter((path) => path.includes("tests/")), []);
  });
});
