// The passkey route to approve a held call is the operator door. The panel
// behind `verax desktop` is not released, so no text the CLI prints sends an
// operator to it.

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { runCli } from "../packages/body/src/cli.ts";
import { unreadableSentence } from "../packages/body/src/install.ts";

describe("where the CLI says a held call is approved", () => {
  it("--help names the operator door and not the panel", async () => {
    let out = "";
    const code = await runCli(["--help"], { stdout: { write: (s: string) => (out += s) } });
    assert.equal(code, 0);
    const approve = out.slice(out.indexOf("  approve <args>"), out.indexOf("\n  ", out.indexOf("  approve <args>") + 1 + 400));
    assert.equal(/panel/.test(approve), false, approve);
    assert.match(out, /operator door/);
  });

  it("the unreadable-directory sentence for approve on Windows names the operator door", { skip: process.platform !== "win32" }, () => {
    const said = unreadableSentence("C:\\state", "approve");
    assert.equal(/panel/.test(said), false, said);
    assert.match(said, /operator door/);
    assert.match(said, /separate administrator account/);
  });
});
