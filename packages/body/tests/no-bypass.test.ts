import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { scanNoBypass } from "../src/no-bypass-scan.ts";

const pkg = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("B1 no-bypass", () => {
  it("the tree has no bypass hits", () => {
    const hits = scanNoBypass(pkg);
    assert.deepEqual(
      hits,
      [],
      hits.map((h) => `${h.file}:${h.line}: ${h.why}: ${h.text}`).join("\n"),
    );
  });

  it("RED: a static tools import outside wiring is refused", () => {
    const spec = [".", "tools", "memory.ts"].join("/");
    const red = scanNoBypass(pkg, [{ file: "src/index.ts", text: `import "${spec}";\n` }]);
    assert.ok(
      red.some((h) => h.file === "src/index.ts" && h.why === "static import of tools/"),
      JSON.stringify(red),
    );
  });

  it("P2-7: unquoted dynamic import forms are hits", () => {
    const dyn = ["im", "port("].join("");
    const byName = scanNoBypass(pkg, [{ file: "src/index.ts", text: `await ${dyn}name)\n` }]);
    const byUrl = scanNoBypass(pkg, [
      {
        file: "src/index.ts",
        text: `${dyn}new URL("./tools/memory.ts", import.meta.url).href)\n`,
      },
    ]);
    assert.ok(byName.some((h) => h.why === "dynamic-import"), `name-form hits=${JSON.stringify(byName)}`);
    assert.ok(byUrl.some((h) => h.why === "dynamic-import"), `url-form hits=${JSON.stringify(byUrl)}`);
  });

  it("P2-E: comment or newline between import and paren is a hit", () => {
    const head = ["im", "port"].join("");
    const commented = scanNoBypass(pkg, [{ file: "src/index.ts", text: `await ${head}/*x*/(name)\n` }]);
    const broken = scanNoBypass(pkg, [{ file: "src/index.ts", text: `${head}\n(name)\n` }]);
    assert.equal(
      commented.filter((h) => h.why === "dynamic-import").length,
      1,
      `comment-form hits=${JSON.stringify(commented)}`,
    );
    assert.equal(
      broken.filter((h) => h.why === "dynamic-import").length,
      1,
      `newline-form hits=${JSON.stringify(broken)}`,
    );
  });

  it("5: import inside string-wrapped comment markers is still a hit", () => {
    const head = ["im", "port"].join("");
    const wrapped = scanNoBypass(pkg, [
      { file: "src/index.ts", text: `const a="/*"; await ${head}(name); const b="*/";\n` },
    ]);
    assert.equal(
      wrapped.filter((h) => h.why === "dynamic-import").length,
      1,
      `string-form hits=${JSON.stringify(wrapped)}`,
    );
  });

  it("6: a string or comment containing the import sequence is still a hit", () => {
    const dyn = ["im", "port("].join("");
    const inString = scanNoBypass(pkg, [{ file: "src/index.ts", text: `const docs = "call ${dyn}name)";\n` }]);
    const inComment = scanNoBypass(pkg, [{ file: "src/index.ts", text: `// docs: ${dyn}name)\n` }]);
    assert.equal(
      inString.filter((h) => h.why === "dynamic-import").length,
      1,
      `string-probe hits=${JSON.stringify(inString)}`,
    );
    assert.equal(
      inComment.filter((h) => h.why === "dynamic-import").length,
      1,
      `comment-probe hits=${JSON.stringify(inComment)}`,
    );
  });

  it("6: threat model states the conservative no-bypass rule", () => {
    const threat = readFileSync(join(pkg, "..", "..", "docs", "THREAT_MODEL.md"), "utf8");
    const a = ["im", "port("].join("");
    const b = ["req", "uire("].join("");
    const sentence =
      "The no-bypass scan is deliberately conservative: the character sequences `" +
      a +
      "` and `" +
      b +
      "` may not appear anywhere in packages/body, including strings and comments.";
    assert.equal(threat.includes(sentence), true);
    assert.equal(threat.includes("\n\n" + sentence + "\n\n"), true);
    const c = ["child", "_process"].join("");
    const desktopException =
      "Exception: `src/desktop.ts` may import `node:" +
      c +
      "` to supervise the issuer, body, and panel. That file is still scanned for `" +
      a +
      "`, `" +
      b +
      "`, `eval`, and `tools/` imports.";
    assert.equal(threat.includes(desktopException), true);
    const lockSentence =
      "The directory lock detects an accidental second body on the same state directory. It is not a distributed lock: a lock is never taken over automatically; an operator removes a dead lock with `verax unlock`. A multi-process ledger belongs to the phase 4 witness process.";
    assert.equal(threat.includes(lockSentence), true);
    const status = readFileSync(join(pkg, "..", "..", "docs", "STATUS.md"), "utf8");
    assert.equal(status.includes("Operator unlock is recorded in unlocks.jsonl, not signed"), true);
    assert.equal(status.includes("best effort; single writer by construction"), true);
  });

  it("RED: a dynamic concatenated tools import is refused", () => {
    const head = "im" + "port(";
    const red = scanNoBypass(pkg, [
      { file: "src/index.ts", text: `await ${head}"./${"tools"}/" + "memory.ts");\n` },
    ]);
    assert.ok(
      red.some((h) => h.why === "dynamic-import"),
      JSON.stringify(red),
    );
  });
});
