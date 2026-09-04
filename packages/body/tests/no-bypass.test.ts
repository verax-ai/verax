import { strict as assert } from "node:assert";
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
