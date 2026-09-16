import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { packReportFiles } from "../scripts/pack-report.ts";

// Two real shapes: npm 10 on the Linux runner, npm 12 on a developer machine.
const ARRAY_SHAPE = JSON.stringify([
  { id: "@verax-ai/body@0.1.0", name: "@verax-ai/body", files: [{ path: "dist/index.js" }, { path: "package.json" }] },
]);
const OBJECT_SHAPE = JSON.stringify({
  "@verax-ai/body": {
    id: "@verax-ai/body@0.1.0",
    name: "@verax-ai/body",
    files: [{ path: "dist/index.js" }, { path: "package.json" }],
  },
});

describe("reading npm pack --json", () => {
  for (const [label, text] of [
    ["npm 10 array", ARRAY_SHAPE],
    ["npm 12 object", OBJECT_SHAPE],
  ] as const) {
    it(`finds the packed files in the ${label} shape`, () => {
      const { files, why } = packReportFiles(text, "@verax-ai/body");
      assert.deepEqual(files, ["dist/index.js", "package.json"], why);
    });
  }

  it("turns Windows separators into the paths npm publishes", () => {
    const { files } = packReportFiles(
      JSON.stringify([{ files: [{ path: "dist\\tools\\spend.js" }] }]),
      "@verax-ai/body",
    );
    assert.deepEqual(files, ["dist/tools/spend.js"]);
  });

  it("says why when there is nothing to read, instead of reporting an empty package", () => {
    const empty = packReportFiles("npm error code E404\n", "@verax-ai/body");
    assert.deepEqual(empty.files, []);
    assert.match(empty.why, /no json/);
    const broken = packReportFiles("{ not json", "@verax-ai/body");
    assert.match(broken.why, /unreadable json/);
  });
});
