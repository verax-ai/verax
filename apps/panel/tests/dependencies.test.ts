import { strict as assert } from "node:assert";
import { globSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * A dependency the panel no longer imports still ships in the install and
 * still reads as a claim about what the panel is made of.
 */
describe("panel dependencies", () => {
  it("imports every workspace package it depends on", () => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
      dependencies?: Record<string, string>;
    };
    const sources = globSync(join(root, "src", "**", "*.{ts,tsx}"))
      .map((file) => readFileSync(file, "utf8"))
      .join(String.fromCharCode(10));
    const workspace = Object.keys(pkg.dependencies ?? {}).filter((name) =>
      name.startsWith("@verax-ai/"),
    );
    assert.ok(workspace.length > 0, "no workspace dependencies found to check");
    for (const name of workspace) {
      assert.ok(
        sources.includes(`"${name}"`),
        `${name} is a dependency the panel source never imports`,
      );
    }
  });
});
