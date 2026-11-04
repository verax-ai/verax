import { strict as assert } from "node:assert";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const src = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src");

/**
 * A console that is not set to UTF-8 shows a multibyte character as other
 * characters: on a Turkish Windows the middle dot printed as two signs. These
 * two files do not write to a console: one holds tool descriptions sent as JSON,
 * the other a page served as UTF-8.
 */
const NOT_CONSOLE = new Set(["server.ts", "operator-door-page.ts"]);

describe("the body's console text is ASCII", () => {
  it("no source line outside a comment holds another character", () => {
    const found: string[] = [];
    const files = readdirSync(src, { recursive: true, encoding: "utf8" }).filter(
      (name) => name.endsWith(".ts") && !NOT_CONSOLE.has(name),
    );
    assert.ok(files.length > 20, `read ${files.length} files`);
    for (const name of files) {
      readFileSync(join(src, name), "utf8")
        .split("\n")
        .forEach((line, index) => {
          if (/^\s*(\/\/|\/\*|\*)/.test(line)) return;
          if (/[^\x00-\x7F]/.test(line.replace(/\s\/\/ .*$/, ""))) found.push(`${name}:${index + 1}`);
        });
    }
    assert.deepEqual(found, []);
  });
});
