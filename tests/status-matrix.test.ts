import { strict as assert } from "node:assert";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

// docs/STATUS.md states a capability per released version and names the test
// that holds each row up. That is the same fact in two places: the matrix and
// the tree. This file is the third thing that compares them, so a release that
// moves the version, or a rename that takes a guard away, turns red here
// instead of leaving a customer reading a sentence nothing tests any more.

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const status = readFileSync(join(root, "docs", "STATUS.md"), "utf8");

/** The version on the matrix heading: `## Capability matrix — 0.1.2`. */
export function matrixVersion(text: string): string | null {
  const m = /^##\s+Capability matrix\s+—\s+(\d+\.\d+\.\d+)\s*$/m.exec(text);
  return m ? m[1] : null;
}

/** The rows of that table, up to the next heading. */
export function matrixRows(text: string): string[] {
  const start = text.indexOf("| Capability | Since |");
  if (start < 0) return [];
  const rest = text.slice(start);
  const end = rest.search(/\n##\s/);
  return (end < 0 ? rest : rest.slice(0, end))
    .split("\n")
    .filter((line) => line.startsWith("|"))
    .slice(2); // header and separator
}

/**
 * Bare backticked names in the last cell. A name with a slash (`apps/panel`)
 * is a suite, not a file, and is not looked up.
 */
export function guardNames(row: string): string[] {
  const cells = row.split("|").map((c) => c.trim());
  const last = cells[cells.length - 2] ?? "";
  const names = [...last.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
  return names.filter((n) => /^[a-z0-9-]+$/.test(n));
}

function guardFile(name: string): string | null {
  for (const dir of [["tests"], ["packages", "proxy", "tests"]]) {
    const path = join(root, ...dir, `${name}.test.ts`);
    if (existsSync(path)) return path;
  }
  return null;
}

describe("the capability matrix states the released version", () => {
  it("names the version the body package carries", () => {
    const pkg = JSON.parse(readFileSync(join(root, "packages", "body", "package.json"), "utf8")) as {
      version: string;
    };
    assert.equal(
      matrixVersion(status),
      pkg.version,
      "docs/STATUS.md still names an older version than packages/body/package.json",
    );
  });

  it("reads the version off the heading and not off any other line", () => {
    assert.equal(matrixVersion("## Capability matrix — 9.9.9\n"), "9.9.9");
    assert.equal(matrixVersion("we shipped 0.1.2 last night\n"), null);
  });
});

describe("every guard the matrix names is a test in this tree", () => {
  const rows = matrixRows(status);

  it("finds the table", () => {
    assert.ok(rows.length >= 10, `expected the matrix rows, read ${rows.length}`);
  });

  for (const row of rows) {
    const capability = (row.split("|")[1] ?? "").trim();
    const names = guardNames(row);
    it(`${capability}: ${names.join(", ") || "a suite, not a file"}`, () => {
      for (const name of names) {
        assert.ok(guardFile(name), `docs/STATUS.md names ${name}, which is not a test file`);
      }
    });
  }
});

describe("the historical record is marked as historical", () => {
  it("puts the matrix before the dated phases", () => {
    const matrix = status.indexOf("## Capability matrix");
    const history = status.indexOf("## Historical record");
    const phase0 = status.indexOf("## Phase 0");
    assert.ok(matrix > -1 && history > -1 && phase0 > -1, "a heading is missing");
    assert.ok(matrix < history, "the matrix has to come before the historical record");
    assert.ok(history < phase0, "Phase 0 has to sit under the historical record heading");
  });
});
