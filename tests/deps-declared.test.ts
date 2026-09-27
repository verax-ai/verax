// A package that imports another at run time must list it. In the workspace a hoisted
// node_modules hides a missing entry; an install of the published package alone does not.
import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { builtinModules } from "node:module";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(path));
    else if (/\.(ts|tsx|mjs|js)$/.test(entry.name) && !/\.test\./.test(entry.name) && !entry.name.endsWith(".d.ts")) out.push(path);
  }
  return out;
}

/** Package names imported for their values. `import type` and `export type` are erased and do not count. */
export function runtimeImports(source: string): Set<string> {
  const names = new Set<string>();
  const statement = /(?:^|\n)\s*(import|export)\s+(type\s+)?(?:[^'"]*?\s+from\s+)?["']([^"']+)["']/g;
  const dynamic = /\bimport\(\s*["']([^"']+)["']\s*\)/g;
  const add = (spec: string): void => {
    if (spec.startsWith(".") || spec.startsWith("/") || spec.startsWith("node:")) return;
    const name = spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0]!;
    if (builtinModules.includes(name)) return;
    names.add(name);
  };
  for (const m of source.matchAll(statement)) if (!m[2]) add(m[3]!);
  for (const m of source.matchAll(dynamic)) add(m[1]!);
  return names;
}

describe("published packages declare what they import", () => {
  it("the scanner skips type-only imports and catches value imports", () => {
    const found = runtimeImports(
      'import type { A } from "only-types";\nimport { b } from "@scope/value";\nexport { c } from "re-export";\nconst d = await import("dyn");\n',
    );
    assert.deepEqual([...found].sort(), ["@scope/value", "dyn", "re-export"]);
  });

  for (const pkg of ["inventory", "proxy", "body"]) {
    it(`@verax-ai/${pkg}`, () => {
      const dir = join(root, "packages", pkg);
      const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as {
        name: string;
        dependencies?: Record<string, string>;
        peerDependencies?: Record<string, string>;
        optionalDependencies?: Record<string, string>;
      };
      const declared = new Set([
        manifest.name,
        ...Object.keys(manifest.dependencies ?? {}),
        ...Object.keys(manifest.peerDependencies ?? {}),
        ...Object.keys(manifest.optionalDependencies ?? {}),
      ]);
      const missing = new Map<string, string>();
      for (const file of sourceFiles(join(dir, "src"))) {
        for (const name of runtimeImports(readFileSync(file, "utf8"))) {
          if (!declared.has(name) && !missing.has(name)) missing.set(name, file.slice(root.length + 1));
        }
      }
      assert.deepEqual(Object.fromEntries(missing), {}, "imported at run time but not in dependencies");
    });
  }
});
