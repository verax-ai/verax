import { strict as assert } from "node:assert";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

// What npm shows beside the code: the README is the package page, the
// LICENSE travels with what it licenses, and the manifest points at the
// website and the directory in this repository. Every public workspace under
// packages/ is held to it, so a new package cannot ship an empty page.

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

type Manifest = {
  name: string;
  private?: boolean;
  homepage?: string;
  keywords?: string[];
  repository?: { directory?: string };
};

const website = (JSON.parse(readFileSync(join(root, "server.json"), "utf8")) as { websiteUrl: string }).websiteUrl;
const rootLicense = readFileSync(join(root, "LICENSE"));

const published = readdirSync(join(root, "packages"))
  .map((dir) => ({ dir, path: join(root, "packages", dir) }))
  .filter(({ path }) => existsSync(join(path, "package.json")))
  .map(({ dir, path }) => ({ dir, path, pkg: JSON.parse(readFileSync(join(path, "package.json"), "utf8")) as Manifest }))
  .filter(({ pkg }) => pkg.private !== true);

describe("what every published package carries beside its code", () => {
  it("there are public packages to hold to this", () => {
    assert.ok(published.length > 0, "no public package under packages/");
  });

  for (const { dir, path, pkg } of published) {
    it(`${pkg.name}: README.md opens with the package name and points at STATUS.md`, () => {
      assert.ok(existsSync(join(path, "README.md")), "no README.md: npm shows an empty page");
      const readme = readFileSync(join(path, "README.md"), "utf8");
      assert.ok(readme.startsWith(`# ${pkg.name}\n`), `README.md does not open with "# ${pkg.name}"`);
      assert.match(readme, /docs\/STATUS\.md/, "README.md does not point at docs/STATUS.md, where the unproven parts are stated");
    });

    it(`${pkg.name}: LICENSE is the repository's license, byte for byte`, () => {
      assert.ok(existsSync(join(path, "LICENSE")), "no LICENSE beside the code");
      assert.ok(rootLicense.equals(readFileSync(join(path, "LICENSE"))), `packages/${dir}/LICENSE differs from LICENSE`);
    });

    it(`${pkg.name}: package.json points npm at the website and at this directory`, () => {
      assert.equal(pkg.homepage, website, "homepage is not the website server.json names");
      assert.equal(pkg.repository?.directory, `packages/${dir}`, "repository.directory does not name this directory");
      assert.ok(Array.isArray(pkg.keywords) && pkg.keywords.length > 0, "no keywords: npm search does not find the package");
    });
  }
});
