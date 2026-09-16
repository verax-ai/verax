import { strict as assert } from "node:assert";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

// The shape of the publish workflow, read as text. A YAML parser would be
// stricter and is not in the tree; these checks hold the parts that, if they
// drift, publish something different from what the suite proved or publish
// through a weaker path than trusted publishing.

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const path = join(root, ".github", "workflows", "release.yml");
const yml = existsSync(path) ? readFileSync(path, "utf8") : "";

const PUBLISH_ORDER = ["@verax-ai/inventory", "@verax-ai/proxy", "@verax-ai/body"];

function namedStep(text: string, title: string): string {
  const start = text.indexOf(`- name: ${title}`);
  assert.ok(start >= 0, `step "${title}" is gone`);
  const rest = text.slice(start + 1);
  const next = rest.search(/\n      - /);
  return next >= 0 ? text.slice(start, start + 1 + next) : text.slice(start);
}

describe("release.yml, the only path that publishes to npm from this repository", () => {
  it("exists", () => {
    assert.ok(yml.length > 0, ".github/workflows/release.yml is missing");
  });

  it("runs only from the Actions tab, and only when confirm says publish or check", () => {
    assert.match(yml, /^on:\s*\n\s+workflow_dispatch:/m, "release.yml does not start with workflow_dispatch");
    assert.doesNotMatch(yml, /^\s+push:/m, "a push trigger would publish without anyone asking");
    assert.doesNotMatch(yml, /^\s+tags:/m, "a tag trigger would publish without anyone asking");
    const gate = namedStep(yml, "refuse without confirmation");
    assert.match(gate, /"publish"/, "the gate does not name publish");
    assert.match(gate, /"check"/, "the gate does not name check");
  });

  it("uses trusted publishing: id-token on the job, provenance on the publish, no long-lived token", () => {
    assert.match(yml, /^permissions:\s*\n\s+contents: read\s*$/m, "workflow-level permissions are not read-only");
    assert.match(yml, /^\s{6}id-token: write$/m, "the job does not request id-token: write");
    assert.doesNotMatch(yml, /NPM_TOKEN|NODE_AUTH_TOKEN/, "a token secret is referenced; trusted publishing needs none");
    const send = namedStep(yml, "send them in dependency order");
    assert.match(send, /--provenance/, "publish runs without --provenance");
  });

  it("check mode never reaches the publish or the readback", () => {
    for (const title of [
      "send them in dependency order",
      "npm answers with this version",
      "every tarball of this version answers",
      "a clean install from the registry",
    ]) {
      assert.match(
        namedStep(yml, title),
        /if: \$\{\{ inputs\.confirm == 'publish' \}\}/,
        `step "${title}" is not confined to confirm=publish`,
      );
    }
  });

  it("publishes the three packages in dependency order", () => {
    const send = namedStep(yml, "send them in dependency order");
    const found = PUBLISH_ORDER.map((p) => send.indexOf(p));
    for (let i = 0; i < PUBLISH_ORDER.length; i += 1) {
      assert.ok(found[i] >= 0, `${PUBLISH_ORDER[i]} is not published`);
      if (i > 0) assert.ok(found[i] > found[i - 1], `${PUBLISH_ORDER[i]} is sent before ${PUBLISH_ORDER[i - 1]}`);
    }
  });

  it("proves the tree before anything is sent: the suite and pack:smoke come before publish", () => {
    const suite = yml.indexOf("npm test");
    const smoke = yml.indexOf("npm run pack:smoke");
    const send = yml.indexOf("- name: send them in dependency order");
    assert.ok(suite >= 0 && suite < send, "npm test does not run before publish");
    assert.ok(smoke >= 0 && smoke < send, "pack:smoke does not run before publish");
  });

  it("holds the three packages and server.json to one version before publishing", () => {
    const gate = namedStep(yml, "the three packages carry one version, and server.json agrees");
    assert.match(gate, /server\.json/, "the version gate does not read server.json");
    const send = yml.indexOf("- name: send them in dependency order");
    assert.ok(yml.indexOf("- name: the three packages carry one version") < send, "the version gate is not before publish");
  });

  it("reads the result back from npm, version and tarball, and then installs from the registry", () => {
    const send = yml.indexOf("- name: send them in dependency order");
    const version = yml.indexOf("- name: npm answers with this version");
    const tarball = yml.indexOf("- name: every tarball of this version answers");
    const install = yml.indexOf("- name: a clean install from the registry");
    assert.ok(send < version && version < tarball && tarball < install, "readback steps are missing or out of order");
    const readback = namedStep(yml, "npm answers with this version");
    assert.match(readback, /deadline=\$\(\(SECONDS \+ \d{3}\)\)/, "the readback has no shared deadline; npm is eventual");
    const bytes = namedStep(yml, "every tarball of this version answers");
    assert.match(bytes, /dist\.tarball/, "the tarball check does not use the URL npm names");
    const smoke = namedStep(yml, "a clean install from the registry");
    assert.match(smoke, /npm audit signatures/, "the installed packages are not checked for attestations");
    assert.match(smoke, /verax --version/, "the installed bin is not asked its version");
  });

  it("pins its actions to commits", () => {
    for (const m of yml.matchAll(/uses: ([^@\s]+)@(\S+)/g)) {
      assert.match(m[2], /^[0-9a-f]{40}( |$)/, `${m[1]} is not pinned to a commit`);
    }
  });
});
