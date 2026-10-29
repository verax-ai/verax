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

const PUBLISH_ORDER = ["inventory", "proxy", "body"];

function namedStep(text: string, title: string): string {
  const start = text.indexOf(`- name: ${title}`);
  assert.ok(start >= 0, `step "${title}" is gone`);
  const rest = text.slice(start + 1);
  const next = rest.search(/\n      - /);
  return next >= 0 ? text.slice(start, start + 1 + next) : text.slice(start);
}

/** The text of one job, from its key at two spaces of indent to the next job's key. */
function job(text: string, name: string): string {
  const start = text.search(new RegExp(`^  ${name}:\\s*$`, "m"));
  assert.ok(start >= 0, `job "${name}" is gone`);
  const rest = text.slice(start + 1);
  const next = rest.search(/\n  [a-z][a-z0-9_-]*:\s*\n/);
  return next >= 0 ? text.slice(start, start + 1 + next) : text.slice(start);
}

/** Every job key under `jobs:`. */
function jobNames(text: string): string[] {
  const body = text.slice(text.search(/^jobs:\s*$/m));
  return [...body.matchAll(/^  ([a-z][a-z0-9_-]*):\s*$/gm)].map((m) => m[1]!);
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
    for (const [name, titles] of [
      ["publish", ["send them in dependency order"]],
      ["verify", ["npm answers with this version", "every tarball of this version answers", "a clean install from the registry"]],
    ] as const) {
      const text = job(yml, name);
      assert.match(text, /^    if: \$\{\{ inputs\.confirm == 'publish' \}\}$/m, `job "${name}" is not confined to confirm=publish`);
      for (const title of titles) {
        assert.ok(text.includes(`- name: ${title}`), `step "${title}" is not in the ${name} job`);
      }
    }
  });

  it("publishes the three packages in dependency order", () => {
    const send = namedStep(yml, "send them in dependency order");
    assert.match(send, new RegExp(`for p in ${PUBLISH_ORDER.join(" ")}; do`), "the publish loop is not inventory, proxy, body");
    // npm reads `release-tarballs/x.tgz` as a GitHub owner/repo spec and runs
    // git ls-remote on it; the 0.8.0 publish failed there. ./ makes it a file.
    assert.match(send, /npm publish "\.\/release-tarballs\/verax-ai-\$p-\$v\.tgz"/, "publish does not send the packed tarball as a ./ path");
  });

  it("only the publish job holds id-token, and it runs no repository or dependency code", () => {
    // A dependency that runs during the suite could otherwise mint a publish
    // credential. The publish job gets the tarballs and npm, nothing else.
    const holders = jobNames(yml).filter((name) => /^\s+id-token: write\s*$/m.test(job(yml, name)));
    assert.deepEqual(holders, ["publish"], `id-token: write is held by ${holders.join(", ") || "no job"}`);
    const publish = job(yml, "publish");
    for (const [pattern, what] of [
      [/actions\/checkout@/, "a checkout"],
      [/\bnpm ci\b/, "npm ci"],
      [/\bnpm install\b/, "npm install"],
      [/\bnpm test\b/, "npm test"],
      [/\bnpm run\b/, "npm run"],
      [/\bnpm pack\b/, "npm pack"],
      [/\bnpx\b/, "npx"],
    ] as const) {
      assert.doesNotMatch(publish, pattern, `the publish job runs ${what}`);
    }
    assert.match(namedStep(yml, "send them in dependency order"), /--ignore-scripts/, "publish runs the tarballs' scripts");
    assert.match(namedStep(yml, "the tarballs are the ones the build job hashed"), /sha256sum -c SHA256SUMS/, "the tarballs are not checked against the build job's hashes");
  });

  it("packs and keeps the tarballs before the suite runs", () => {
    const build = job(yml, "build");
    const pack = build.indexOf("- name: pack the three tarballs");
    const keep = build.indexOf("- name: keep the tarballs as an artifact");
    const suite = build.indexOf("- run: npm test");
    assert.ok(pack >= 0 && keep > pack && suite > keep, "the tarballs are not packed and kept before npm test");
    assert.match(namedStep(yml, "pack the three tarballs"), /sha256sum \.\/\*\.tgz > SHA256SUMS/, "the packed tarballs are not hashed");
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
