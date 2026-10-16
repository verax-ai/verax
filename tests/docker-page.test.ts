import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (...p: string[]) => readFileSync(join(root, ...p), "utf8");

/**
 * The Docker Hub page is sent from docs/dockerhub.md. It describes the image
 * the Dockerfile builds, so the facts it states are held to the Dockerfile here.
 */
describe("Docker Hub page", () => {
  const page = read("docs", "dockerhub.md");
  const dockerfile = read("Dockerfile");

  it("names the base image, the user, the state directory and the bind the Dockerfile sets", () => {
    const base = /^FROM (node:[^@\s]+)/m.exec(dockerfile)?.[1];
    assert.ok(base, "Dockerfile has no node base image");
    assert.ok(page.includes(`\`${base}\``), `docs/dockerhub.md does not name ${base}`);
    const user = /^USER (\S+)$/m.exec(dockerfile)?.[1];
    assert.ok(user && page.includes(`Runs as the \`${user}\` user`), `docs/dockerhub.md does not name the user ${user}`);
    const state = /VERAX_STATE_DIR=(\S+)/.exec(dockerfile)?.[1];
    assert.ok(state && page.includes(`\`${state}\` (\`VERAX_STATE_DIR\`)`), `docs/dockerhub.md does not name ${state}`);
    const bind = /VERAX_BIND=(\S+)/.exec(dockerfile)?.[1];
    assert.ok(bind && page.includes(`\`${bind}\` (\`VERAX_BIND\`)`), `docs/dockerhub.md does not name ${bind}`);
  });

  it("runs the image with the settings the body refuses to start without", () => {
    const run = /```sh\n(docker volume create[\s\S]*?)```/.exec(page)?.[1] ?? "";
    assert.match(run, /-p 8787:8787 /, "the example does not publish the port the image listens on");
    for (const name of ["VERAX_ISSUER", "VERAX_JWKS_URL", "VERAX_AUDIENCE", "VERAX_POLICY_FILE"]) {
      assert.match(run, new RegExp(`-e ${name}=\\S`), `the example does not set ${name}`);
    }
    assert.match(run, /-e VERAX_TLS_TERMINATED=1 /, "a bind other than loopback needs VERAX_TLS_TERMINATED=1");
    assert.match(run, /-v verax-state:\/var\/lib\/verax /, "the example does not keep the ledger in a volume");
    assert.match(run, /\n {2}veraxai\/verax serve\n/, "the example does not start the body with serve");
  });

  it("is sent by the publish path only, with the token kept off command lines", () => {
    const yml = read(".github", "workflows", "docker.yml");
    const start = yml.indexOf("- name: Page text on Docker Hub");
    assert.ok(start >= 0, "docker.yml has no step that sends the page text");
    const step = yml.slice(start);
    assert.match(step, /if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.event\.inputs\.confirm == 'publish' \}\}/);
    assert.match(step, /readFileSync\("docs\/dockerhub\.md"/);
    assert.match(step, /readFileSync\("packages\/body\/package\.json"/);
    assert.match(step, /secret: process\.env\.DOCKERHUB_TOKEN/);
    assert.doesNotMatch(step, /\$DOCKERHUB_TOKEN|\$\{DOCKERHUB_TOKEN\}/, "the token is expanded into a command line");
  });
});
