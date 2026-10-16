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
