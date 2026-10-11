import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { releaseProblems, statusMatrixVersion, type ReleaseFacts } from "../scripts/release-facts.ts";

const SHA = "7d7ca5117b313bbf1d4b7f27c07f91b80e2b6f79";

function agreed(): ReleaseFacts {
  const packages = { "@verax-ai/body": "0.4.8", "@verax-ai/proxy": "0.4.8", "@verax-ai/inventory": "0.4.8" };
  return {
    version: "0.4.8",
    packages,
    npmLatest: { ...packages },
    releaseCommit: SHA,
    platformsSha: SHA,
    statusMatrixVersion: "0.4.8",
    dockerVersionDigest: "sha256:b0d5",
    dockerLatestDigest: "sha256:b0d5",
    zenodoLatestVersion: "0.4.8",
    registryLatestVersion: "0.4.8",
  };
}

describe("release facts", () => {
  it("passes when every place names the version", () => {
    assert.deepEqual(releaseProblems(agreed()), []);
  });

  it("names a Docker Hub tag that was never pushed (0.4.8, 11 October 2026)", () => {
    const f = agreed();
    f.dockerVersionDigest = null;
    f.dockerLatestDigest = "sha256:9e2e";
    assert.deepEqual(releaseProblems(f), ["Docker Hub has no veraxai/verax:0.4.8"]);
  });

  it("names latest left on the previous image", () => {
    const f = agreed();
    f.dockerLatestDigest = "sha256:9e2e";
    assert.deepEqual(releaseProblems(f), ["Docker Hub veraxai/verax:latest is not the 0.4.8 image"]);
  });

  it("names a Zenodo archive that stayed on the previous version", () => {
    const f = agreed();
    f.zenodoLatestVersion = "0.4.7";
    assert.deepEqual(releaseProblems(f), ["Zenodo's newest Verax record is 0.4.7, not 0.4.8"]);
  });

  it("names a platform table generated for another commit", () => {
    const f = agreed();
    f.platformsSha = "5c50e0451dbbd2a3881a22a9f2a3d95dcbd881fd";
    assert.deepEqual(releaseProblems(f), ["docs/platforms.json is for 5c50e04, v0.4.8 is 7d7ca51"]);
  });

  it("names a missing tag, a stale matrix, npm and the registry", () => {
    const f = agreed();
    f.releaseCommit = null;
    f.statusMatrixVersion = "0.4.7";
    f.npmLatest["@verax-ai/proxy"] = "0.4.7";
    f.registryLatestVersion = null;
    assert.deepEqual(releaseProblems(f), [
      "npm latest for @verax-ai/proxy is 0.4.7, the tree has 0.4.8",
      "no tag v0.4.8",
      "docs/STATUS.md capability matrix is for 0.4.7, not 0.4.8",
      "the MCP registry marks nothing as latest, not 0.4.8",
    ]);
  });

  it("names a package left behind in the tree", () => {
    const f = agreed();
    f.packages["@verax-ai/inventory"] = "0.4.7";
    f.npmLatest["@verax-ai/inventory"] = "0.4.7";
    assert.deepEqual(releaseProblems(f), ["@verax-ai/inventory is 0.4.7 in the tree, body is 0.4.8"]);
  });

  it("reads the capability matrix heading", () => {
    assert.equal(statusMatrixVersion("# Status\n\n## Capability matrix — 0.4.8\n"), "0.4.8");
    assert.equal(statusMatrixVersion("## Capability matrix\n"), null);
  });
});
