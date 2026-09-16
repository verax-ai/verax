import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { latestRecord } from "../scripts/registry-record.ts";

const NAME = "io.github.verax-ai/verax";
const OFFICIAL = "io.modelcontextprotocol.registry/official";

// The shape the registry actually returned on 16 Sep 2026: the row wraps the
// server object. The first version of this reader looked for `name` on the row.
const WRAPPED = JSON.stringify({
  servers: [
    {
      server: { name: NAME, version: "0.1.0", description: "..." },
      _meta: { [OFFICIAL]: { isLatest: true, publishedAt: "2026-09-16T10:50:08Z" } },
    },
  ],
});

describe("reading the registry's answer", () => {
  it("finds the version in the wrapped row the registry returns", () => {
    const { found, why } = latestRecord(WRAPPED, NAME);
    assert.ok(found, why);
    assert.equal(found.version, "0.1.0");
    assert.equal(found.publishedAt, "2026-09-16T10:50:08Z");
  });

  it("reads a flat row too, so a shape change does not read as a missing record", () => {
    const flat = JSON.stringify({
      servers: [{ name: NAME, version: "0.2.0", _meta: { [OFFICIAL]: { isLatest: true } } }],
    });
    assert.equal(latestRecord(flat, NAME).found?.version, "0.2.0");
  });

  it("ignores rows for other servers", () => {
    const other = JSON.stringify({
      servers: [
        { server: { name: "io.github.someone/else", version: "9.9.9" }, _meta: { [OFFICIAL]: { isLatest: true } } },
      ],
    });
    const { found, why } = latestRecord(other, NAME);
    assert.equal(found, null);
    assert.match(why, /no row named/);
  });

  it("says an older row is not the latest instead of accepting it", () => {
    const superseded = JSON.stringify({
      servers: [{ server: { name: NAME, version: "0.1.0" }, _meta: { [OFFICIAL]: { isLatest: false } } }],
    });
    const { found, why } = latestRecord(superseded, NAME);
    assert.equal(found, null);
    assert.match(why, /none marked isLatest/);
  });
});
