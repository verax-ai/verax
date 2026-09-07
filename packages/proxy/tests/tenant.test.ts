import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { sha256Canonical } from "../src/hash.ts";
import { tenantKey } from "../src/tenant.ts";

describe("S4 tenant key", () => {
  it("hashes { iss, sub } and never an aud field", () => {
    const key = tenantKey({ brain: "alice", iss: "https://issuer-a.example" });
    assert.equal(key, sha256Canonical({ iss: "https://issuer-a.example", sub: "alice" }));
    assert.equal(key.includes("aud"), false);
    const again = tenantKey({ brain: "alice", iss: "https://issuer-a.example" });
    assert.equal(again, key);
  });

  it("same iss+sub stay equal when a tenant/org claim is absent", () => {
    const a = tenantKey({ brain: "alice", iss: "https://issuer-a.example" });
    const b = tenantKey({ brain: "alice", iss: "https://issuer-a.example" });
    assert.equal(a, b);
  });

  it("different sub or iss, or a tenant claim, change the key", () => {
    const base = tenantKey({ brain: "alice", iss: "https://issuer-a.example" });
    assert.notEqual(base, tenantKey({ brain: "bob", iss: "https://issuer-a.example" }));
    assert.notEqual(base, tenantKey({ brain: "alice", iss: "https://issuer-b.example" }));
    assert.notEqual(
      base,
      tenantKey({ brain: "alice", iss: "https://issuer-a.example", tenant: "org-1" }),
    );
  });
});
