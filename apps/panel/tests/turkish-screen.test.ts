import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { englishInterfaceLeftovers } from "./turkish-screen.ts";

describe("turkish screen leftovers", () => {
  it("lets a filled Turkish status sentence through", () => {
    assert.deepEqual(
      englishInterfaceLeftovers("Defterde 8 karar var.\nDefter kilidi: tutuluyor\nTanık: self 2"),
      [],
    );
  });

  it("flags held when the lock word bypasses the copy table", () => {
    assert.deepEqual(englishInterfaceLeftovers("Defter kilidi: held"), ["held"]);
  });
});
