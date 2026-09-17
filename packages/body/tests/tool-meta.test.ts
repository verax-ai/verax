import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { TOOL_META } from "../src/server.ts";
import { TOOL_NAMES } from "../src/wiring.ts";

// A brain reads these before it calls. A one-line description leaves it to
// guess the bounds, the side effects and the shape of the answer; this test
// keeps every tool and every parameter described, in the order the body
// serves them.

const MIN_TOOL_DESCRIPTION = 200;
const MIN_PARAM_DESCRIPTION = 40;

describe("tools/list describes every tool and every parameter", () => {
  it("names the tools the body serves, in the same order", () => {
    assert.deepEqual(
      TOOL_META.map((t) => t.name),
      [...TOOL_NAMES],
    );
  });

  for (const tool of TOOL_META) {
    it(`${tool.name}: says what it is for, what it answers, and what the gate may refuse`, () => {
      assert.equal(typeof tool.description, "string");
      assert.ok(
        tool.description.length >= MIN_TOOL_DESCRIPTION,
        `${tool.name} description is ${tool.description.length} chars, under ${MIN_TOOL_DESCRIPTION}`,
      );
      assert.match(tool.description, /Use it /, `${tool.name} does not say when to use it`);
      assert.match(tool.description, /Returns |answers /, `${tool.name} does not say what comes back`);
      assert.match(tool.description, /recorded|decision record|signed/, `${tool.name} does not say it is recorded`);
    });

    it(`${tool.name}: every parameter carries a description`, () => {
      const props = tool.inputSchema.properties as Record<string, { description?: unknown }>;
      for (const [name, schema] of Object.entries(props)) {
        assert.equal(typeof schema.description, "string", `${tool.name}.${name} has no description`);
        assert.ok(
          (schema.description as string).length >= MIN_PARAM_DESCRIPTION,
          `${tool.name}.${name} description is under ${MIN_PARAM_DESCRIPTION} chars`,
        );
      }
      const required = (tool.inputSchema as { required?: readonly string[] }).required ?? [];
      for (const name of required) {
        assert.ok(name in props, `${tool.name} requires ${name} but does not describe it`);
      }
    });
  }

  it("the tools that can be held describe _ref the same way", () => {
    const withRef = TOOL_META.filter((t) => "_ref" in t.inputSchema.properties);
    assert.deepEqual(
      withRef.map((t) => t.name),
      ["message.send", "spend"],
    );
    const texts = new Set(
      withRef.map((t) => (t.inputSchema.properties as Record<string, { description: string }>)._ref.description),
    );
    assert.equal(texts.size, 1);
    assert.match([...texts][0], /allowed:<ref>/);
    assert.match([...texts][0], /denied:ref-reuse/);
  });
});
