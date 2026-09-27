import { strict as assert } from "node:assert";

import { defaultElevated } from "../packages/body/src/install.ts";

/** True when this process would be treated as Administrator or root. */
export const elevatedRunner = defaultElevated();

/**
 * An elevated child of this checkout is refused before the command runs.
 * Callers that are not elevated get false and keep their own assertion.
 */
export function refusedAsElevated(code: number | null, stderr: string): boolean {
  if (!elevatedRunner) return false;
  assert.equal(code, 78, stderr);
  assert.match(stderr, /the verax code at .+ can be changed by/);
  return true;
}

/**
 * A test that needs a child of this checkout's CLI to run cannot do so on an elevated runner:
 * the child is refused before the command (R15-1). The refusal itself is tested in attack-r15.
 */
export function skipIfElevated(t: { skip: (message?: string) => void }): boolean {
  if (!elevatedRunner) return false;
  t.skip("elevated runner: the CLI refuses this checkout's code, which the user can change");
  return true;
}
