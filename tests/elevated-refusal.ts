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
