// A temp directory only its owner can write. `verax desktop` refuses an
// existing directory others could write, and a Windows TEMP can carry
// inherited write entries for other principals (security software,
// AppContainer capabilities), so desktop tests start from an owner-only one.

import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { restrictToOwnerWin32 } from "../packages/body/src/install.ts";

export function privateTempDir(prefix: string): string {
  const dir = realpathSync.native(mkdtempSync(join(tmpdir(), prefix)));
  if (process.platform === "win32") restrictToOwnerWin32(dir, undefined, true);
  return dir;
}
