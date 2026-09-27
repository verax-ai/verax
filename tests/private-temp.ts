// A temp directory only its owner can write. `verax desktop` refuses an
// existing directory others could write, and a Windows TEMP can carry
// inherited write entries for other principals (security software,
// AppContainer capabilities), so desktop tests start from an owner-only one.
// The desktop also refuses a directory whose ancestor another principal can
// replace, and such a TEMP is that ancestor: on Windows the base is a folder
// under the profile directory instead, which carries the profile's owner-only
// ACL. Tests that start the CLI as a child cannot inject an ancestor hook.

import { mkdirSync, mkdtempSync, realpathSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

import { restrictToOwnerWin32 } from "../packages/body/src/install.ts";

function tempBase(): string {
  if (process.platform !== "win32") return tmpdir();
  const base = join(homedir(), ".verax-test-tmp");
  mkdirSync(base, { recursive: true });
  return base;
}

export function privateTempDir(prefix: string): string {
  const dir = realpathSync.native(mkdtempSync(join(tempBase(), prefix)));
  if (process.platform === "win32") restrictToOwnerWin32(dir, undefined, true);
  return dir;
}

/**
 * Ancestor SDDL the installer's ancestor mask accepts (owner SYSTEM, full control
 * for SYSTEM and Administrators only). Spread into `runDesktop` on Windows when
 * the test is not about ancestors: a TEMP parent can carry a replace right, and
 * that is a different assertion.
 */
export function desktopAncestorDaclHook(): { windowsAncestorDacl?: (dir: string) => string } {
  if (process.platform !== "win32") return {};
  return { windowsAncestorDacl: () => "O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)" };
}
