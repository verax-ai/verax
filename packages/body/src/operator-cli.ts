import { lstatSync } from "node:fs";

import { beginPairing } from "./operator-pairing.ts";

/**
 * Whose file the pairing code should be. An installed body runs as its own
 * account and owns its state directory; root asking for a code is the usual
 * case there. A file root wrote would be root's, which that account cannot
 * read, and a write by root into a directory another account owns is a write
 * that account can aim somewhere else. So root gives up being root first and
 * writes as the directory's owner. Null when there is nothing to become:
 * Windows, a caller who is not root, a directory root owns, or none yet.
 */
export function stateOwnerToBecome(
  platform: NodeJS.Platform,
  uid: number | undefined,
  owner: { uid: number; gid: number; isDirectory: boolean } | null,
): { uid: number; gid: number } | null {
  if (platform === "win32" || uid !== 0 || !owner || !owner.isDirectory || owner.uid === 0) return null;
  return { uid: owner.uid, gid: owner.gid };
}

function stateOwner(stateDir: string): { uid: number; gid: number; isDirectory: boolean } | null {
  try {
    // lstat: a link where the state directory should be is not followed.
    const st = lstatSync(stateDir);
    return { uid: st.uid, gid: st.gid, isDirectory: st.isDirectory() };
  } catch {
    return null;
  }
}

export async function runOperator(argv: string[]): Promise<number> {
  if (argv[1] !== "enroll") {
    process.stderr.write("verax operator enroll --state <dir>\n");
    return 78;
  }
  let stateDir = "";
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === "--state") {
      stateDir = argv[++i] ?? "";
      continue;
    }
    if (argv[i]?.startsWith("-")) {
      process.stderr.write(`flag-unknown:${argv[i]}\n`);
      return 78;
    }
  }
  if (!stateDir) {
    process.stderr.write("verax operator enroll --state <dir>\n");
    return 78;
  }
  const become = stateOwnerToBecome(process.platform, process.getuid?.(), stateOwner(stateDir));
  if (become) {
    // Groups first, then the group, then the user: after the last one there is no way back.
    process.setgroups?.([become.gid]);
    process.setgid?.(become.gid);
    process.setuid?.(become.uid);
  }
  const { code } = beginPairing(stateDir);
  process.stdout.write(`${code}\n`);
  return 0;
}
