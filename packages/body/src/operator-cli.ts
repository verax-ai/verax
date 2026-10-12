import { lstatSync, realpathSync } from "node:fs";
import { dirname } from "node:path";

import { beginPairing } from "./operator-pairing.ts";

type Seen = { uid: number; gid: number; mode: number; isDirectory: boolean };

/** What `runOperator` asks of the process and the disk. Tests stand in for it. */
export type OperatorSys = {
  platform: NodeJS.Platform;
  getuid?: () => number;
  getgid?: () => number;
  setgroups?: (groups: number[]) => void;
  setgid?: (gid: number) => void;
  setuid?: (uid: number) => void;
  /** lstat: a link is seen as a link, not as what it points at. Null when there is nothing there. */
  look: (path: string) => Seen | null;
  real: (path: string) => string | null;
};

export type PairingWriter =
  | { kind: "as-is"; stateDir: string }
  | { kind: "become"; stateDir: string; uid: number; gid: number }
  | { kind: "refuse"; reason: string };

/**
 * As whom the pairing code is written. An installed body runs as its own
 * account and owns its state directory, and root asking for a code is the
 * usual case there. A file root wrote would be root's, which that account
 * cannot read; and a write by root into a place another account controls is a
 * write that account can aim somewhere else. So root writes only in two ways.
 * Into a directory another account owns, it gives up being root first and
 * writes as that owner. Into a directory of its own, it writes as root, and
 * only when every directory above is root's too and nobody else can change
 * it. A link, a missing directory or anything else is refused: root does not
 * make a state directory here.
 */
export function pairingWriter(
  stateDir: string,
  sys: Pick<OperatorSys, "platform" | "getuid" | "look" | "real">,
): PairingWriter {
  if (sys.platform === "win32" || sys.getuid?.() !== 0) return { kind: "as-is", stateDir };
  const seen = sys.look(stateDir);
  if (!seen) return { kind: "refuse", reason: `state-dir-missing:${stateDir}` };
  if (!seen.isDirectory) return { kind: "refuse", reason: `state-dir-not-a-directory:${stateDir}` };
  if (seen.uid !== 0) return { kind: "become", stateDir, uid: seen.uid, gid: seen.gid };
  const real = sys.real(stateDir);
  if (!real) return { kind: "refuse", reason: `state-dir-missing:${stateDir}` };
  for (let at = real; ; at = dirname(at)) {
    const dir = sys.look(at);
    // Group- or other-writable is still root's when the sticky bit keeps others from renaming what is in it.
    const othersCanChange = dir ? (dir.mode & 0o022) !== 0 && (dir.mode & 0o1000) === 0 : true;
    if (!dir || !dir.isDirectory || dir.uid !== 0 || othersCanChange) {
      return { kind: "refuse", reason: `state-dir-not-roots-alone:${at}` };
    }
    if (dirname(at) === at) break;
  }
  return { kind: "as-is", stateDir: real };
}

/** Groups first, then the group, then the user: after the last one there is no way back. Null when it held. */
export function becomeOwner(sys: OperatorSys, uid: number, gid: number): string | null {
  if (!sys.setgroups || !sys.setgid || !sys.setuid || !sys.getuid || !sys.getgid) return "cannot-change-account";
  try {
    sys.setgroups([gid]);
    sys.setgid(gid);
    sys.setuid(uid);
  } catch {
    return "cannot-change-account";
  }
  return sys.getuid() === uid && sys.getgid() === gid ? null : "account-did-not-change";
}

const realSys: OperatorSys = {
  platform: process.platform,
  getuid: process.getuid?.bind(process),
  getgid: process.getgid?.bind(process),
  setgroups: process.setgroups?.bind(process),
  setgid: process.setgid?.bind(process),
  setuid: process.setuid?.bind(process),
  look: (path) => {
    try {
      const st = lstatSync(path);
      return { uid: st.uid, gid: st.gid, mode: st.mode, isDirectory: st.isDirectory() };
    } catch {
      return null;
    }
  },
  real: (path) => {
    try {
      return realpathSync(path);
    } catch {
      return null;
    }
  },
};

export async function runOperator(argv: string[], sys: OperatorSys = realSys): Promise<number> {
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
  const writer = pairingWriter(stateDir, sys);
  if (writer.kind === "refuse") {
    process.stderr.write(`${writer.reason}\n`);
    return 78;
  }
  if (writer.kind === "become") {
    const failed = becomeOwner(sys, writer.uid, writer.gid);
    if (failed) {
      // Nothing has been written, and nothing will be as root.
      process.stderr.write(`${failed}\n`);
      return 78;
    }
  }
  const { code } = beginPairing(writer.stateDir);
  process.stdout.write(`${code}\n`);
  return 0;
}
