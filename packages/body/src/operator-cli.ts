import { lstatSync } from "node:fs";
import { resolve } from "node:path";

import {
  credentialsPath,
  readCredentials,
  readCredentialsAt,
  readRemoved,
  removeCredential,
  removedPath,
} from "./operator-credentials.ts";
import { beginPairing } from "./operator-pairing.ts";

type Seen = { uid: number; gid: number; isDirectory: boolean };

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
};

export type PairingWriter =
  | { kind: "as-is"; stateDir: string }
  | { kind: "become"; stateDir: string; uid: number; gid: number }
  | { kind: "refuse"; reason: string };

/**
 * As whom the pairing code is written. An installed body runs as its own
 * account and owns its state directory, and root asking for a code is the
 * usual case there. A file root wrote would be root's, which that account
 * cannot read; and a write by root into a directory another account owns is
 * a write that account can aim somewhere else. So for such a directory root
 * gives up being root first and writes as its owner. A link, a missing
 * directory, a file, or a directory whose group is root's is refused: root
 * makes no state directory here and keeps no part of itself.
 *
 * A directory that is root's own is written as root, as it always was. There
 * is no other account to become, and a root-run body whose state someone else
 * can replace is theirs already, whoever writes the code.
 */
export function pairingWriter(stateDir: string, sys: Pick<OperatorSys, "platform" | "getuid" | "look">): PairingWriter {
  if (sys.platform === "win32" || sys.getuid?.() !== 0) return { kind: "as-is", stateDir };
  // Resolved first: a link with a slash after it is looked through, and must not be.
  const dir = resolve(stateDir);
  const seen = sys.look(dir);
  if (!seen) return { kind: "refuse", reason: `state-dir-missing:${dir}` };
  if (!seen.isDirectory) return { kind: "refuse", reason: `state-dir-not-a-directory:${dir}` };
  if (seen.uid === 0) return { kind: "as-is", stateDir: dir };
  if (seen.gid === 0) return { kind: "refuse", reason: `state-dir-group-is-roots:${dir}` };
  return { kind: "become", stateDir: dir, uid: seen.uid, gid: seen.gid };
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

/** What is at the path itself. A link is a link here, whatever it points at. */
export function lookWithoutFollowing(path: string): Seen | null {
  try {
    const st = lstatSync(path);
    return { uid: st.uid, gid: st.gid, isDirectory: st.isDirectory() };
  } catch {
    return null;
  }
}

const realSys: OperatorSys = {
  platform: process.platform,
  getuid: process.getuid?.bind(process),
  getgid: process.getgid?.bind(process),
  setgroups: process.setgroups?.bind(process),
  setgid: process.setgid?.bind(process),
  setuid: process.setuid?.bind(process),
  look: lookWithoutFollowing,
};

const USAGE =
  "verax operator enroll --state <dir>\n" +
  "verax operator list --state <dir>\n" +
  "verax operator remove --state <dir> --id <passkey id>\n";

export async function runOperator(argv: string[], sys: OperatorSys = realSys): Promise<number> {
  const verb = argv[1];
  if (verb !== "enroll" && verb !== "list" && verb !== "remove") {
    process.stderr.write(USAGE);
    return 78;
  }
  let stateDir = "";
  let id = "";
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === "--state") {
      stateDir = argv[++i] ?? "";
      continue;
    }
    if (argv[i] === "--id" && verb === "remove") {
      id = argv[++i] ?? "";
      continue;
    }
    if (argv[i]?.startsWith("-")) {
      process.stderr.write(`flag-unknown:${argv[i]}\n`);
      return 78;
    }
  }
  if (!stateDir || (verb === "remove" && !id)) {
    process.stderr.write(USAGE);
    return 78;
  }
  // All three go in as the pairing code does. What `remove` writes the body
  // must be able to read, and nothing here is read or written as root in a
  // directory another account owns.
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
  if (verb === "enroll") {
    const { code } = beginPairing(writer.stateDir);
    process.stdout.write(`${code}\n`);
    return 0;
  }
  if (verb === "list") {
    const removed = readRemoved(writer.stateDir);
    if (!removed) {
      process.stderr.write(`removed-list-unreadable:${removedPath(writer.stateDir)}\n`);
      return 78;
    }
    // In the order they were enrolled: the file is only ever added to at its end.
    for (const row of readCredentialsAt(credentialsPath(writer.stateDir))) {
      process.stdout.write(`${row.id}\t${row.sub}\t${removed.has(row.id) ? "removed" : "in use"}\n`);
    }
    return 0;
  }
  const done = removeCredential(writer.stateDir, id);
  if (done === "unreadable") {
    process.stderr.write(`removed-list-unreadable:${removedPath(writer.stateDir)}\n`);
    return 78;
  }
  if (done === "unknown") {
    process.stderr.write("passkey-unknown\n");
    return 78;
  }
  process.stdout.write(`${done}\n`);
  if (readCredentials(writer.stateDir).length === 0) {
    process.stdout.write("no passkey is left in use: verax operator enroll --state <dir> gives a code for a new one\n");
  }
  return 0;
}
