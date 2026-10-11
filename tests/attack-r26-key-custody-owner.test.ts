import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { runDoctor } from "../packages/body/src/doctor.ts";
import { windowsFileOwner } from "../packages/body/src/install.ts";

/**
 * R26-10. `key-custody` was `ok` when one `open()` of the record key failed
 * with EACCES or EPERM. The check exists because an agent running as that
 * user can sign records as the body. A key file this user OWNS fails that
 * open after `chmod 000` (POSIX) or a deny entry (Windows), and the same user
 * restores read with one command, because an owner may always rewrite the
 * mode or the ACL. Doctor read green; the agent's shell was one `chmod` or
 * `icacls` away from the key.
 */

const windows = process.platform === "win32";
const me = userInfo().username;

function lockOut(key: string): boolean {
  if (windows) return spawnSync("icacls", [key, "/deny", `${me}:(R)`], { stdio: "ignore" }).status === 0;
  chmodSync(key, 0o000);
  return true;
}

function letIn(key: string): void {
  if (windows) spawnSync("icacls", [key, "/remove:d", me], { stdio: "ignore" });
  else chmodSync(key, 0o600);
}

function stateWithKey(): { dir: string; key: string } {
  const dir = mkdtempSync(join(tmpdir(), "verax-r26-10-"));
  const key = join(dir, "keys", "record.private.pem");
  mkdirSync(join(dir, "keys"));
  writeFileSync(key, "-----BEGIN PRIVATE KEY-----\nnot a real key\n-----END PRIVATE KEY-----\n", "utf8");
  return { dir, key };
}

function custodyOf(dir: string, keyOwner?: (path: string) => "self" | "other" | "unknown") {
  const checks = runDoctor({ VERAX_STATE_DIR: dir }, [], { elevated: () => false, ...(keyOwner ? { keyOwner } : {}) });
  const custody = checks.find((c) => c.id === "key-custody");
  assert.ok(custody, "no key-custody line");
  return custody;
}

/**
 * On Windows a file may be owned by a group. A user whose token holds that
 * group enabled has the owner's rights over the file, the same as an owning
 * user. The first version compared the owner with the user's own SID only and
 * read such a key as someone else's.
 */
describe("R26-10 the Windows owner reader", () => {
  const USER = "S-1-5-21-1-2-3-1001";
  const GROUP = "S-1-5-21-1-2-3-2002";
  const STRANGER = "S-1-5-21-9-9-9-500";

  function reader(lines: string[], status = 0) {
    return (argv: string[]) =>
      argv.some((a) => /whoami/i.test(a))
        ? { status: 0, stdout: `user name sid\n${USER}\n` }
        : { status, stdout: `${lines.join("\r\n")}\r\n` };
  }

  it("a key owned by a group this user holds is the user's own", () => {
    const got = windowsFileOwner("C:\\state\\keys\\record.private.pem", reader([`owner ${GROUP}`, `user ${USER}`, `group S-1-5-32-545`, `group ${GROUP}`]));
    assert.equal(got, "self");
  });

  it("a key owned by the user is the user's own", () => {
    const got = windowsFileOwner("C:\\k.pem", reader([`owner ${USER}`, `user ${USER}`, `group S-1-5-32-545`]));
    assert.equal(got, "self");
  });

  it("a key owned by an account or group this user does not hold is someone else's", () => {
    const got = windowsFileOwner("C:\\k.pem", reader([`owner ${STRANGER}`, `user ${USER}`, `group S-1-5-32-545`]));
    assert.equal(got, "other");
  });

  it("a refused security descriptor means the caller is not the owner", () => {
    assert.equal(windowsFileOwner("C:\\k.pem", reader(["VERAX-OWNER-DENIED"])), "other");
  });

  it("anything else is unknown, never someone else's", () => {
    assert.equal(windowsFileOwner("C:\\k.pem", reader([`owner ${STRANGER}`], 1)), "unknown");
    assert.equal(windowsFileOwner("C:\\k.pem", reader([`owner ${STRANGER}`])), "unknown", "no user line");
    assert.equal(windowsFileOwner("C:\\k.pem", reader([`user ${USER}`, `group ${GROUP}`])), "unknown", "no owner line");
    assert.equal(windowsFileOwner("C:\\k.pem", reader([])), "unknown", "empty output");
    assert.equal(
      windowsFileOwner("C:\\k.pem", () => {
        throw new Error("powershell is not there");
      }),
      "unknown",
    );
  });
});

describe("R26-10 key-custody and a key file this user owns", () => {
  it("is not ok while the user can give itself read again", (t) => {
    if (!windows && typeof process.getuid === "function" && process.getuid() === 0) {
      t.skip("root opens any file; the check is about a non-elevated user");
      return;
    }
    const { dir, key } = stateWithKey();
    let lockedOut = false;
    try {
      lockedOut = lockOut(key);
      assert.equal(lockedOut, true, "could not remove this user's read access for the test");
      const custody = custodyOf(dir);
      // What an agent's shell does next, as the same user, with no elevation.
      letIn(key);
      lockedOut = false;
      const readBack = readFileSync(key, "utf8").includes("BEGIN PRIVATE KEY");
      assert.equal(readBack, true, "the owner could not restore read; the premise of this test does not hold here");
      assert.equal(
        custody.level,
        "fail",
        `doctor said "${custody.detail}" for a key its own user then read after one ${windows ? "icacls /remove:d" : "chmod"}`,
      );
      assert.match(custody.detail, /owns/);
    } finally {
      if (lockedOut) letIn(key);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("stays ok for a key this user cannot read and does not own", (t) => {
    if (!windows && typeof process.getuid === "function" && process.getuid() === 0) {
      t.skip("root opens any file");
      return;
    }
    const { dir, key } = stateWithKey();
    let lockedOut = false;
    try {
      lockedOut = lockOut(key);
      const custody = custodyOf(dir, () => "other");
      assert.equal(custody.level, "ok", custody.detail);
    } finally {
      if (lockedOut) letIn(key);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("warns when the owner of an unreadable key could not be read", (t) => {
    if (!windows && typeof process.getuid === "function" && process.getuid() === 0) {
      t.skip("root opens any file");
      return;
    }
    const { dir, key } = stateWithKey();
    let lockedOut = false;
    try {
      lockedOut = lockOut(key);
      const custody = custodyOf(dir, () => "unknown");
      assert.equal(custody.level, "warn", custody.detail);
    } finally {
      if (lockedOut) letIn(key);
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
