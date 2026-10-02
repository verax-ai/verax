// POSIX extended ACL. Parsers run on every platform. Live grants run on macOS and Linux CI.

import { spawnSync } from "node:child_process";
import { strict as assert } from "node:assert";
import { chmodSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { desktopCodeRefusal, runDesktop, type DesktopSignalHost } from "../packages/body/src/desktop.ts";
import {
  defaultExec,
  posixAclWriterDetail,
  posixAclWriters,
  posixCodeDirectoryDetail,
  systemToolPath,
  trustTargets,
  type ExecResult,
  type ToolExec,
} from "../packages/body/src/install.ts";

function recorded(script: (argv: string[]) => ExecResult): { exec: ToolExec; calls: string[][] } {
  const calls: string[][] = [];
  const exec: ToolExec = (argv) => {
    calls.push([...argv]);
    return script(argv);
  };
  return { exec, calls };
}

const darwinListing = [
  "-rw-r--r--  1 root  staff  0 Oct  2 12:00 /tmp/mallory",
  " 0: user:mallory allow add_file,write",
  "-rw-r--r--  1 root  staff  0 Oct  2 12:00 /tmp/deny",
  " 0: group:everyone deny delete",
  "-rw-r--r--  1 root  staff  0 Oct  2 12:00 /tmp/admin",
  " 0: group:admin allow write",
  "-rw-r--r--  1 mallory  staff  0 Oct  2 12:00 /tmp/owner",
  " 0: user:mallory allow write",
  "-rw-r--r--  1 root  staff  0 Oct  2 12:00 /tmp/inherit",
  " 0: user:ada allow write inherited",
].join("\n");

const linuxListing = [
  "drwxr-xr-x+ 2 root root 4096 Oct 2 12:00 /tmp/open",
  "drwxr-xr-x+ 2 root root 4096 Oct 2 12:00 /tmp/masked",
  "drwxr-xr-x  2 root root 4096 Oct 2 12:00 /tmp/plain",
].join("\n");

const linuxGetfacl = [
  "user::rwx",
  "user:mallory:rw-",
  "group::r-x",
  "mask::rwx",
  "other::r-x",
  "",
  "user::rwx",
  "user:mallory:rw-",
  "group::r-x",
  "mask::r-x",
  "other::r-x",
].join("\n");

function quietSignals(): DesktopSignalHost {
  const on = new Map<string, Set<() => void>>();
  const bucket = (event: string): Set<() => void> => {
    let set = on.get(event);
    if (!set) {
      set = new Set();
      on.set(event, set);
    }
    return set;
  };
  return {
    once(event, fn) {
      bucket(event).add(fn);
    },
    on(event, fn) {
      bucket(event).add(fn);
    },
    removeListener(event, fn) {
      on.get(event)?.delete(fn);
    },
    exit() {},
    platform: process.platform,
  };
}

/** Null when the grant is in place. Otherwise the skip reason. */
function grantNobodyWrite(dir: string): string | null {
  if (process.platform === "darwin") {
    const ran = spawnSync("/bin/chmod", ["+a", "user:nobody allow write", dir], { encoding: "utf8" });
    if (ran.error || (ran.status ?? 1) !== 0) {
      return (ran.stderr || ran.error?.message || "chmod +a failed").trim();
    }
    return null;
  }
  const ran = spawnSync("setfacl", ["-m", "u:nobody:rwx", dir], { encoding: "utf8" });
  if (ran.error || (ran.status ?? 1) !== 0) {
    return (ran.stderr || ran.error?.message || "setfacl is not installed").trim();
  }
  return null;
}

describe("attack R25 POSIX extended ACL", () => {
  it("parses one macOS ls -lde: mallory and an inherited write are refused, everyone deny, admin, and the owner are not", () => {
    const paths = ["/tmp/mallory", "/tmp/deny", "/tmp/admin", "/tmp/owner", "/tmp/inherit"];
    const { exec, calls } = recorded(() => ({ status: 0, stdout: `${darwinListing}\n`, stderr: "" }));
    const map = posixAclWriters(paths, "darwin", exec);
    assert.equal(calls.length, 1);
    assert.equal(calls[0]![0], systemToolPath("ls", "darwin"));
    assert.deepEqual(calls[0]!.slice(1, 3), ["-lde", "--"]);
    assert.deepEqual(calls[0]!.slice(3), paths);
    assert.deepEqual(map.get("/tmp/mallory"), ["user:mallory"]);
    assert.deepEqual(map.get("/tmp/deny"), []);
    assert.deepEqual(map.get("/tmp/admin"), []);
    assert.deepEqual(map.get("/tmp/owner"), []);
    assert.deepEqual(map.get("/tmp/inherit"), ["user:ada"]);
  });

  it("parses one Linux ls and one getfacl: a named user write is refused only when the mask allows it", () => {
    const paths = ["/tmp/open", "/tmp/masked", "/tmp/plain"];
    const { exec, calls } = recorded((argv) => {
      if ((argv[0] ?? "").endsWith("getfacl")) return { status: 0, stdout: `${linuxGetfacl}\n`, stderr: "" };
      return { status: 0, stdout: `${linuxListing}\n`, stderr: "" };
    });
    const map = posixAclWriters(paths, "linux", exec);
    assert.equal(calls.length, 2);
    assert.equal(calls[0]![0], systemToolPath("ls", "linux"));
    assert.deepEqual(calls[0]!.slice(1, 3), ["-ld", "--"]);
    assert.deepEqual(calls[0]!.slice(3), paths);
    assert.equal(calls[1]![0], systemToolPath("getfacl", "linux"));
    assert.deepEqual(calls[1]!.slice(1, 3), ["-cp", "--"]);
    assert.deepEqual(calls[1]!.slice(3), ["/tmp/open", "/tmp/masked"]);
    assert.deepEqual(map.get("/tmp/open"), ["user:mallory"]);
    assert.deepEqual(map.get("/tmp/masked"), []);
    assert.deepEqual(map.get("/tmp/plain"), []);
  });

  it("does not run getfacl when ls shows no extended ACL", () => {
    const { exec, calls } = recorded(() => ({ status: 0, stdout: "drwxr-xr-x 2 root root 4096 Oct 2 12:00 /tmp/plain\n", stderr: "" }));
    const map = posixAclWriters(["/tmp/plain"], "linux", exec);
    assert.equal(calls.length, 1);
    assert.deepEqual(map.get("/tmp/plain"), []);
  });

  it("fails closed when ls shows + and getfacl cannot be run", () => {
    const { exec, calls } = recorded((argv) => {
      if ((argv[0] ?? "").endsWith("getfacl")) return { status: null, stdout: "", stderr: "" };
      return { status: 0, stdout: "drwxr-xr-x+ 2 root root 4096 Oct 2 12:00 /tmp/open\n", stderr: "" };
    });
    const map = posixAclWriters(["/tmp/open"], "linux", exec);
    assert.equal(calls.length, 2);
    assert.equal(map.get("/tmp/open"), "unreadable");
    assert.equal(posixAclWriterDetail("unreadable"), "install acl or remove the ACL");
    assert.equal(posixAclWriterDetail(["user:mallory"]), "user:mallory");
    assert.equal(posixAclWriterDetail([]), null);
  });

  it("refuses a root-owned mode-safe path when the ACL map names a writer or cannot be read", () => {
    const dir = "/tmp/verax-acl-not-on-disk";
    const read = () => ({ uid: 0, mode: 0o755, symlink: false as const });
    const safe = new Map<string, string[] | "unreadable">(
      trustTargets(dir, "linux").map((entry) => [entry.path, []]),
    );
    assert.equal(posixCodeDirectoryDetail(dir, "linux", read, safe), false);
    const writers = new Map(safe);
    writers.set(dir, ["user:mallory"]);
    assert.match(String(posixCodeDirectoryDetail(dir, "linux", read, writers)), /\/tmp\/verax-acl-not-on-disk ACL user:mallory/);
    const closed = new Map(safe);
    closed.set(dir, "unreadable");
    assert.match(String(posixCodeDirectoryDetail(dir, "linux", read, closed)), /install acl or remove the ACL/);
  });

  it("refuses a live nobody write ACL on desktop and on the code check", async (t) => {
    if (process.platform !== "darwin" && process.platform !== "linux") {
      t.skip("POSIX ACL");
      return;
    }
    const dir = realpathSync.native(mkdtempSync(join(tmpdir(), "verax-acl-")));
    const file = join(dir, "dev-issuer.mjs");
    writeFileSync(file, "");
    chmodSync(file, 0o644);
    chmodSync(dir, 0o700);
    const err: string[] = [];
    try {
      const grant = grantNobodyWrite(dir);
      if (grant) {
        t.skip(process.platform === "linux" ? `setfacl unavailable: ${grant}` : `chmod +a failed: ${grant}`);
        return;
      }
      const platform = process.platform === "darwin" ? "darwin" : "linux";
      // On Linux the ACL mask is the group bits, so a named write sets group w
      // and the mode check refuses first (mode 770). macOS keeps ACLs out of
      // st_mode, so there the refusal can only come from the ACL.
      const why = platform === "darwin" ? /user:nobody/ : /user:nobody|mode 7[0-7]0|replaced by another user|writable by others/;
      const refused = desktopCodeRefusal([file], process.platform);
      assert.equal(refused?.path, dir);
      assert.match(refused?.detail ?? "", why);
      const targets = trustTargets(file, platform);
      const acls = posixAclWriters(targets.map((entry) => entry.path), platform, defaultExec);
      // The live listing (ls -lde, or ls -ld and getfacl) names exactly that writer.
      assert.deepEqual(acls.get(dir), ["user:nobody"]);
      const detail = posixCodeDirectoryDetail(
        file,
        platform,
        () => ({ uid: 0, mode: 0o755, symlink: false }),
        acls,
      );
      assert.match(String(detail), /user:nobody/);
      const code = await runDesktop(
        { stateDir: dir, issuerPort: 18765, bodyPort: 18766, panelPort: 18767, browser: "no-browser" },
        (line) => err.push(line),
        {
          readyMs: 50,
          signals: quietSignals(),
          spawn: () => {
            throw new Error("spawned");
          },
        },
      );
      assert.equal(code, 1, err.join(""));
      assert.match(err.join(""), /desktop-dir-refused/);
      assert.match(err.join(""), why);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
