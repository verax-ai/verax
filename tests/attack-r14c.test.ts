// Install-root ancestors. On 1933163 each `it` fails.

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { planInstall, planUninstall, posixCodeDirectoryDetail } from "../packages/body/src/install.ts";

const linuxEnv = {
  SUDO_USER: "runner",
  SUDO_UID: "1000",
  SUDO_GID: "1000",
  VERAX_INVOKING_HOME: "/home/runner",
};

const darwinEnv = {
  SUDO_USER: "runner",
  SUDO_UID: "501",
  SUDO_GID: "20",
  VERAX_INVOKING_HOME: "/Users/runner",
};

const linuxBase = {
  port: 8801,
  days: 30,
  force: false,
  execPath: "/usr/bin/node",
  bodyVersion: "0.3.0",
  npmCli: "/usr/lib/node_modules/npm/bin/npm-cli.js",
  stateExists: false,
};

const darwinBase = {
  port: 8801,
  days: 30,
  force: false,
  execPath: "/usr/bin/node",
  bodyVersion: "0.3.0",
  npmCli: "/usr/lib/node_modules/npm/bin/npm-cli.js",
  stateExists: false,
  invokingIds: { uid: 501, gid: 20 },
};

type Stat = { uid: number; mode: number };

/** Every ancestor is root-owned 0755 except the paths named here. Nothing is lstat'd. */
function injected(overrides: Record<string, Stat>): (dir: string) => Stat {
  return (dir) => overrides[dir] ?? { uid: 0, mode: 0o755 };
}

function refusal(dir: string, uid: number, mode: number): string {
  return `refusing: ${dir} can be changed by other users (owner uid ${uid}, mode ${mode.toString(8)}); the service code under it could be replaced\n`;
}

describe("attack R14c", () => {
  it("Linux install refuses a world-writable or non-root ancestor and accepts sticky 01777 and 0755", () => {
    const open = planInstall("linux", linuxEnv, { ...linuxBase, ancestorStat: injected({ "/opt": { uid: 0, mode: 0o777 } }) });
    assert.equal(open.ok, false);
    if (!open.ok) {
      assert.equal(open.code, 78);
      assert.equal(open.message, refusal("/opt", 0, 0o777));
    }

    const sticky = planInstall("linux", linuxEnv, { ...linuxBase, ancestorStat: injected({ "/opt": { uid: 0, mode: 0o1777 } }) });
    assert.equal(sticky.ok, true, sticky.ok ? "" : sticky.message);

    const normal = planInstall("linux", linuxEnv, { ...linuxBase, ancestorStat: injected({ "/opt": { uid: 0, mode: 0o755 } }) });
    assert.equal(normal.ok, true, normal.ok ? "" : normal.message);

    const owned = planInstall("linux", linuxEnv, { ...linuxBase, ancestorStat: injected({ "/opt": { uid: 1000, mode: 0o755 } }) });
    assert.equal(owned.ok, false);
    if (!owned.ok) {
      assert.equal(owned.code, 78);
      assert.equal(owned.message, refusal("/opt", 1000, 0o755));
    }

    const unit = planInstall("linux", linuxEnv, {
      ...linuxBase,
      ancestorStat: injected({ "/etc/systemd/system": { uid: 0, mode: 0o777 } }),
    });
    assert.equal(unit.ok, false);
    if (!unit.ok) assert.equal(unit.message, refusal("/etc/systemd/system", 0, 0o777));

    const stateParent = planInstall("linux", linuxEnv, {
      ...linuxBase,
      ancestorStat: injected({ "/var/lib": { uid: 0, mode: 0o777 } }),
    });
    assert.equal(stateParent.ok, false);
    if (!stateParent.ok) assert.equal(stateParent.message, refusal("/var/lib", 0, 0o777));

    const removed = planUninstall("linux", linuxEnv, { keepState: false });
    assert.equal(removed.ok, true, removed.ok ? "" : removed.message);
  });

  it("macOS install refuses a world-writable or non-root ancestor and accepts sticky 01777 and 0755", () => {
    const open = planInstall("darwin", darwinEnv, { ...darwinBase, ancestorStat: injected({ "/Library": { uid: 0, mode: 0o777 } }) });
    assert.equal(open.ok, false);
    if (!open.ok) {
      assert.equal(open.code, 78);
      assert.equal(open.message, refusal("/Library", 0, 0o777));
    }

    const sticky = planInstall("darwin", darwinEnv, { ...darwinBase, ancestorStat: injected({ "/Library": { uid: 0, mode: 0o1777 } }) });
    assert.equal(sticky.ok, true, sticky.ok ? "" : sticky.message);

    const normal = planInstall("darwin", darwinEnv, { ...darwinBase, ancestorStat: injected({ "/Library": { uid: 0, mode: 0o755 } }) });
    assert.equal(normal.ok, true, normal.ok ? "" : normal.message);

    const owned = planInstall("darwin", darwinEnv, { ...darwinBase, ancestorStat: injected({ "/Library": { uid: 1000, mode: 0o755 } }) });
    assert.equal(owned.ok, false);
    if (!owned.ok) {
      assert.equal(owned.code, 78);
      assert.equal(owned.message, refusal("/Library", 1000, 0o755));
    }

    const codeParent = planInstall("darwin", darwinEnv, {
      ...darwinBase,
      ancestorStat: injected({ "/Library/Verax": { uid: 0, mode: 0o777 } }),
    });
    assert.equal(codeParent.ok, false);
    if (!codeParent.ok) assert.equal(codeParent.message, refusal("/Library/Verax", 0, 0o777));

    const stateParent = planInstall("darwin", darwinEnv, {
      ...darwinBase,
      ancestorStat: injected({ "/Library/Application Support/Verax": { uid: 0, mode: 0o777 } }),
    });
    assert.equal(stateParent.ok, false);
    if (!stateParent.ok) assert.equal(stateParent.message, refusal("/Library/Application Support/Verax", 0, 0o777));

    const launchd = planInstall("darwin", darwinEnv, {
      ...darwinBase,
      ancestorStat: injected({ "/Library/LaunchDaemons": { uid: 0, mode: 0o777 } }),
    });
    assert.equal(launchd.ok, false);
    if (!launchd.ok) assert.equal(launchd.message, refusal("/Library/LaunchDaemons", 0, 0o777));
  });

  it("the elevated CLI code check accepts a sticky 01777 ancestor and refuses a 0777 one", () => {
    const dir = "/opt/verax-f23c-not-a-real-prefix/lib/node_modules/@verax-ai/body";
    const read = (optMode: number) => (file: string) => ({
      uid: 0,
      mode: file === "/opt" ? optMode : 0o755,
      symlink: false,
    });
    assert.equal(posixCodeDirectoryDetail(dir, "linux", read(0o1777)), false);
    assert.equal(posixCodeDirectoryDetail(dir, "linux", read(0o777)), "/opt owner uid 0, mode 777");
    assert.equal(
      posixCodeDirectoryDetail(dir, "linux", () => ({ uid: 0, mode: 0o1777, symlink: false })),
      `${dir} owner uid 0, mode 1777`,
    );
  });
});
