// R7: the boundaries added since R3. Each `it` asserts the safe behaviour.
// On the current tree the implementation does the unsafe thing, so the
// assertion fails. A fix should turn that assertion green without weakening it.

import { strict as assert } from "node:assert";
import { mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { memoryPut } from "../packages/body/src/tools/memory.ts";
import { planInstall, verifyServiceAcl, windowsUserCanWrite } from "../packages/body/src/install.ts";
import type { Principal } from "../packages/proxy/src/types.ts";

const winEnv = {
  ProgramFiles: "C:\\Program Files",
  ProgramData: "C:\\ProgramData",
  USERPROFILE: "C:\\Users\\operator",
  USERNAME: "operator",
  USERDOMAIN: "DESKTOP",
};

const winOpts = {
  port: 8801,
  days: 30,
  force: false,
  execPath: "C:\\Program Files\\nodejs\\node.exe",
  bodyVersion: "0.3.0",
  npmCli: "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js",
  stateExists: false,
  veraxRootExists: true,
  markerExists: true,
  winRootOwner: "BUILTIN\\Administrators",
};

/** A non-admin write ACE the English name list does not spell. */
const NON_ADMIN_ACES = [
  "*S-1-5-32-545:(OI)(CI)(M)",
  "*S-1-1-0:(OI)(CI)(M)",
  "VORDEFINIERT\\Benutzer:(OI)(CI)(M)",
  "BUILTIN\\Kullanıcılar:(OI)(CI)(M)",
  "VORDEFINIERT\\ERSTELLER-BESITZER:(OI)(CI)(IO)(F)",
];

const ADMIN_SDDL = "O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";
const TI = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

describe("attack R7", () => {
  it("R7-1 a non-admin write ACE is refused when icacls names it by SID or by a non-English account", () => {
    const admin = "BUILTIN\\Administrators:(OI)(CI)(F)\nNT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n";
    for (const ace of NON_ADMIN_ACES) {
      const plan = planInstall("win32", winEnv, {
        ...winOpts,
        winRootAcl: `${ace}\n${admin}`,
      });
      assert.equal(plan.ok, false, ace);
      if (plan.ok) continue;
      assert.match(plan.message, /was not created by verax install/);
    }
  });

  it("R7-2 two in-flight memory puts cannot pass the tenant quota together", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-r7-quota-"));
    const principal: Principal = {
      brain: "brain-r7",
      scopes: new Set(["verax:memory"]),
      iss: "https://issuer.example",
    };
    const body = "x".repeat(600_000);
    const put = (id: string) =>
      memoryPut(
        {
          name: "memory.put",
          arguments: {
            id,
            body,
            source: { kind: "r7" },
            validUntilMs: 9_999_999_999_999,
          },
        },
        stateDir,
        principal,
      );
    try {
      const [a, b] = await Promise.all([put("one"), put("two")]);
      const texts = [a, b].map((result) => result.content[0]?.text ?? "");
      const refused = texts.filter((text) => text.includes("memory-quota"));
      assert.ok(refused.length >= 1, texts.join("\n"));
      let stored = 0;
      const tenants = join(stateDir, "tenants");
      for (const tenant of readdirSync(tenants)) {
        const memory = join(tenants, tenant, "memory");
        for (const name of readdirSync(memory)) stored += statSync(join(memory, name)).size;
      }
      assert.ok(stored <= 1024 * 1024, String(stored));
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("the same SDDL is the same decision on an English, a German, and a Turkish machine", () => {
    const usersWrite = `${ADMIN_SDDL}(A;OICI;FW;;;BU)`;
    const fixtures = [
      { lang: "en", icaclsIgnored: "BUILTIN\\Users:(OI)(CI)(M)", sddl: usersWrite },
      { lang: "de", icaclsIgnored: "VORDEFINIERT\\Benutzer:(OI)(CI)(M)", sddl: usersWrite },
      { lang: "tr", icaclsIgnored: "BUILTIN\\Kullanıcılar:(OI)(CI)(M)", sddl: usersWrite },
    ];
    const decisions = fixtures.map((row) => windowsUserCanWrite(row.sddl));
    assert.deepEqual(decisions, [true, true, true]);
    const clean = fixtures.map(() => windowsUserCanWrite(ADMIN_SDDL));
    assert.deepEqual(clean, [false, false, false]);
  });

  it("a Users write ACE given as BU, a SID, WD, AU, or CO is refused", () => {
    const writers = ["BU", "S-1-5-32-545", "WD", "AU", "CO"];
    for (const sid of writers) {
      const sddl = `${ADMIN_SDDL}(A;OICI;FW;;;${sid})`;
      assert.equal(windowsUserCanWrite(sddl), true, sid);
      const plan = planInstall("win32", winEnv, { ...winOpts, winRootAcl: sddl });
      assert.equal(plan.ok, false, sid);
    }
  });

  it("Administrators, SYSTEM, TrustedInstaller, and the service SID are the only accepted writers", () => {
    const sddl = `O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FA;;;${TI})(A;OICI;FA;;;S-1-5-21-9)`;
    assert.equal(windowsUserCanWrite(sddl, { svcSid: "S-1-5-21-9" }), false);
    const exact = "O:BAG:SYD:PAI(A;OICI;FA;;;S-1-5-21-9)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";
    assert.equal(verifyServiceAcl(exact, "state", { svcSid: "S-1-5-21-9" }).ok, true);
    const inheritOnly = `${ADMIN_SDDL}(A;OICIIO;FA;;;BU)`;
    assert.equal(windowsUserCanWrite(inheritOnly), false);
  });
});
