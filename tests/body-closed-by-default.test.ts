import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { createConnection } from "node:net";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const main = join(root, "packages", "body", "src", "main.ts");

function connect(port: number): Promise<Error> {
  return new Promise((resolve) => {
    const sock = createConnection({ host: "127.0.0.1", port });
    sock.once("connect", () => {
      sock.destroy();
      resolve(new Error("connected"));
    });
    sock.once("error", (err) => resolve(err));
  });
}

describe("B4 closed-by-default", () => {
  it("empty env exits 78 and the bind port stays closed", async () => {
    const port = 18787;
    const child = spawn(process.execPath, ["--experimental-strip-types", main], {
      cwd: root,
      env: {
        ...process.env,
        VERAX_BIND: `127.0.0.1:${port}`,
        VERAX_ISSUER: "",
        VERAX_JWKS_URL: "",
        VERAX_AUDIENCE: "",
        VERAX_STATE_DIR: "",
        VERAX_POLICY_FILE: "",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stderr = await new Promise<string>((resolve) => {
      let buf = "";
      child.stderr?.on("data", (c) => {
        buf += String(c);
      });
      child.on("exit", () => resolve(buf));
    });
    assert.equal(child.exitCode, 78, stderr);
    assert.match(stderr, /missing VERAX_ISSUER/);
    const err = await connect(port);
    assert.equal((err as NodeJS.ErrnoException).code, "ECONNREFUSED");
  });
});
