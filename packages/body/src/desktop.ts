import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createConnection } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..");

export type DesktopOpts = {
  stateDir: string;
  panelPort: number;
  issuerPort: number;
  bodyPort: number;
  browser?: string;
  inventoryFile?: string;
};

/** Newest modification time under a file or directory, ignoring build output. */
function newestUnder(path: string, since: number): boolean {
  let entry;
  try {
    entry = statSync(path);
  } catch {
    return false;
  }
  if (!entry.isDirectory()) return entry.mtimeMs > since;
  let names;
  try {
    names = readdirSync(path, { withFileTypes: true });
  } catch {
    return false;
  }
  for (const name of names) {
    if (name.name === "node_modules" || name.name === "dist" || name.name.startsWith(".")) continue;
    if (newestUnder(join(path, name.name), since)) return true;
  }
  return false;
}

/**
 * True when the panel has no build, or when a watched source is newer than the
 * one it has. The launcher used to skip the build whenever `dist/index.html`
 * existed, so a session served whatever had been built once: editing the panel
 * and reopening it showed the previous app, with no sign that it was stale.
 */
export function panelBuildNeeded(distIndex: string, sourceRoots: readonly string[]): boolean {
  let builtAt: number;
  try {
    builtAt = statSync(distIndex).mtimeMs;
  } catch {
    return true;
  }
  return sourceRoots.some((root) => newestUnder(root, builtAt));
}

export function parseDesktopArgs(argv: string[]): DesktopOpts | { error: string } {
  const rest = argv.slice(1);
  let stateDir = "";
  let panelPort = 5173;
  let issuerPort = Number(process.env.VERAX_DEV_ISSUER_PORT ?? "8790");
  let bodyPort = 8787;
  let browser: string | undefined;
  let inventoryFile: string | undefined;
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i]!;
    if (a === "--state") {
      stateDir = rest[++i] ?? "";
      continue;
    }
    if (a === "--port") {
      panelPort = Number(rest[++i]);
      continue;
    }
    if (a === "--issuer-port") {
      issuerPort = Number(rest[++i]);
      continue;
    }
    if (a === "--body-port") {
      bodyPort = Number(rest[++i]);
      continue;
    }
    if (a === "--browser") {
      browser = rest[++i];
      continue;
    }
    if (a === "--inventory") {
      inventoryFile = rest[++i];
      continue;
    }
    if (a.startsWith("-")) return { error: `flag-unknown:${a}` };
  }
  if (!stateDir) return { error: "usage" };
  if (![panelPort, issuerPort, bodyPort].every((n) => Number.isInteger(n) && n > 0 && n < 65536)) {
    return { error: "port-invalid" };
  }
  return { stateDir, panelPort, issuerPort, bodyPort, browser, inventoryFile };
}

export function portOpen(port: number, host = "127.0.0.1"): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = createConnection({ port, host });
    sock.once("connect", () => {
      sock.end();
      resolve(true);
    });
    sock.once("error", () => resolve(false));
  });
}

async function waitPort(port: number, ms: number): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < ms) {
    if (await portOpen(port)) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

export function killTree(pid: number | undefined): void {
  if (pid == null) return;
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/T", "/PID", String(pid), "/F"], { windowsHide: true, stdio: "ignore" });
    return;
  }
  try {
    process.kill(-pid, "SIGTERM");
  } catch {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      // gone
    }
  }
}

/** The panel's redirect is its own origin, so the issuer has to be told which port
 *  this run put it on: the allow-list default only holds 5173 and 4173. */
export function issuerEnv(
  base: NodeJS.ProcessEnv,
  opts: { stateDir: string; issuerPort: number; panelPort: number },
  audience: string,
  issuerUrl: string,
): NodeJS.ProcessEnv {
  return {
    ...base,
    NODE_ENV: "development",
    VERAX_STATE_DIR: opts.stateDir,
    VERAX_DEV_ISSUER_PORT: String(opts.issuerPort),
    VERAX_AUDIENCE: audience,
    VERAX_ISSUER: issuerUrl,
    VERAX_DEV_REDIRECT_URIS: `http://127.0.0.1:${opts.panelPort}/`,
  };
}

function cleanEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: "1", FORCE_COLOR: "0" };
  delete env.VERAX_DEV_TOKEN;
  return env;
}

function spawnLogged(
  cmd: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  cwd: string,
): ChildProcess {
  return spawn(cmd, args, {
    cwd,
    env,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    detached: process.platform !== "win32",
  });
}

function defaultBrowser(): string | null {
  const edge = [
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
  ];
  const chrome = [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
  ];
  for (const p of edge) if (existsSync(p)) return p;
  for (const p of chrome) if (existsSync(p)) return p;
  return null;
}

function collectOutput(child: ChildProcess, sink: { text: string }): void {
  const feed = (c: Buffer | string) => {
    sink.text += String(c);
  };
  child.stdout?.on("data", feed);
  child.stderr?.on("data", feed);
}

export async function runDesktop(
  opts: DesktopOpts,
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
): Promise<number> {
  mkdirSync(opts.stateDir, { recursive: true });
  const tokenPath = join(opts.stateDir, "dev-token");
  const issuerScript = join(repoRoot, "scripts", "dev-issuer.mjs");
  const mainTs = join(here, "main.ts");
  const viteJs = join(repoRoot, "node_modules", "vite", "bin", "vite.js");
  const panelDir = join(repoRoot, "apps", "panel");
  const policy = join(repoRoot, "packages", "proxy", "policy", "default.json");
  const audience = `http://127.0.0.1:${opts.bodyPort}`;
  const issuerUrl = `http://127.0.0.1:${opts.issuerPort}`;
  const kids: ChildProcess[] = [];
  const log = { text: "" };

  const stopAll = () => {
    for (const c of kids) killTree(c.pid);
  };

  try {
    const issuer = spawnLogged(
      process.execPath,
      [issuerScript, "--out", tokenPath],
      issuerEnv(cleanEnv(), opts, audience, issuerUrl),
      repoRoot,
    );
    kids.push(issuer);
    collectOutput(issuer, log);
    if (!(await waitPort(opts.issuerPort, 15_000))) {
      writeErr("desktop-issuer-timeout\n");
      stopAll();
      return 1;
    }
    const token = readFileSync(tokenPath, "utf8").trim();
    if (token === "") {
      writeErr("desktop-token-missing\n");
      stopAll();
      return 1;
    }

    const body = spawnLogged(
      process.execPath,
      ["--experimental-strip-types", mainTs],
      {
        ...cleanEnv(),
        VERAX_STATE_DIR: opts.stateDir,
        VERAX_ISSUER: issuerUrl,
        VERAX_JWKS_URL: `${issuerUrl}/.well-known/jwks.json`,
        VERAX_AUDIENCE: audience,
        VERAX_BIND: `127.0.0.1:${opts.bodyPort}`,
        VERAX_POLICY_FILE: policy,
        ...(opts.inventoryFile ? { VERAX_INVENTORY_FILE: opts.inventoryFile } : {}),
      },
      repoRoot,
    );
    kids.push(body);
    collectOutput(body, log);
    if (!(await waitPort(opts.bodyPort, 15_000))) {
      writeErr("desktop-body-timeout\n");
      stopAll();
      return 1;
    }

    const panelSources = [
      join(panelDir, "src"),
      join(panelDir, "index.html"),
      join(panelDir, "vite.config.ts"),
      join(repoRoot, "packages"),
    ];
    if (panelBuildNeeded(join(panelDir, "dist", "index.html"), panelSources)) {
      const built = spawnSync(process.execPath, [viteJs, "build"], {
        cwd: panelDir,
        env: { ...cleanEnv(), VERAX_BODY_URL: audience },
        encoding: "utf8",
        windowsHide: true,
      });
      if (built.status !== 0) {
        const detail = `${built.stderr ?? ""}\n${built.stdout ?? ""}`.slice(0, 800);
        writeErr(`desktop-panel-build-failed\n${detail}\n`);
        stopAll();
        return 1;
      }
    }

    const panel = spawnLogged(
      process.execPath,
      [viteJs, "preview", "--host", "127.0.0.1", "--port", String(opts.panelPort), "--strictPort"],
      {
        ...cleanEnv(),
        VERAX_DEV_TOKEN: token,
        VERAX_BODY_URL: audience,
      },
      panelDir,
    );
    kids.push(panel);
    collectOutput(panel, log);
    if (!(await waitPort(opts.panelPort, 20_000))) {
      writeErr("desktop-panel-timeout\n");
      stopAll();
      return 1;
    }

    const url = `http://127.0.0.1:${opts.panelPort}`;
    const scriptBrowser = Boolean(opts.browser && /\.(mjs|js|ts)$/.test(opts.browser));
    const browserBin = scriptBrowser ? process.execPath : (opts.browser ?? defaultBrowser());
    if (!browserBin) {
      writeErr("desktop-browser-missing\n");
      stopAll();
      return 1;
    }
    const profileDir = join(opts.stateDir, "browser-profile");
    mkdirSync(profileDir, { recursive: true });
    const browserArgv = scriptBrowser
      ? [opts.browser!, url]
      : [
          `--user-data-dir=${profileDir}`,
          "--no-first-run",
          "--no-default-browser-check",
          `--app=${url}`,
          "--window-size=1360,880",
        ];
    const browser = spawnLogged(browserBin, browserArgv, cleanEnv(), repoRoot);
    kids.push(browser);
    collectOutput(browser, log);
    if (log.text.includes(token)) {
      writeErr("desktop-token-leaked\n");
      stopAll();
      return 1;
    }
    process.stdout.write(
      `desktop-ready issuer=${opts.issuerPort} body=${opts.bodyPort} panel=${opts.panelPort}\n`,
    );
    const onSignal = () => {
      stopAll();
      process.exit(1);
    };
    process.once("SIGINT", onSignal);
    process.once("SIGTERM", onSignal);
    const closed = new Promise<void>((resolve) => {
      browser.once("close", () => resolve());
    });
    const exitedEarly = await Promise.race([
      closed.then(() => true),
      new Promise<boolean>((resolve) => {
        setTimeout(() => resolve(false), 3_000);
      }),
    ]);
    if (exitedEarly) {
      writeErr("desktop-browser-exited-early\n");
      process.removeListener("SIGINT", onSignal);
      process.removeListener("SIGTERM", onSignal);
      stopAll();
      return 1;
    }
    await closed;
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
    stopAll();
    return 0;
  } catch (err) {
    stopAll();
    const msg = err instanceof Error ? err.message : "unknown";
    writeErr(`desktop-failed:${msg}\n`);
    return 1;
  }
}

export async function desktopMain(argv: string[]): Promise<number> {
  const parsed = parseDesktopArgs(argv);
  if ("error" in parsed) {
    process.stderr.write("verax desktop [--state <dir>] [--port 5173] [--browser <cmd>] [--inventory <file>]\n");
    return 78;
  }
  return runDesktop(parsed);
}
