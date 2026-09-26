import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, unlinkSync } from "node:fs";
import { get } from "node:http";
import { createConnection, createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { systemToolPath } from "./install.ts";
import { hasRegisteredOperator } from "./operator-credentials.ts";
import { pidAlive, readLockFile } from "./unlock.ts";

/** One stderr line when this state has no enrolled operator. */
export const DESKTOP_PASSKEY_HINT =
  "the panel reads the ledger after a passkey sign-in; run verax operator enroll\n";

/**
 * The credentials file is written only when an operator enrolls. Its presence
 * is the whole answer; a missing file means the panel's audit doors will
 * refuse the session that has no passkey.
 */
export function desktopPasskeyHint(stateDir: string): string | null {
  return hasRegisteredOperator(stateDir) ? null : DESKTOP_PASSKEY_HINT;
}

const here = dirname(fileURLToPath(import.meta.url));

export function resolveRepoRoot(): string {
  return join(here, "..", "..", "..");
}

export const DESKTOP_CLONE_ONLY =
  "verax desktop runs from a clone of github.com/verax-ai/verax; it is not in the npm package\n";

export function desktopCloneError(root: string): string | null {
  if (!existsSync(join(root, "scripts", "dev-issuer.mjs")) || !existsSync(join(root, "apps", "panel"))) {
    return DESKTOP_CLONE_ONLY;
  }
  return null;
}

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

/**
 * Bind the loopback port and close it. True only when this process held it.
 * A connect probe is not this: whoever is already listening would answer it.
 */
export function desktopPortFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = createServer();
    server.once("error", () => resolve(false));
    server.listen(port, "127.0.0.1", () => {
      server.close(() => resolve(true));
    });
  });
}

export function desktopPortBusyLine(name: DesktopChildName, port: number): string {
  return `desktop-port-busy:${name}:${port}\n`;
}

/** JWKS document the dev issuer rewrites under the state directory on every start. */
export function issuerJwksPinPath(stateDir: string): string {
  return join(stateDir, "dev-issuer", "jwks.json");
}

/** Drop a file left by an earlier run. A missing file is the state we want. */
export function discardStaleFile(file: string): void {
  try {
    unlinkSync(file);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
}

/**
 * The pin is the file the issuer just wrote. Compact JSON, or a throw when
 * it is not a key set. Nothing is fetched.
 */
export function readIssuerJwksPin(stateDir: string): string {
  let text: string;
  try {
    text = readFileSync(issuerJwksPinPath(stateDir), "utf8");
  } catch {
    throw new Error("desktop-jwks-pin-failed");
  }
  try {
    const parsed = JSON.parse(text) as { keys?: unknown };
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.keys) || parsed.keys.length === 0) {
      throw new Error("desktop-jwks-pin-failed");
    }
    return JSON.stringify({ keys: parsed.keys });
  } catch (err) {
    if (err instanceof Error && err.message === "desktop-jwks-pin-failed") throw err;
    throw new Error("desktop-jwks-pin-failed");
  }
}

export function issuerReadyLine(port: number): string {
  return `dev-issuer listening on http://127.0.0.1:${port}/`;
}

export function bodyReadyLine(port: number): string {
  return `listening 127.0.0.1:${port}`;
}

export function panelReadyLine(port: number): string {
  return `http://127.0.0.1:${port}`;
}

export function childStillAlive(child: { exitCode: number | null; signalCode: NodeJS.Signals | null }): boolean {
  return child.exitCode === null && child.signalCode === null;
}

/** GET /healthz on the loopback port; true only for a 200. */
export function healthzUp(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const req = get({ host: "127.0.0.1", port, path: "/healthz", timeout: 3_000 }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.once("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.once("error", () => resolve(false));
  });
}

export type DesktopMode =
  | { mode: "spawn" }
  | { mode: "attach"; pid: number }
  | { error: "desktop-body-locked"; pid: number };

/**
 * One ledger, one body. The desktop used to build its own issuer and body on
 * every open, which on a machine whose body starts at logon put the window on
 * a second, empty ledger: the panel looked broken while the real decisions sat
 * in the directory the lock names. So the lock is read first. Held by a live
 * process that answers /healthz where this run was told to look, the panel
 * joins that body. Held by a live process that does not answer there, the
 * desktop stops: someone owns the ledger and is not where we were pointed, and
 * a second body would be refused by the lock anyway. A dead or unreadable lock
 * is the body's own to clear (`verax unlock`); the desktop builds as before.
 */
export async function desktopMode(
  stateDir: string,
  bodyPort: number,
  probe: (port: number) => Promise<boolean> = healthzUp,
): Promise<DesktopMode> {
  const lockPath = join(stateDir, "ledger.lock");
  if (!existsSync(lockPath)) return { mode: "spawn" };
  const lock = readLockFile(lockPath);
  if (!lock || !pidAlive(lock.pid)) return { mode: "spawn" };
  if (await probe(bodyPort)) return { mode: "attach", pid: lock.pid };
  return { error: "desktop-body-locked", pid: lock.pid };
}

export type DesktopChildName = "issuer" | "body" | "panel";

export type SupervisedChild = {
  name: DesktopChildName;
  /** Registers the listener invoked when this child exits. May run it immediately if it already has. */
  onExit: (listener: () => void) => void;
};

/**
 * The first of the issuer, the body or the panel to exit stops the rest.
 * A later exit does not stop again. `stillWatching` is false once this run
 * is shutting down on purpose, so those exits are not a child failure.
 */
export function superviseDesktopChildren(
  children: readonly SupervisedChild[],
  stopAll: () => void,
  stillWatching: () => boolean = () => true,
): Promise<DesktopChildName> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (name: DesktopChildName) => {
      if (done || !stillWatching()) return;
      done = true;
      stopAll();
      resolve(name);
    };
    for (const child of children) child.onExit(() => finish(child.name));
  });
}

export function desktopChildExitedLine(name: DesktopChildName): string {
  return `desktop-child-exited:${name}\n`;
}

export type DesktopSpawnName = DesktopChildName | "browser";

/** Test seam. Production leaves this unset and spawns the real children. */
export type DesktopHooks = {
  spawn?: (
    name: DesktopSpawnName,
    cmd: string,
    args: string[],
    env: NodeJS.ProcessEnv,
    cwd: string,
  ) => ChildProcess;
  /** Caps issuer, body, and panel readiness waits. The CLI uses the built-in budgets. */
  readyMs?: number;
};

export function killTree(pid: number | undefined): void {
  if (pid == null) return;
  if (process.platform === "win32") {
    spawnSync(systemToolPath("taskkill", "win32"), ["/T", "/PID", String(pid), "/F"], {
      windowsHide: true,
      stdio: "ignore",
    });
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

/**
 * `windowsHide` is right for the servers: it keeps a console window off the
 * screen. It is wrong for the browser. On Windows the flag becomes SW_HIDE in
 * the child's STARTUPINFO, and Chrome and Edge honour it for their first
 * window: the process starts, renderers run, the panel answers on its port,
 * and the app window is created hidden. That is the desktop app opening to
 * nothing. The browser must be spawned with the flag off.
 */
function spawnLogged(
  cmd: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  cwd: string,
  hideWindow = true,
): ChildProcess {
  return spawn(cmd, args, {
    cwd,
    env,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: hideWindow,
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

export async function runDesktop(
  opts: DesktopOpts,
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
  hooks?: DesktopHooks,
): Promise<number> {
  const repoRoot = resolveRepoRoot();
  const cloneOnly = desktopCloneError(repoRoot);
  if (cloneOnly) {
    writeErr(cloneOnly);
    return 78;
  }
  // Before the issuer, the body, or the window: a first run with no operator
  // file otherwise opens a panel that cannot read the ledger and does not say why.
  const passkeyHint = desktopPasskeyHint(opts.stateDir);
  if (passkeyHint) writeErr(passkeyHint);
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
  const gate = { watch: true };
  const exited: { name: DesktopChildName | null } = { name: null };
  let resolveGone: (name: DesktopChildName) => void = () => {};
  const childGone = new Promise<DesktopChildName>((resolve) => {
    resolveGone = resolve;
  });

  const stopAll = () => {
    gate.watch = false;
    for (const c of kids) killTree(c.pid);
  };
  const launch = (
    name: DesktopSpawnName,
    cmd: string,
    args: string[],
    env: NodeJS.ProcessEnv,
    cwd: string,
    hideWindow = true,
  ): ChildProcess => (hooks?.spawn ? hooks.spawn(name, cmd, args, env, cwd) : spawnLogged(cmd, args, env, cwd, hideWindow));
  const pipe = (child: ChildProcess, own: { text: string }) => {
    const feed = (chunk: Buffer | string) => {
      const text = String(chunk);
      own.text += text;
      log.text += text;
    };
    child.stdout?.on("data", feed);
    child.stderr?.on("data", feed);
  };
  // Before the wait, so a child that dies during startup is the failure.
  const arm = (name: DesktopChildName, child: ChildProcess) => {
    const note = () => {
      if (!gate.watch || exited.name) return;
      exited.name = name;
      resolveGone(name);
      stopAll();
    };
    if (child.exitCode !== null || child.signalCode !== null) note();
    else child.once("exit", note);
  };
  const waitReady = async (
    child: ChildProcess,
    own: { text: string },
    ready: (text: string) => boolean,
    ms: number,
  ): Promise<"ready" | "exited" | "timeout"> => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      if (exited.name || !childStillAlive(child)) return "exited";
      if (ready(own.text)) return childStillAlive(child) && !exited.name ? "ready" : "exited";
      await new Promise((r) => setTimeout(r, 20));
    }
    if (exited.name || !childStillAlive(child)) return "exited";
    return ready(own.text) ? "ready" : "timeout";
  };
  const busy = async (name: DesktopChildName, port: number): Promise<boolean> => {
    if (await desktopPortFree(port)) return false;
    writeErr(desktopPortBusyLine(name, port));
    stopAll();
    return true;
  };
  const childFailed = (name: DesktopChildName): number => {
    writeErr(desktopChildExitedLine(exited.name ?? name));
    stopAll();
    return 1;
  };

  try {
    const decided = await desktopMode(opts.stateDir, opts.bodyPort);
    if ("error" in decided) {
      writeErr(`${decided.error}:${decided.pid}\n`);
      return 1;
    }

    // Joining a running body: its issuer is whatever the body's resource
    // metadata names, and its token is not ours to read. The panel's own
    // origin has to be on that issuer's allow-list (VERAX_DEV_REDIRECT_URIS on
    // the running issuer), which this run cannot set after the fact.
    // The body port is that body. Only the ports this run will bind must be free.
    const ports: [DesktopChildName, number][] =
      decided.mode === "spawn"
        ? [
            ["issuer", opts.issuerPort],
            ["body", opts.bodyPort],
            ["panel", opts.panelPort],
          ]
        : [["panel", opts.panelPort]];
    for (const [name, port] of ports) {
      if (await busy(name, port)) return 1;
    }

    let token: string | null = null;
    if (decided.mode === "spawn") {
      // A token or pin left on disk is the previous run's. This issuer must write both.
      discardStaleFile(tokenPath);
      discardStaleFile(issuerJwksPinPath(opts.stateDir));
      if (await busy("issuer", opts.issuerPort)) return 1;
      const issuer = launch(
        "issuer",
        process.execPath,
        ["--experimental-strip-types", issuerScript, "--out", tokenPath],
        issuerEnv(cleanEnv(), opts, audience, issuerUrl),
        repoRoot,
      );
      kids.push(issuer);
      arm("issuer", issuer);
      const issuerOut = { text: "" };
      pipe(issuer, issuerOut);
      const issuerReady = await waitReady(
        issuer,
        issuerOut,
        (text) => text.includes(issuerReadyLine(opts.issuerPort)),
        hooks?.readyMs ?? 15_000,
      );
      if (issuerReady === "exited") return childFailed("issuer");
      if (issuerReady === "timeout") {
        writeErr("desktop-issuer-timeout\n");
        stopAll();
        return 1;
      }
      // The --out file is the agent credential. It does not carry verax:audit.
      // The panel reads the ledger with the passkey session, not this file.
      let tokenText = "";
      try {
        tokenText = readFileSync(tokenPath, "utf8").trim();
      } catch {
        tokenText = "";
      }
      if (tokenText === "") {
        writeErr("desktop-token-missing\n");
        stopAll();
        return 1;
      }
      token = tokenText;

      // The body verifies with the keys this issuer wrote at start. A fetch of
      // the port would pin whoever answered. VERAX_JWKS_FILE is not this pin:
      // that mode refuses operator scopes. The URL stays so config can load;
      // the pin is what verification uses, and it does not refetch.
      let pinnedJwks: string;
      try {
        pinnedJwks = readIssuerJwksPin(opts.stateDir);
      } catch {
        writeErr("desktop-jwks-pin-failed\n");
        stopAll();
        return 1;
      }

      if (await busy("body", opts.bodyPort)) return 1;
      const body = launch(
        "body",
        process.execPath,
        ["--experimental-strip-types", mainTs],
        {
          ...cleanEnv(),
          VERAX_STATE_DIR: opts.stateDir,
          VERAX_ISSUER: issuerUrl,
          VERAX_JWKS_URL: `${issuerUrl}/.well-known/jwks.json`,
          VERAX_JWKS_PIN: pinnedJwks,
          VERAX_AUDIENCE: audience,
          VERAX_BIND: `127.0.0.1:${opts.bodyPort}`,
          VERAX_POLICY_FILE: policy,
          ...(opts.inventoryFile ? { VERAX_INVENTORY_FILE: opts.inventoryFile } : {}),
        },
        repoRoot,
      );
      kids.push(body);
      arm("body", body);
      const bodyOut = { text: "" };
      pipe(body, bodyOut);
      const bodyReady = await waitReady(
        body,
        bodyOut,
        (text) => text.includes(bodyReadyLine(opts.bodyPort)),
        hooks?.readyMs ?? 15_000,
      );
      if (bodyReady === "exited") return childFailed("body");
      if (bodyReady === "timeout") {
        writeErr("desktop-body-timeout\n");
        stopAll();
        return 1;
      }
    }

    const panelSources = [
      join(panelDir, "src"),
      join(panelDir, "index.html"),
      join(panelDir, "vite.config.ts"),
      join(repoRoot, "packages"),
    ];
    if (!hooks?.spawn && panelBuildNeeded(join(panelDir, "dist", "index.html"), panelSources)) {
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

    if (await busy("panel", opts.panelPort)) return 1;
    const panel = launch(
      "panel",
      process.execPath,
      [viteJs, "preview", "--host", "127.0.0.1", "--port", String(opts.panelPort), "--strictPort"],
      {
        ...cleanEnv(),
        VERAX_BODY_URL: audience,
      },
      panelDir,
    );
    kids.push(panel);
    arm("panel", panel);
    const panelOut = { text: "" };
    pipe(panel, panelOut);
    const panelReady = await waitReady(
      panel,
      panelOut,
      (text) => text.includes(panelReadyLine(opts.panelPort)),
      hooks?.readyMs ?? 20_000,
    );
    if (panelReady === "exited") return childFailed("panel");
    if (panelReady === "timeout") {
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
    const browser = launch("browser", browserBin, browserArgv, cleanEnv(), repoRoot, false);
    kids.push(browser);
    pipe(browser, { text: "" });
    if (token !== null && log.text.includes(token)) {
      writeErr("desktop-token-leaked\n");
      stopAll();
      return 1;
    }
    process.stdout.write(
      decided.mode === "attach"
        ? `desktop-ready body=${opts.bodyPort} panel=${opts.panelPort} attached=1 pid=${decided.pid}\n`
        : `desktop-ready issuer=${opts.issuerPort} body=${opts.bodyPort} panel=${opts.panelPort}\n`,
    );
    const onSignal = () => {
      stopAll();
      process.exit(1);
    };
    process.once("SIGINT", onSignal);
    process.once("SIGTERM", onSignal);
    const closed = new Promise<void>((resolve) => {
      if (browser.exitCode !== null || browser.signalCode !== null) resolve();
      else browser.once("close", () => resolve());
    });
    const childExit = async (name: DesktopChildName): Promise<number> => {
      writeErr(desktopChildExitedLine(name));
      process.removeListener("SIGINT", onSignal);
      process.removeListener("SIGTERM", onSignal);
      stopAll();
      return 1;
    };
    const exitedEarly = await Promise.race([
      closed.then(() => ({ kind: "browser" as const })),
      childGone.then((name) => ({ kind: "child" as const, name })),
      new Promise<{ kind: "stay" }>((resolve) => {
        setTimeout(() => resolve({ kind: "stay" }), 3_000);
      }),
    ]);
    if (exitedEarly.kind === "child") return childExit(exitedEarly.name);
    if (exitedEarly.kind === "browser") {
      writeErr("desktop-browser-exited-early\n");
      process.removeListener("SIGINT", onSignal);
      process.removeListener("SIGTERM", onSignal);
      stopAll();
      return 1;
    }
    const ended = await Promise.race([
      closed.then(() => ({ kind: "browser" as const })),
      childGone.then((name) => ({ kind: "child" as const, name })),
    ]);
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
    if (ended.kind === "child") return childExit(ended.name);
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
