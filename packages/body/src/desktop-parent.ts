/** Env the desktop launcher sets on the issuer and the body. Absent outside that launch. */
export const DESKTOP_PARENT_PID = "VERAX_DESKTOP_PARENT_PID";

export type DesktopParentWatch = {
  env?: NodeJS.ProcessEnv;
  /** True when `pid` is still a process. Default is `process.kill(pid, 0)`. */
  pidAlive?: (pid: number) => boolean;
  exit?: (code: number) => void;
  schedule?: (fn: () => void, ms: number) => { unref?: () => void };
};

/** `process.kill(pid, 0)` — EPERM means the process exists. */
export function desktopParentAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * When `VERAX_DESKTOP_PARENT_PID` is set, exit once that pid is gone.
 * Polls every 2s. No-op when the variable is unset, so a normal body or issuer
 * start does not watch anything.
 */
export function watchDesktopParent(hooks: DesktopParentWatch = {}): void {
  const env = hooks.env ?? process.env;
  const raw = env[DESKTOP_PARENT_PID]?.trim() ?? "";
  if (raw === "") return;
  const exit = hooks.exit ?? ((code: number) => process.exit(code));
  const pid = Number(raw);
  if (!Number.isInteger(pid) || pid <= 0) {
    exit(1);
    return;
  }
  const alive = hooks.pidAlive ?? desktopParentAlive;
  if (!alive(pid)) {
    exit(1);
    return;
  }
  const schedule =
    hooks.schedule ??
    ((fn: () => void, ms: number) => {
      const timer = setInterval(fn, ms);
      timer.unref();
      return timer;
    });
  schedule(() => {
    if (!alive(pid)) exit(1);
  }, 2_000);
}
