import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

export async function bumpMetric(stateDir: string, key: string): Promise<number> {
  const path = join(stateDir, "metrics.json");
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  let raw: Record<string, number> = {};
  try {
    raw = JSON.parse(await readFile(path, "utf8")) as Record<string, number>;
  } catch {
    raw = {};
  }
  const count = Number(raw[key] ?? 0) + 1;
  raw[key] = count;
  await writeFile(path, `${JSON.stringify(raw)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  return count;
}

export async function bumpUnauthenticated(stateDir: string): Promise<number> {
  return bumpMetric(stateDir, "unauthenticated_requests");
}
