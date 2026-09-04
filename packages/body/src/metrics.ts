import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

export async function bumpUnauthenticated(stateDir: string): Promise<number> {
  const path = join(stateDir, "metrics.json");
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  let count = 0;
  try {
    const raw = JSON.parse(await readFile(path, "utf8")) as { unauthenticated_requests?: number };
    count = Number(raw.unauthenticated_requests ?? 0);
  } catch {
    count = 0;
  }
  count += 1;
  await writeFile(path, `${JSON.stringify({ unauthenticated_requests: count })}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  return count;
}
