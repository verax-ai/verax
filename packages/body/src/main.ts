import { EX_CONFIG, loadConfig } from "./config.ts";
import { listen } from "./server.ts";

export async function main(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const loaded = loadConfig(env);
  if (!loaded.ok) {
    process.stderr.write(`${loaded.reason}\n`);
    process.exit(loaded.code);
  }
  await listen(loaded.value);
}

const invoked = process.argv[1] && process.argv[1].replace(/\\/g, "/").endsWith("/main.ts");
if (invoked) {
  await main();
}
