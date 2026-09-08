import { EX_CONFIG, loadConfig, overlayInventoryArg } from "./config.ts";
import { KeysPartialError } from "./keys.ts";
import { listen } from "./server.ts";

export async function main(
  env: NodeJS.ProcessEnv = process.env,
  argv: readonly string[] = process.argv,
): Promise<void> {
  const overlaid = overlayInventoryArg(env, argv);
  if ("error" in overlaid) {
    process.stderr.write(`${overlaid.error}\n`);
    process.exit(EX_CONFIG);
  }
  const loaded = loadConfig(overlaid);
  if (!loaded.ok) {
    process.stderr.write(`${loaded.reason}\n`);
    process.exit(loaded.code);
  }
  try {
    const server = await listen(loaded.value);
    const shutdown = () => {
      server.close(() => process.exit(0));
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  } catch (err) {
    if (err instanceof KeysPartialError) {
      process.stderr.write("keys-partial\n");
      process.exit(err.code);
    }
    throw err;
  }
}

const invoked = process.argv[1] && process.argv[1].replace(/\\/g, "/").endsWith("/main.ts");
if (invoked) {
  await main();
}
