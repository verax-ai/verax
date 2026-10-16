import { type AddressInfo } from "node:net";
import { setTimeout } from "node:timers";
import { terminalText } from "@verax-ai/proxy";
import { JwksFileError } from "./auth.ts";
import { EX_CONFIG, loadConfig, overlayInventoryArg } from "./config.ts";
import { watchDesktopParent } from "./desktop-parent.ts";
import { KeyAlgorithmError, KeysPartialError } from "./keys.ts";
import { listen, operatorDoorOf } from "./server.ts";

// exitCode alone leaves a listening server up (for example `verax witness`).
// On Windows, process.exit while a handle is still closing crashes in libuv;
// letting the loop drain on its own exits cleanly. Set the code immediately so
// an empty loop ends at once, and after 3s an unref'd timer forces the exit.
// unref: the timer does not keep the loop alive, and by 3s a closing handle is
// gone.
export function endProcess(code: number): void {
  process.exitCode = code;
  setTimeout(() => process.exit(code), 3000).unref();
}

export async function main(
  env: NodeJS.ProcessEnv = process.env,
  argv: readonly string[] = process.argv,
): Promise<void> {
  // stderr can be a file: launchd gives the installed body one. When its disk
  // stops taking writes, a line written there fails after the write has
  // returned, as an 'error' on the stream, and with nobody listening Node ends
  // the process on it. The line is lost; the body is not stopped by that.
  process.stderr.on("error", () => {});
  watchDesktopParent({ env });
  const overlaid = overlayInventoryArg(env, argv);
  if ("error" in overlaid) {
    // ProcessEnv's index makes `error` look optional. The overlay's own
    // failure is always a string; the same sentence is the stand-in.
    const reason = overlaid.error ?? "missing --inventory path";
    process.stderr.write(`${terminalText(reason)}\n`);
    process.exit(EX_CONFIG);
  }
  const loaded = loadConfig(overlaid);
  if (!loaded.ok) {
    process.stderr.write(`${terminalText(loaded.reason)}\n`);
    process.exit(loaded.code);
  }
  try {
    const server = await listen(loaded.value);
    const addr = server.address();
    if (addr && typeof addr === "object") {
      process.stderr.write(`listening ${(addr as AddressInfo).address}:${(addr as AddressInfo).port}\n`);
    }
    const doorAddr = operatorDoorOf(server)?.address();
    if (doorAddr && typeof doorAddr === "object" && loaded.value.operatorDoor) {
      process.stderr.write(
        `operator door ${doorAddr.address}:${doorAddr.port} for ${loaded.value.operatorDoor.origin}\n`,
      );
    }
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
    if (err instanceof KeyAlgorithmError) {
      process.stderr.write(`${terminalText(err.message)}\n`);
      process.exit(err.code);
    }
    if (err instanceof JwksFileError) {
      process.stderr.write(`${terminalText(err.message)}\n`);
      process.exit(err.code);
    }
    if (err instanceof Error && err.message.startsWith("downstream-")) {
      process.stderr.write(`${terminalText(err.message)}\n`);
      endProcess(EX_CONFIG);
      return;
    }
    throw err;
  }
}

const invoked = process.argv[1] && process.argv[1].replace(/\\/g, "/").endsWith("/main.ts");
if (invoked) {
  await main();
}
