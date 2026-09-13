import { beginPairing } from "./operator-pairing.ts";

export async function runOperator(argv: string[]): Promise<number> {
  if (argv[1] !== "enroll") {
    process.stderr.write("verax operator enroll --state <dir>\n");
    return 78;
  }
  let stateDir = "";
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === "--state") {
      stateDir = argv[++i] ?? "";
      continue;
    }
    if (argv[i]?.startsWith("-")) {
      process.stderr.write(`flag-unknown:${argv[i]}\n`);
      return 78;
    }
  }
  if (!stateDir) {
    process.stderr.write("verax operator enroll --state <dir>\n");
    return 78;
  }
  const { code } = beginPairing(stateDir);
  process.stdout.write(`${code}\n`);
  return 0;
}
