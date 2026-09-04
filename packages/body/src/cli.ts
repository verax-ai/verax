import { doctorExit, runDoctor } from "./doctor.ts";
import { main } from "./main.ts";
import { runUnlock } from "./unlock.ts";

const argv = process.argv.slice(2);
if (argv[0] === "unlock") {
  const stateDir = argv[1];
  if (!stateDir) {
    process.stderr.write("verax unlock <stateDir>\n");
    process.exit(78);
  }
  process.exit(runUnlock(stateDir));
}
if (argv[0] === "doctor") {
  const json = argv.includes("--json");
  const checks = runDoctor(process.env, process.argv);
  if (json) {
    process.stdout.write(`${JSON.stringify({ checks })}\n`);
  } else {
    for (const c of checks) {
      process.stdout.write(`${c.level}\t${c.id}\t${c.detail}\n`);
    }
  }
  process.exit(doctorExit(checks));
}

await main();
