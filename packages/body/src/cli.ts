import { doctorExit, runDoctor } from "./doctor.ts";
import { main } from "./main.ts";

const argv = process.argv.slice(2);
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
