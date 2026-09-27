// The desktop launcher without the CLI. 0.4.0 does not ship `verax desktop`;
// the launcher stays under test for 0.4.1. Arguments are the ones the command took.

import { desktopMain } from "../packages/body/src/desktop.ts";

process.exit(await desktopMain(["desktop", ...process.argv.slice(2)]));
