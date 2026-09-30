// The desktop launcher without the CLI. No release ships `verax desktop` yet;
// the launcher stays under test until it is released. Arguments are the ones the command took.

import { desktopMain } from "../packages/body/src/desktop.ts";

process.exit(await desktopMain(["desktop", ...process.argv.slice(2)]));
