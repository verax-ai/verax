// Run by tests/browser-cleanup.test.ts in a child `node --test`, never by the
// suite itself. A test that fails with its browser still open.
import { after, it } from "node:test";
import { killStragglers, launchBrowser } from "../../scripts/test-preview.ts";

after(killStragglers);

it("fails with the browser still open", async () => {
  const { browser } = await launchBrowser();
  await browser.newPage();
  throw new Error("left-open");
});
