import { strict as assert } from "node:assert";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { killStragglers, startPreview, trackBrowser } from "../../../scripts/test-preview.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const viteJs = join(root, "..", "..", "node_modules", "vite", "bin", "vite.js");

after(killStragglers);

describe("body-map page", () => {
  it("opens seven labels, click changes the card, lang=tr sets the title", async () => {
    // This wait used to sit outside the try below, so a preview that never
    // came up failed the test and left vite running - and a live child keeps
    // the runner from exiting at all. startPreview owns the child from the
    // moment it is spawned.
    const preview = await startPreview({ viteJs, cwd: root, port: 4177, label: "body-map-page" });
    const ready = `${preview.base}/verax/`;
    try {
      const { chromium } = await import("playwright");
      const browser = await chromium.launch({ args: ["--use-gl=swiftshader"] });
      const stopBrowser = trackBrowser(browser);
      const page = await browser.newPage();
      await page.goto(ready, { waitUntil: "networkidle" });
      const labels = page.locator("button.label");
      await labels.first().waitFor({ state: "visible", timeout: 30_000 });
      assert.equal(await labels.count(), 7);
      assert.equal(await labels.filter({ visible: true }).count(), 7);
      await labels.nth(0).click();
      await page.waitForTimeout(200);
      const card = await page.locator(".card").innerText();
      assert.match(card, /Tugra|Head|Baş/);
      await page.goto(`${ready}?lang=tr`, { waitUntil: "networkidle" });
      assert.match(await page.title(), /gövde|fatura/i);
      await browser.close();
      stopBrowser();
    } finally {
      preview.stop();
    }
  });
});
