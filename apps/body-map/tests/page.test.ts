import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const viteJs = join(root, "..", "..", "node_modules", "vite", "bin", "vite.js");

describe("body-map page", () => {
  it("opens seven labels, click changes the card, lang=tr sets the title", async () => {
    const child = spawn(process.execPath, [viteJs, "--host", "127.0.0.1", "--port", "4177", "--strictPort"], {
      cwd: root,
      env: { ...process.env, NO_COLOR: "1", FORCE_COLOR: "0" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const ready = await new Promise<string>((resolve, reject) => {
      let buf = "";
      const timer = setTimeout(() => reject(new Error("preview-timeout")), 90_000);
      const onData = (chunk: Buffer) => {
        buf += String(chunk);
        if (buf.includes("http://127.0.0.1:4177/")) {
          clearTimeout(timer);
          resolve("http://127.0.0.1:4177/verax/");
        }
      };
      child.stdout.on("data", onData);
      child.stderr.on("data", onData);
      child.on("exit", (code) => reject(new Error(`preview-exit:${code}`)));
    });
    try {
      const { chromium } = await import("playwright");
      const browser = await chromium.launch({ args: ["--use-gl=swiftshader"] });
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
    } finally {
      child.kill();
    }
  });
});
