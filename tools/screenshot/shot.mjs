#!/usr/bin/env node
/*
 * Renders each extension against fixture.html in headless Chromium and
 * saves a screenshot per extension. Pull requests upload the output as a
 * CI artifact so reviewers can see the visual change without running
 * Melovian.
 *
 * Usage:
 *   cd tools/screenshot && npm ci && npx playwright install chromium
 *   node shot.mjs [extension-id ...]
 */

import { mkdir, readdir, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..");
const outDir = path.join(here, "out");
const MANIFEST = "melovian-extension.json";

const wanted = process.argv.slice(2);
const extRoot = path.join(root, "extensions");
const targets = wanted.length
  ? wanted
  : (await readdir(extRoot, { withFileTypes: true }))
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort();

await mkdir(outDir, { recursive: true });
const browser = await chromium.launch();

for (const id of targets) {
  const dir = path.join(extRoot, id);
  const manifestPath = path.join(dir, MANIFEST);
  if (!existsSync(manifestPath)) {
    console.error(`skip ${id}: no manifest`);
    continue;
  }
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));

  const page = await browser.newPage({ viewport: { width: 900, height: 520 } });
  await page.goto(`file://${path.join(here, "fixture.html")}`);

  for (const rel of manifest.styles ?? []) {
    const css = await readFile(path.join(dir, rel), "utf8");
    await page.addStyleTag({ content: css });
  }
  await page.evaluate((m) => window.render(m), manifest);
  await page.waitForFunction(() => window.__done === true);
  await page.screenshot({ path: path.join(outDir, `${id}.png`) });
  console.log(`shot ${id}`);
  await page.close();
}

await browser.close();
