#!/usr/bin/env node
/*
 * Nightly re-audit helper. Re-runs the current audit over every published
 * extension and diffs findings against the warnings recorded when each
 * version shipped. Old packages should not silently pass rules that did
 * not exist when they were published.
 *
 * Usage:
 *   node tools/reaudit.mjs            prints a markdown findings report
 *
 * Exit 0 when nothing new turned up, exit 3 when new findings exist so
 * the workflow can open an issue without parsing stdout.
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { auditAll } from "./audit.mjs";

const root = path.dirname(fileURLToPath(new URL(".", import.meta.url)));

let recorded = {};
const regPath = path.join(root, "registry.json");
if (existsSync(regPath)) {
  const doc = JSON.parse(await readFile(regPath, "utf8"));
  for (const entry of doc.extensions ?? []) {
    recorded[entry.id] = new Set(entry.audit?.warnings ?? []);
  }
}

const results = await auditAll(root);
const lines = ["Extension re-audit findings", ""];
let fresh = 0;

for (const [name, result] of results) {
  const known = recorded[name] ?? new Set();
  const newWarnings = result.warnings.filter((w) => !known.has(w));
  for (const err of result.errors) {
    lines.push(`- **error** \`${name}\`: ${err}`);
    fresh += 1;
  }
  for (const warn of newWarnings) {
    lines.push(`- new warning \`${name}\`: ${warn}`);
    fresh += 1;
  }
}

if (fresh === 0) lines.push("No new findings versus the published registry.");
console.log(lines.join("\n"));
process.exit(fresh === 0 ? 0 : 3);
