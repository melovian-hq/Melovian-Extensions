#!/usr/bin/env node
/*
 * Marks an extension delisted in delisted.json. Delisted entries stay in
 * registry.json so installed clients see the flag and warn; the app
 * refuses new installs of flagged extensions.
 *
 * Usage:
 *   node tools/delist.mjs <id> --reason "why it was pulled"
 *   node tools/delist.mjs <id> --restore
 *
 * Run tools/build.mjs afterwards to regenerate the signed index.
 */

import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(new URL(".", import.meta.url)));
const FILE = path.join(root, "delisted.json");
const ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;

const [id, ...rest] = process.argv.slice(2);
const restore = rest.includes("--restore");
const reasonIdx = rest.indexOf("--reason");
const reason = reasonIdx >= 0 ? rest[reasonIdx + 1] : "";

if (!id || !ID_PATTERN.test(id) || (!restore && !reason)) {
  console.error('usage: node tools/delist.mjs <id> --reason "..." | --restore');
  process.exit(2);
}
if (!existsSync(path.join(root, "extensions", id))) {
  console.error(`extensions/${id} does not exist`);
  process.exit(1);
}

const doc = existsSync(FILE)
  ? JSON.parse(await readFile(FILE, "utf8"))
  : {};

if (restore) {
  delete doc[id];
  console.log(`${id} restored`);
} else {
  doc[id] = { reason, at: new Date().toISOString().slice(0, 10) };
  console.log(`${id} delisted: ${reason}`);
}

const keys = Object.keys(doc).sort();
await writeFile(
  FILE,
  keys.length
    ? JSON.stringify(Object.fromEntries(keys.map((k) => [k, doc[k]])), null, 2) + "\n"
    : "{}\n",
);
console.log("run node tools/build.mjs to publish the change");
