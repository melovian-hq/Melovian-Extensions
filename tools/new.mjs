#!/usr/bin/env node
/*
 * Scaffolds a new extension under extensions/<id>/ so contributors start
 * from a valid baseline: manifest, CHANGELOG, a typed script stub, and an
 * icon placeholder.
 *
 * Usage:
 *   node tools/new.mjs <id> "Display name" [--script] [--styles] [--theme]
 *
 * Flags pick which capabilities the skeleton wires up. Without flags the
 * scaffold is a track-decorations only extension, the smallest useful
 * baseline. The manifest permissions field is filled in to match.
 */

import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(new URL(".", import.meta.url)));
const ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
const MANIFEST = "melovian-extension.json";

const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="14" fill="#1b1f2a"/>
  <circle cx="32" cy="32" r="14" fill="none" stroke="#7aa2ff" stroke-width="4"/>
</svg>
`;

const SCRIPT_TS = `/// <reference path="../../types/melovian-extension.d.ts" />
// The sandbox loads the compiled .js and calls register(api) once.
// api.registerTrackRule adds one declarative rule per call. Network,
// storage, and DOM access are blocked by the audit and the loader.
// Imports are not allowed; the reference above gives you the types.

function register(api: melovian.ExtensionAPI) {
  api.registerTrackRule({
    match: { genreContains: "example" },
    decoration: { progressColor: "#7aa2ff" },
  });
}
`;

function usage() {
  console.error(
    'usage: node tools/new.mjs <id> "Display name" [--script] [--styles] [--theme]',
  );
  process.exit(2);
}

const [id, name, ...flags] = process.argv.slice(2);
if (!id || !name || !ID_PATTERN.test(id)) usage();
const wantScript = flags.includes("--script");
const wantStyles = flags.includes("--styles");
const wantTheme = flags.includes("--theme");

const dir = path.join(root, "extensions", id);
if (existsSync(dir)) {
  console.error(`extensions/${id} already exists`);
  process.exit(1);
}

const permissions = ["track-decorations"];
if (wantScript) permissions.push("script");
if (wantStyles) permissions.push("styles");
if (wantTheme) permissions.push("theme");

const manifest = {
  id,
  name,
  version: "0.1.0",
  description: `${name}.`,
  author: "",
  license: "Apache-2.0",
  homepage: "https://github.com/melovian-hq/Melovian-Extensions",
  tags: [],
  icon: "assets/icon.svg",
  permissions,
  trackRules: [
    {
      match: { genreContains: "example" },
      decoration: { icon: "sparkles" },
    },
  ],
  ...(wantTheme ? { appTheme: id } : {}),
  ...(wantStyles ? { styles: ["theme.css"] } : {}),
  ...(wantScript ? { script: "script.ts" } : {}),
};

const changelog = `# Changelog

## [0.1.0] - ${new Date().toISOString().slice(0, 10)}

Initial release.
`;

await mkdir(path.join(dir, "assets"), { recursive: true });
await writeFile(path.join(dir, MANIFEST), JSON.stringify(manifest, null, 2) + "\n");
await writeFile(path.join(dir, "CHANGELOG.md"), changelog);
await writeFile(path.join(dir, "assets", "icon.svg"), ICON_SVG);
if (wantStyles) {
  await writeFile(
    path.join(dir, "theme.css"),
    `:root {\n  --${id}-accent: #7aa2ff;\n}\n`,
  );
}
if (wantScript) await writeFile(path.join(dir, "script.ts"), SCRIPT_TS);

console.log(`created extensions/${id}`);
console.log("next: fill in description, author, tags, then run node tools/audit.mjs --strict");
