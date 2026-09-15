#!/usr/bin/env node
/*
 * Builds a markdown audit report for pull requests. Diffs each extension
 * against the published registry so reviewers see what changed in the
 * danger surface, not just the code.
 *
 * Usage:
 *   node tools/pr-report.mjs [base-registry.json] > report.md
 *
 * With a base registry path the report includes capability diffs against
 * the previously published version. Without one every extension is
 * treated as new.
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { auditAll } from "./audit.mjs";
import { capabilities, riskRating } from "./build.mjs";

const root = path.dirname(fileURLToPath(new URL(".", import.meta.url)));

const basePath = process.argv[2];
let base = {};
if (basePath && existsSync(basePath)) {
  try {
    const doc = JSON.parse(await readFile(basePath, "utf8"));
    for (const entry of doc.extensions ?? []) base[entry.id] = entry;
  } catch {
    // Missing or unreadable base registry just means no diff columns.
  }
}

const results = await auditAll(root);
const lines = ["## Extension audit report", ""];

if (results.size === 0) {
  lines.push("No extensions under extensions/.");
} else {
  lines.push(
    "| Extension | Version | Risk | Declared permissions | External URLs | Audit |",
    "|---|---|---|---|---|---|",
  );
  for (const [name, result] of results) {
    const m = result.manifest;
    if (!m) {
      lines.push(`| ${name} | - | - | - | - | errors: ${result.errors.length} |`);
      continue;
    }
    const caps = capabilities(m, result.files);
    const risk = riskRating(m, result.files, result.externalUrls ?? []);
    const perms = (m.permissions ?? []).join(", ") || "none declared";
    const urls = (result.externalUrls ?? []).length;
    const status =
      result.errors.length > 0
        ? `${result.errors.length} error(s), ${result.warnings.length} warning(s)`
        : result.warnings.length > 0
          ? `${result.warnings.length} warning(s)`
          : "clean";
    void caps;
    lines.push(
      `| ${name} | ${m.version} | ${risk} | ${perms} | ${urls} | ${status} |`,
    );
  }
}

const diffs = [];
for (const [name, result] of results) {
  const m = result.manifest;
  if (!m) continue;
  const prev = base[name];
  if (!prev) {
    diffs.push(`- \`${name}\` ${m.version}: new extension`);
    continue;
  }
  const changes = [];
  if (prev.version !== m.version) changes.push(`version ${prev.version} -> ${m.version}`);
  const prevCaps = prev.capabilities ?? {};
  const caps = capabilities(m, result.files);
  for (const key of ["script", "wasm", "appTheme"]) {
    if (Boolean(prevCaps[key]) !== Boolean(caps[key])) {
      changes.push(`${key} ${prevCaps[key] ? "removed" : "added"}`);
    }
  }
  for (const key of ["styles", "trackRules", "playerHooks"]) {
    if ((prevCaps[key] ?? 0) !== caps[key]) {
      changes.push(`${key} ${prevCaps[key] ?? 0} -> ${caps[key]}`);
    }
  }
  const prevPerms = new Set(prev.permissions ?? []);
  const newPerms = (m.permissions ?? []).filter((p) => !prevPerms.has(p));
  if (newPerms.length) changes.push(`new permissions: ${newPerms.join(", ")}`);
  const prevUrls = new Set(prev.externalUrls ?? []);
  const newUrls = (result.externalUrls ?? []).filter((u) => !prevUrls.has(u));
  if (newUrls.length) {
    changes.push(`new external URLs: ${newUrls.map((u) => `\`${u}\``).join(", ")}`);
  }
  if (changes.length) diffs.push(`- \`${name}\`: ${changes.join("; ")}`);
}

if (diffs.length) {
  lines.push("", "### Changes since the published registry", "", ...diffs);
} else {
  lines.push("", "No capability changes versus the published registry.");
}

for (const [name, result] of results) {
  for (const err of result.errors) lines.push(`- **error** \`${name}\`: ${err}`);
  for (const warn of result.warnings) lines.push(`- warning \`${name}\`: ${warn}`);
}

console.log(lines.join("\n"));
