#!/usr/bin/env node
/*
 * Security audit for Melovian extension packages.
 *
 * The hard gates mirror the checks Melovian applies at install and load
 * time (internal/extensions/validate.go and install.go in the app repo):
 * manifest shape, id format, safe relative paths, the package file
 * allowlist, size caps, and the script sandbox blocklist. This tool adds
 * registry-side checks the app cannot do: secret scanning, remote URL
 * policy, CSS exfiltration rules, and SVG hygiene.
 *
 * Usage:
 *   node tools/audit.mjs                 audit every dir under extensions/
 *   node tools/audit.mjs extensions/foo  audit specific dirs
 *   node tools/audit.mjs --strict        warnings fail the run
 *   node tools/audit.mjs --json          machine readable report
 */

import { readdirSync, readFileSync, statSync, lstatSync, existsSync } from "node:fs";
import { readdir, lstat, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const MANIFEST_NAME =
  process.env.MELOVIAN_EXTENSION_MANIFEST || "melovian-extension.json";

export const MAX_SCRIPT_BYTES = 32 * 1024;
export const MAX_ASSET_BYTES = 8 * 1024 * 1024;
export const MAX_PACKAGE_BYTES = 32 * 1024 * 1024;

export const ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
export const VERSION_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$/;
export const THEME_PATTERN = /^[a-z0-9-]{1,32}$/;

export const ALLOWED_EXTS = new Set([
  ".json",
  ".js",
  ".mjs",
  ".wasm",
  ".css",
  ".txt",
  ".md",
  ".png",
  ".jpg",
  ".jpeg",
  ".webp",
  ".gif",
  ".svg",
  ".woff",
  ".woff2",
  ".ttf",
  ".otf",
]);

const IMAGE_EXTS = new Set([".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg"]);
const TEXT_EXTS = new Set([".json", ".js", ".mjs", ".css", ".txt", ".md", ".svg"]);

const MANIFEST_KEYS = new Set([
  "id",
  "name",
  "version",
  "description",
  "author",
  "icon",
  "image",
  "appTheme",
  "styles",
  "script",
  "trackRules",
  "playerHooks",
]);

const MATCH_KEYS = new Set([
  "genreContains",
  "artistContains",
  "albumContains",
  "titleContains",
  "titleRegex",
  "tagEquals",
  "minRating",
  "isLocal",
]);

const DECORATION_KEYS = new Set([
  "progressColor",
  "progressGradient",
  "progressThumbUrl",
  "progressParticleUrl",
  "icon",
  "iconUrl",
  "titlePrefix",
  "coverOverlayIcon",
  "playerTheme",
]);

// Kept in sync with blockedScriptPatterns in internal/extensions/validate.go.
export const BLOCKED_SCRIPT_PATTERNS = [
  /\bimport\b/i,
  /\brequire\s*\(/i,
  /\bfetch\s*\(/i,
  /\bXMLHttpRequest\b/i,
  /\beval\s*\(/i,
  /\bFunction\s*\(/i,
  /\bwindow\b/i,
  /\bdocument\b/i,
  /\blocalStorage\b/i,
  /\bsessionStorage\b/i,
  /\b__proto__\b/i,
  /\bconstructor\b/i,
  /\bprocess\b/i,
  /\bglobalThis\b/i,
];

// Not blocked by the app sandbox, but worth a human look during review.
const SCRIPT_WARN_PATTERNS = [
  [/\batob\s*\(|\bbtoa\s*\(|String\.fromCharCode/, "obfuscation primitive"],
  [/\bWebSocket\b|\bEventSource\b|\bnavigator\.|\bindexedDB\b/, "platform API access"],
  [/\bWebAssembly\b/, "WebAssembly usage"],
  [/[A-Za-z0-9+/]{200,}={0,2}/, "long base64-looking blob"],
];

const SECRET_PATTERNS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "private key"],
  [/\bAKIA[0-9A-Z]{16}\b/, "AWS access key"],
  [/\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/, "GitHub token"],
  [/\bsk-(live|test|proj)?-[A-Za-z0-9_-]{16,}\b/, "API key"],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, "Slack token"],
  [/\bAIza[0-9A-Za-z_-]{35}\b/, "Google API key"],
  [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, "JWT"],
  [
    /(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9_\-.]{16,}["']/i,
    "hardcoded credential",
  ],
];

const CSS_BLOCK_PATTERNS = [
  [/@import\b/i, "@import loads remote stylesheets"],
  [/url\(\s*['"]?\s*(https?:)?\/\//i, "remote url() reference"],
  [/expression\s*\(/i, "expression()"],
  [/-moz-binding\b/i, "-moz-binding"],
  [/behavior\s*:/i, "behavior property"],
];

const SVG_BLOCK_PATTERNS = [
  [/<script\b/i, "script element"],
  [/\son[a-z]+\s*=/i, "event handler attribute"],
  [/javascript\s*:/i, "javascript: URL"],
  [/data\s*:\s*text\/html/i, "data:text/html payload"],
];

const COLOR_SUSPECT = /[;{}]|url\s*\(|javascript\s*:/i;

function isSafeRelPath(rel) {
  rel = rel.trim().replace(/\\/g, "/");
  if (rel === "" || rel.startsWith("/") || rel.includes("..")) return false;
  if (path.isAbsolute(rel)) return false;
  return true;
}

function normalizeRel(rel) {
  return rel.trim().replace(/\\/g, "/").replace(/^\/+/, "");
}

function checkColorValue(value, where, errors) {
  if (typeof value !== "string") {
    errors.push(`${where} must be a string`);
    return;
  }
  if (COLOR_SUSPECT.test(value)) {
    errors.push(`${where} contains disallowed markup in color value`);
  }
}

function checkDecorationUrl(value, where, dirFiles, errors, warnings) {
  if (typeof value !== "string") {
    errors.push(`${where} must be a string`);
    return;
  }
  const v = value.trim();
  if (/^https?:\/\//i.test(v)) {
    if (!/^https:\/\//i.test(v)) {
      errors.push(`${where} uses http, remote assets must be https`);
    }
    return;
  }
  if (/^\/\//.test(v)) {
    errors.push(`${where} uses a protocol-relative URL`);
    return;
  }
  if (!isSafeRelPath(v)) {
    errors.push(`${where} is not a safe relative path`);
    return;
  }
  const rel = normalizeRel(v);
  if (!dirFiles.has(rel) && !dirFiles.has(`assets/${rel}`)) {
    warnings.push(`${where} points at ${rel} which is not in the package`);
  }
}

function auditTrackRules(manifest, dirFiles, errors, warnings) {
  const rules = manifest.trackRules;
  if (rules === undefined) return;
  if (!Array.isArray(rules)) {
    errors.push("trackRules must be an array");
    return;
  }
  if (rules.length > 64) warnings.push(`trackRules has ${rules.length} entries`);
  rules.forEach((rule, i) => {
    const where = `trackRules[${i}]`;
    if (typeof rule !== "object" || rule === null || Array.isArray(rule)) {
      errors.push(`${where} must be an object`);
      return;
    }
    if (typeof rule.match !== "object" || rule.match === null) {
      errors.push(`${where}.match is required`);
      return;
    }
    for (const key of Object.keys(rule.match)) {
      if (!MATCH_KEYS.has(key)) warnings.push(`${where}.match has unknown key ${key}`);
    }
    if (rule.match.titleRegex !== undefined) {
      const re = rule.match.titleRegex;
      if (typeof re !== "string") {
        errors.push(`${where}.match.titleRegex must be a string`);
      } else {
        if (re.length > 256) errors.push(`${where}.match.titleRegex exceeds 256 chars`);
        try {
          new RegExp(re, "i");
        } catch (err) {
          errors.push(`${where}.match.titleRegex does not compile: ${err.message}`);
        }
        if (/(\([^)]*[+*][^)]*\)|\.[*+])[+*{]/.test(re)) {
          warnings.push(`${where}.match.titleRegex may have catastrophic backtracking`);
        }
      }
    }
    if (rule.match.minRating !== undefined) {
      const r = rule.match.minRating;
      if (!Number.isInteger(r)) {
        errors.push(`${where}.match.minRating must be an integer`);
      } else if (r < 0 || r > 5) {
        warnings.push(`${where}.match.minRating ${r} is outside the 0-5 rating scale`);
      }
    }
    if (rule.match.isLocal !== undefined && typeof rule.match.isLocal !== "boolean") {
      errors.push(`${where}.match.isLocal must be a boolean`);
    }
    for (const key of [
      "genreContains",
      "artistContains",
      "albumContains",
      "titleContains",
      "tagEquals",
    ]) {
      if (rule.match[key] !== undefined && typeof rule.match[key] !== "string") {
        errors.push(`${where}.match.${key} must be a string`);
      }
    }
    if (typeof rule.decoration !== "object" || rule.decoration === null) {
      errors.push(`${where}.decoration is required`);
      return;
    }
    const deco = rule.decoration;
    for (const key of Object.keys(deco)) {
      if (!DECORATION_KEYS.has(key))
        warnings.push(`${where}.decoration has unknown key ${key}`);
    }
    for (const key of ["progressColor", "progressGradient"]) {
      if (deco[key] !== undefined) checkColorValue(deco[key], `${where}.decoration.${key}`, errors);
    }
    for (const key of ["progressThumbUrl", "progressParticleUrl", "iconUrl"]) {
      if (deco[key] !== undefined)
        checkDecorationUrl(deco[key], `${where}.decoration.${key}`, dirFiles, errors, warnings);
    }
    if (deco.icon !== undefined) {
      if (typeof deco.icon !== "string" || !/^[a-z0-9-]{1,64}$/.test(deco.icon)) {
        warnings.push(`${where}.decoration.icon should be a lowercase icon name`);
      }
    }
    if (deco.coverOverlayIcon !== undefined) {
      if (
        typeof deco.coverOverlayIcon !== "string" ||
        !/^[a-z0-9-]{1,64}$/.test(deco.coverOverlayIcon)
      ) {
        warnings.push(
          `${where}.decoration.coverOverlayIcon should be a lowercase icon name`,
        );
      }
    }
    if (deco.titlePrefix !== undefined) {
      if (typeof deco.titlePrefix !== "string") {
        errors.push(`${where}.decoration.titlePrefix must be a string`);
      } else if (deco.titlePrefix.length > 40) {
        warnings.push(`${where}.decoration.titlePrefix exceeds 40 chars`);
      }
    }
    if (deco.playerTheme !== undefined) {
      if (typeof deco.playerTheme !== "string" || !THEME_PATTERN.test(deco.playerTheme)) {
        errors.push(`${where}.decoration.playerTheme must match ${THEME_PATTERN}`);
      } else if (manifest.appTheme && deco.playerTheme !== manifest.appTheme) {
        warnings.push(
          `${where}.decoration.playerTheme ${deco.playerTheme} differs from appTheme ${manifest.appTheme}`,
        );
      }
    }
  });
}

function auditPlayerHooks(manifest, errors, warnings) {
  const hooks = manifest.playerHooks;
  if (hooks === undefined) return;
  if (!Array.isArray(hooks)) {
    errors.push("playerHooks must be an array");
    return;
  }
  hooks.forEach((hook, i) => {
    const where = `playerHooks[${i}]`;
    if (typeof hook !== "object" || hook === null) {
      errors.push(`${where} must be an object`);
      return;
    }
    if (typeof hook.when !== "string" || !/^[a-z][a-z-]{0,31}$/.test(hook.when)) {
      warnings.push(`${where}.when should be a short lowercase token`);
    }
    if (hook.style !== undefined) {
      if (typeof hook.style !== "object" || hook.style === null) {
        errors.push(`${where}.style must be an object`);
      } else {
        for (const [prop, value] of Object.entries(hook.style)) {
          if (typeof value !== "string") {
            errors.push(`${where}.style.${prop} must be a string`);
          } else if (COLOR_SUSPECT.test(value)) {
            errors.push(`${where}.style.${prop} contains disallowed markup`);
          }
        }
      }
    }
  });
}

function auditManifest(dir, dirFiles, errors, warnings) {
  const manifestPath = path.join(dir, MANIFEST_NAME);
  if (!existsSync(manifestPath)) {
    errors.push(`missing ${MANIFEST_NAME}`);
    return null;
  }
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (err) {
    errors.push(`${MANIFEST_NAME} is not valid JSON: ${err.message}`);
    return null;
  }
  if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest)) {
    errors.push(`${MANIFEST_NAME} must contain a JSON object`);
    return null;
  }
  for (const key of Object.keys(manifest)) {
    if (!MANIFEST_KEYS.has(key)) warnings.push(`unknown manifest key ${key}`);
  }
  const id = typeof manifest.id === "string" ? manifest.id.trim() : "";
  if (!ID_PATTERN.test(id)) {
    errors.push(`manifest id ${JSON.stringify(manifest.id)} fails ${ID_PATTERN}`);
  } else if (id !== path.basename(dir)) {
    errors.push(`manifest id ${id} does not match directory name ${path.basename(dir)}`);
  }
  if (typeof manifest.name !== "string" || manifest.name.trim() === "") {
    errors.push("manifest requires a name");
  } else if (manifest.name.length > 80) {
    warnings.push("manifest name exceeds 80 chars");
  }
  if (typeof manifest.version !== "string" || !VERSION_PATTERN.test(manifest.version)) {
    errors.push(`manifest version must be semver, got ${JSON.stringify(manifest.version)}`);
  }
  if (manifest.description !== undefined) {
    if (typeof manifest.description !== "string") {
      errors.push("description must be a string");
    } else if (manifest.description.length > 500) {
      warnings.push("description exceeds 500 chars");
    }
  } else {
    warnings.push("manifest has no description");
  }
  if (manifest.author !== undefined && typeof manifest.author !== "string") {
    errors.push("author must be a string");
  }
  if (manifest.appTheme !== undefined) {
    if (typeof manifest.appTheme !== "string" || !THEME_PATTERN.test(manifest.appTheme)) {
      errors.push(`appTheme must match ${THEME_PATTERN}`);
    }
  }
  for (const key of ["icon", "image"]) {
    const rel = manifest[key];
    if (rel === undefined) continue;
    if (typeof rel !== "string" || !isSafeRelPath(rel)) {
      errors.push(`${key} is not a safe relative path`);
      continue;
    }
    const norm = normalizeRel(rel);
    if (!IMAGE_EXTS.has(path.extname(norm).toLowerCase())) {
      errors.push(`${key} must be an image file, got ${norm}`);
    }
    if (!dirFiles.has(norm)) errors.push(`${key} file ${norm} does not exist`);
  }
  if (manifest.styles !== undefined) {
    if (!Array.isArray(manifest.styles)) {
      errors.push("styles must be an array of paths");
    } else {
      const seen = new Set();
      for (const style of manifest.styles) {
        if (typeof style !== "string" || !isSafeRelPath(style)) {
          errors.push(`style path ${JSON.stringify(style)} is not a safe relative path`);
          continue;
        }
        const norm = normalizeRel(style);
        if (path.extname(norm).toLowerCase() !== ".css") {
          errors.push(`style path ${norm} is not a .css file`);
        }
        if (seen.has(norm)) warnings.push(`duplicate style path ${norm}`);
        seen.add(norm);
        if (!dirFiles.has(norm)) errors.push(`style file ${norm} does not exist`);
      }
    }
  }
  if (manifest.script !== undefined) {
    const rel = manifest.script;
    if (typeof rel !== "string" || !isSafeRelPath(rel)) {
      errors.push(`script path ${JSON.stringify(rel)} is not a safe relative path`);
    } else {
      const norm = normalizeRel(rel);
      if (![".js", ".mjs"].includes(path.extname(norm).toLowerCase())) {
        errors.push(`script ${norm} must be a .js or .mjs file`);
      }
      if (!dirFiles.has(norm)) errors.push(`script file ${norm} does not exist`);
    }
  }
  auditTrackRules(manifest, dirFiles, errors, warnings);
  auditPlayerHooks(manifest, errors, warnings);
  const effectful =
    (manifest.trackRules?.length ?? 0) > 0 ||
    (manifest.playerHooks?.length ?? 0) > 0 ||
    (manifest.styles?.length ?? 0) > 0 ||
    !!manifest.appTheme ||
    !!manifest.script;
  if (!effectful) {
    warnings.push("manifest declares no rules, styles, theme, or script");
  }
  return manifest;
}

function scanText(rel, text, errors, warnings) {
  const ext = path.extname(rel).toLowerCase();
  for (const [pattern, label] of SECRET_PATTERNS) {
    if (pattern.test(text)) {
      errors.push(`${rel} contains something that looks like a ${label}`);
    }
  }
  if (ext === ".css") {
    for (const [pattern, label] of CSS_BLOCK_PATTERNS) {
      if (pattern.test(text)) errors.push(`${rel} uses ${label}`);
    }
  }
  if (ext === ".svg") {
    for (const [pattern, label] of SVG_BLOCK_PATTERNS) {
      if (pattern.test(text)) errors.push(`${rel} contains ${label}`);
    }
  }
  if (ext === ".js" || ext === ".mjs") {
    for (const [pattern, label] of SCRIPT_WARN_PATTERNS) {
      if (pattern.test(text)) warnings.push(`${rel} contains ${label}`);
    }
    if (text.length > MAX_SCRIPT_BYTES) {
      errors.push(`${rel} exceeds the ${MAX_SCRIPT_BYTES} byte script limit`);
    }
    for (const pattern of BLOCKED_SCRIPT_PATTERNS) {
      if (pattern.test(text)) {
        errors.push(`${rel} contains blocked pattern ${pattern}`);
      }
    }
    if (!/\bregister\b/.test(text)) {
      warnings.push(`${rel} never mentions register, the sandbox calls register(api)`);
    }
  }
  if (ext === ".json" && path.basename(rel) !== MANIFEST_NAME) {
    try {
      JSON.parse(text);
    } catch (err) {
      errors.push(`${rel} is not valid JSON: ${err.message}`);
    }
  }
}

async function collectFiles(dir) {
  const files = [];
  const errors = [];
  async function walk(current, relBase) {
    const entries = await readdir(current);
    for (const name of entries) {
      const rel = relBase ? `${relBase}/${name}` : name;
      const full = path.join(current, name);
      const st = await lstat(full);
      if (st.isSymbolicLink()) {
        errors.push(`${rel} is a symlink, packages may not contain links`);
        continue;
      }
      if (name === "__MACOSX" || name === ".DS_Store") {
        errors.push(`${rel} is platform junk, remove it`);
        continue;
      }
      if (name.startsWith(".")) {
        errors.push(`${rel} is a hidden file, not allowed in packages`);
        continue;
      }
      if (name.includes("..") || /[\\/]/.test(name)) {
        errors.push(`${rel} has an unsafe name`);
        continue;
      }
      if (st.isDirectory()) {
        await walk(full, rel);
        continue;
      }
      if (!st.isFile()) {
        errors.push(`${rel} is not a regular file`);
        continue;
      }
      files.push({ rel, full, size: st.size });
    }
  }
  await walk(dir, "");
  return { files, errors };
}

export async function auditExtension(dir) {
  const errors = [];
  const warnings = [];
  const { files, errors: walkErrors } = await collectFiles(dir);
  errors.push(...walkErrors);

  let total = 0;
  const dirFiles = new Set();
  for (const f of files) {
    dirFiles.add(f.rel);
    total += f.size;
    const ext = path.extname(f.rel).toLowerCase();
    if (!ALLOWED_EXTS.has(ext) && f.rel !== MANIFEST_NAME) {
      errors.push(`${f.rel} has a disallowed file type`);
    }
    if (f.size > MAX_ASSET_BYTES) {
      errors.push(`${f.rel} exceeds the ${MAX_ASSET_BYTES} byte per-file limit`);
    } else if (f.size > 2 * 1024 * 1024) {
      warnings.push(`${f.rel} is larger than 2 MiB`);
    }
  }
  if (total > MAX_PACKAGE_BYTES) {
    errors.push(`package totals ${total} bytes, over the ${MAX_PACKAGE_BYTES} limit`);
  }
  if (files.length > 200) {
    warnings.push(`package has ${files.length} files`);
  }
  if (!dirFiles.has(MANIFEST_NAME)) {
    errors.push(`missing ${MANIFEST_NAME}`);
    return { errors, warnings, manifest: null, files };
  }

  const manifest = auditManifest(dir, dirFiles, errors, warnings);

  for (const f of files) {
    const ext = path.extname(f.rel).toLowerCase();
    if (!TEXT_EXTS.has(ext) || f.size > 4 * 1024 * 1024) continue;
    const text = await readFile(f.full, "utf8");
    scanText(f.rel, text, errors, warnings);
  }
  if (files.some((f) => path.extname(f.rel).toLowerCase() === ".wasm")) {
    warnings.push("package ships a .wasm binary, audit it by hand");
  }
  return { errors, warnings, manifest, files };
}

export async function auditAll(rootDir) {
  const extRoot = path.join(rootDir, "extensions");
  const results = new Map();
  if (!existsSync(extRoot)) return results;
  for (const name of readdirSync(extRoot).sort()) {
    const dir = path.join(extRoot, name);
    if (!statSync(dir).isDirectory()) continue;
    if (lstatSync(dir).isSymbolicLink()) continue;
    results.set(name, await auditExtension(dir));
  }
  return results;
}

function printReport(results) {
  let errorCount = 0;
  let warningCount = 0;
  for (const [name, result] of results) {
    for (const err of result.errors) {
      errorCount += 1;
      console.error(`error  ${name}: ${err}`);
    }
    for (const warn of result.warnings) {
      warningCount += 1;
      console.log(`warn   ${name}: ${warn}`);
    }
    if (result.errors.length === 0) {
      console.log(`pass   ${name} (${result.warnings.length} warning(s))`);
    }
  }
  console.log(
    `\n${results.size} extension(s): ${errorCount} error(s), ${warningCount} warning(s)`,
  );
  return errorCount;
}

const isMain =
  process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isMain) {
  const args = process.argv.slice(2);
  const strict = args.includes("--strict");
  const json = args.includes("--json");
  const dirs = args.filter((a) => !a.startsWith("--"));
  const root = path.dirname(fileURLToPath(new URL(".", import.meta.url)));

  let results;
  if (dirs.length === 0) {
    results = await auditAll(root);
    if (results.size === 0) {
      console.error("no extensions found under extensions/");
      process.exit(1);
    }
  } else {
    results = new Map();
    for (const dir of dirs) {
      const resolved = path.resolve(dir);
      const name = path.basename(resolved);
      results.set(name, await auditExtension(resolved));
    }
  }

  if (json) {
    const report = {};
    for (const [name, result] of results) {
      report[name] = { errors: result.errors, warnings: result.warnings };
    }
    console.log(JSON.stringify(report, null, 2));
  } else {
    printReport(results);
  }

  let failures = 0;
  for (const result of results.values()) {
    failures += result.errors.length;
    if (strict) failures += result.warnings.length;
  }
  process.exit(failures === 0 ? 0 : 1);
}
