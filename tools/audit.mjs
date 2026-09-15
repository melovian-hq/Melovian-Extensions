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
  ".ts",
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
const TEXT_EXTS = new Set([
  ".json",
  ".js",
  ".mjs",
  ".ts",
  ".css",
  ".txt",
  ".md",
  ".svg",
]);

const MANIFEST_KEYS = new Set([
  "id",
  "name",
  "version",
  "description",
  "author",
  "homepage",
  "license",
  "tags",
  "icon",
  "image",
  "screenshots",
  "permissions",
  "minAppVersion",
  "requires",
  "appTheme",
  "styles",
  "script",
  "trackRules",
  "playerHooks",
  "settings",
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
// Sources: Socket obfuscation writeups, the StegoAd campaign (Microsoft
// VR), GlassWorm/Open VSX reports, and the Trojan Source paper.
const SCRIPT_WARN_PATTERNS = [
  [/\batob\s*\(|\bbtoa\s*\(|String\.fromCharCode|unescape\s*\(/, "obfuscation primitive"],
  [/\bWebSocket\b|\bEventSource\b|\bnavigator\.|\bindexedDB\b/, "platform API access"],
  [/\bWebAssembly\b/, "WebAssembly usage"],
  [/[A-Za-z0-9+/]{200,}={0,2}/, "long base64-looking blob"],
  [/\bsetTimeout\s*\(\s*["'`]|\bsetInterval\s*\(\s*["'`]/, "string-eval timer"],
  [
    /\bDate\.now\s*\(|\bnew Date\s*\(|\bperformance\.now\s*\(/,
    "time-gated logic, dormant payloads delay execution this way",
  ],
  [
    /\bnavigator\.userAgent|\bouterWidth\b|\bFirebug\b|devtools/i,
    "environment detection, payloads hide from reviewers this way",
  ],
  [
    /\[\s*["'](?:window|document|globalThis|self|top|frames|fetch|eval|localStorage|sessionStorage|constructor|__proto__)\s*["']\s*\]/,
    "computed property access on a sandboxed global",
  ],
  [
    /\bself\b|\btop\b|\bframes\b|\bparent\b/,
    "global scope escape alias",
  ],
];

// Runs of escaped bytes spelling printable ASCII exist to hide strings
// from reviewers. Four or more in a row have no legitimate use here.
const ENCODED_RUN_PATTERNS = [
  [/(?:\\x[0-9a-fA-F]{2}){4,}/, "hex escape run"],
  [/(?:\\u[0-9a-fA-F]{4}){4,}/, "unicode escape run"],
  [/(?:\\u\{[0-9a-fA-F]+\}){4,}/, "unicode codepoint escape run"],
];

// Trojan Source and GlassWorm carriers: bidi controls reorder code
// visually, invisible format chars smuggle payloads, tag block chars
// encode ASCII invisibly. None belong in extension source.
const UNICODE_BLOCK = /[\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\uFEFF\u034F\u115F\u1160\u3164\uFFA0]/;
const UNICODE_BLOCK_SUPPLEMENT =
  /[\u{E0000}-\u{E00EF}\u{E0100}-\u{E01EF}\u{FE00}-\u{FE0F}]/u;
const UNICODE_FORMAT_CATEGORY = /\p{Cf}/u;

const URL_PATTERN = /https?:\/\/[^\s"'`)\]}>\\]+/g;

// Namespace identifiers look like URLs but are never fetched.
const NON_FETCHED_HOSTS = new Set([
  "www.w3.org",
  "schemas.xmlsoap.org",
  "schemas.openxmlformats.org",
  "purl.org",
]);

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

function scanInvisibleUnicode(rel, text, errors) {
  if (UNICODE_BLOCK.test(text) || UNICODE_BLOCK_SUPPLEMENT.test(text)) {
    errors.push(`${rel} contains bidi controls, zero-width, or tag block characters`);
    return;
  }
  if (UNICODE_FORMAT_CATEGORY.test(text)) {
    errors.push(`${rel} contains invisible Unicode format characters`);
  }
}

function collectExternalUrls(text, out) {
  for (const match of text.matchAll(URL_PATTERN)) {
    let url = match[0].replace(/[.,;:]+$/, "");
    try {
      const parsed = new URL(url);
      if (
        (parsed.protocol === "http:" || parsed.protocol === "https:") &&
        !NON_FETCHED_HOSTS.has(parsed.hostname)
      ) {
        out.add(parsed.toString());
      }
    } catch {
      // not a URL after all
    }
  }
}

// Binary image trailers: StegoAd-style campaigns hide payload bytes after
// the image terminator (PNG IEND, JPEG EOI, GIF trailer). Flag any
// trailing data so a human reviews it.
export function checkImageTrailer(rel, data, errors, warnings) {
  const ext = path.extname(rel).toLowerCase();
  if (ext === ".png") {
    const iend = data.lastIndexOf(Buffer.from("IEND"));
    if (iend === -1) {
      warnings.push(`${rel} is not a well-formed PNG (no IEND)`);
      return;
    }
    const trailing = data.length - (iend + 8);
    if (trailing > 0) {
      errors.push(`${rel} has ${trailing} byte(s) after IEND, possible hidden payload`);
    }
    return;
  }
  if (ext === ".jpg" || ext === ".jpeg") {
    const eoi = data.lastIndexOf(Buffer.from([0xff, 0xd9]));
    if (eoi === -1) return;
    const trailing = data.length - (eoi + 2);
    if (trailing > 0) {
      errors.push(`${rel} has ${trailing} byte(s) after JPEG EOI marker`);
    }
    return;
  }
  if (ext === ".gif") {
    const trailer = data.lastIndexOf(0x3b);
    if (trailer === -1) return;
    const trailing = data.length - (trailer + 1);
    if (trailing > 0) {
      errors.push(`${rel} has ${trailing} byte(s) after GIF trailer`);
    }
  }
}

// Name/author impersonation: mixed-script or non-ASCII in identity fields
// is how lookalike extensions fake trust ("Meloviаn" with Cyrillic a).
function checkIdentityField(value, where, warnings) {
  if (typeof value !== "string") return;
  if (/[^\x00-\x7F]/.test(value)) {
    warnings.push(`${where} contains non-ASCII characters, check for homoglyphs`);
  }
}

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

// Capability names mirror what the app surfaces to the user. A manifest
// that uses a capability without declaring it fails the audit, the way
// browser extension stores treat undeclared permissions.
export const PERMISSIONS = [
  "styles",
  "script",
  "theme",
  "track-decorations",
  "player-hooks",
];

function usedCapabilities(manifest) {
  const used = new Set();
  if ((manifest.styles?.length ?? 0) > 0) used.add("styles");
  if (manifest.script !== undefined) used.add("script");
  if (manifest.appTheme !== undefined) used.add("theme");
  if ((manifest.trackRules?.length ?? 0) > 0) used.add("track-decorations");
  if ((manifest.playerHooks?.length ?? 0) > 0) used.add("player-hooks");
  return used;
}

function auditPermissions(manifest, errors, warnings) {
  const used = usedCapabilities(manifest);
  const declared = manifest.permissions;
  if (declared === undefined) {
    if (used.size > 0) {
      warnings.push(
        `no permissions declared, add "permissions": [${[...used].map((p) => `"${p}"`).join(", ")}] to make the capability contract explicit`,
      );
    }
    return;
  }
  if (!Array.isArray(declared)) {
    errors.push("permissions must be an array");
    return;
  }
  const seen = new Set();
  for (const perm of declared) {
    if (!PERMISSIONS.includes(perm)) {
      errors.push(
        `unknown permission ${JSON.stringify(perm)}; valid: ${PERMISSIONS.join(", ")}`,
      );
      continue;
    }
    if (seen.has(perm)) warnings.push(`permissions repeats ${perm}`);
    seen.add(perm);
    if (!used.has(perm)) {
      warnings.push(`permissions declares ${perm} but nothing uses it`);
    }
  }
  for (const cap of used) {
    if (!seen.has(cap)) {
      errors.push(`uses ${cap} but does not declare it in permissions`);
    }
  }
}

const SETTING_TYPES = new Set(["boolean", "choice", "text"]);
const SETTING_KEY = /^[a-z0-9][a-z0-9_-]{0,62}$/;

// Settings declarations mirror the app-side validation in
// internal/extensions/settings.go. Keep both in sync or installs fail
// after a package already passed audit.
function auditSettings(manifest, errors, warnings) {
  if (manifest.settings === undefined) return;
  if (!Array.isArray(manifest.settings) || manifest.settings.length > 16) {
    errors.push("settings must be an array of at most 16 fields");
    return;
  }
  const seen = new Set();
  for (const field of manifest.settings) {
    if (typeof field !== "object" || field === null) {
      errors.push("settings entries must be objects");
      continue;
    }
    const key = typeof field.key === "string" ? field.key : "";
    if (!SETTING_KEY.test(key)) {
      errors.push(`settings key ${JSON.stringify(field.key)} must match ${SETTING_KEY}`);
      continue;
    }
    if (seen.has(key)) errors.push(`settings repeats key ${key}`);
    seen.add(key);
    if (field.label !== undefined && (typeof field.label !== "string" || field.label.length > 80)) {
      errors.push(`settings ${key} label must be a string of at most 80 chars`);
    }
    if (!SETTING_TYPES.has(field.type)) {
      errors.push(`settings ${key} has unknown type ${JSON.stringify(field.type)}`);
      continue;
    }
    if (field.type === "choice") {
      if (!Array.isArray(field.options) || field.options.length === 0) {
        errors.push(`settings ${key} of type choice needs options`);
      } else if (field.options.some((o) => typeof o !== "string" || o === "")) {
        errors.push(`settings ${key} options must be non-empty strings`);
      } else if (field.default !== undefined && !field.options.includes(field.default)) {
        errors.push(`settings ${key} default is not one of its options`);
      }
    }
    if (field.type === "boolean" && field.default !== undefined && typeof field.default !== "boolean") {
      errors.push(`settings ${key} default must be boolean`);
    }
    if (field.type === "text" && field.default !== undefined &&
        (typeof field.default !== "string" || field.default.length > 256)) {
      errors.push(`settings ${key} default must be a string of at most 256 chars`);
    }
  }
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
  checkIdentityField(manifest.name, "name", warnings);
  checkIdentityField(manifest.author, "author", warnings);
  if (manifest.homepage !== undefined) {
    if (typeof manifest.homepage !== "string" || !/^https:\/\//.test(manifest.homepage)) {
      errors.push("homepage must be an https URL");
    }
  }
  if (manifest.license !== undefined) {
    if (typeof manifest.license !== "string" || manifest.license.length > 64) {
      errors.push("license must be a short string like Apache-2.0");
    }
  }
  if (manifest.tags !== undefined) {
    if (!Array.isArray(manifest.tags) || manifest.tags.length > 12) {
      errors.push("tags must be an array of at most 12 entries");
    } else {
      for (const tag of manifest.tags) {
        if (typeof tag !== "string" || !/^[a-z0-9-]{1,24}$/.test(tag)) {
          errors.push(`tag ${JSON.stringify(tag)} must match [a-z0-9-]{1,24}`);
        }
      }
    }
  }
  if (manifest.screenshots !== undefined) {
    if (!Array.isArray(manifest.screenshots) || manifest.screenshots.length > 8) {
      errors.push("screenshots must be an array of at most 8 paths");
    } else {
      for (const shot of manifest.screenshots) {
        if (typeof shot !== "string" || !isSafeRelPath(shot)) {
          errors.push(`screenshot path ${JSON.stringify(shot)} is not a safe relative path`);
          continue;
        }
        const norm = normalizeRel(shot);
        if (!IMAGE_EXTS.has(path.extname(norm).toLowerCase())) {
          errors.push(`screenshot ${norm} must be an image file`);
        }
        if (!dirFiles.has(norm)) errors.push(`screenshot file ${norm} does not exist`);
      }
    }
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
      if (![".js", ".mjs", ".ts"].includes(path.extname(norm).toLowerCase())) {
        errors.push(`script ${norm} must be a .js, .mjs, or .ts file`);
      }
      if (!dirFiles.has(norm)) errors.push(`script file ${norm} does not exist`);
    }
  }
  auditTrackRules(manifest, dirFiles, errors, warnings);
  auditPlayerHooks(manifest, errors, warnings);
  if (manifest.minAppVersion !== undefined) {
    if (
      typeof manifest.minAppVersion !== "string" ||
      !VERSION_PATTERN.test(manifest.minAppVersion)
    ) {
      errors.push(
        `minAppVersion must be semver, got ${JSON.stringify(manifest.minAppVersion)}`,
      );
    }
  }
  if (manifest.requires !== undefined) {
    if (!Array.isArray(manifest.requires) || manifest.requires.length > 8) {
      errors.push("requires must be an array of at most 8 extension ids");
    } else {
      for (const dep of manifest.requires) {
        if (typeof dep !== "string" || !ID_PATTERN.test(dep)) {
          errors.push(`requires entry ${JSON.stringify(dep)} must match ${ID_PATTERN}`);
          continue;
        }
        if (dep === manifest.id) {
          errors.push("requires may not list the extension itself");
          continue;
        }
        const depManifest = path.join(
          path.dirname(dir),
          dep,
          MANIFEST_NAME,
        );
        if (!existsSync(depManifest)) {
          errors.push(`requires ${dep} which is not in this registry`);
        }
      }
    }
  }
  auditPermissions(manifest, errors, warnings);
  auditSettings(manifest, errors, warnings);
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

function scanText(rel, text, errors, warnings, externalUrls) {
  const ext = path.extname(rel).toLowerCase();
  scanInvisibleUnicode(rel, text, errors);
  collectExternalUrls(text, externalUrls);
  for (const [pattern, label] of SECRET_PATTERNS) {
    if (pattern.test(text)) {
      errors.push(`${rel} contains something that looks like a ${label}`);
    }
  }
  for (const [pattern, label] of ENCODED_RUN_PATTERNS) {
    if (pattern.test(text)) {
      errors.push(`${rel} contains a ${label}, review for hidden payloads`);
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
  if (ext === ".js" || ext === ".mjs" || ext === ".ts") {
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
  const externalUrls = new Set();
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
    return { errors, warnings, manifest: null, files, externalUrls: [] };
  }

  const manifest = auditManifest(dir, dirFiles, errors, warnings);
  if (manifest) {
    for (const key of ["icon", "image", "progressThumbUrl", "progressParticleUrl", "iconUrl"]) {
      if (typeof manifest[key] === "string") collectExternalUrls(manifest[key], externalUrls);
    }
    for (const rule of manifest.trackRules ?? []) {
      for (const key of ["progressThumbUrl", "progressParticleUrl", "iconUrl"]) {
        if (typeof rule.decoration?.[key] === "string") {
          collectExternalUrls(rule.decoration[key], externalUrls);
        }
      }
    }
  }

  for (const f of files) {
    const ext = path.extname(f.rel).toLowerCase();
    if (IMAGE_EXTS.has(ext) && ext !== ".svg" && f.size <= MAX_ASSET_BYTES) {
      const data = await readFile(f.full);
      checkImageTrailer(f.rel, data, errors, warnings);
      continue;
    }
    if (!TEXT_EXTS.has(ext) || f.size > 4 * 1024 * 1024) continue;
    const text = await readFile(f.full, "utf8");
    scanText(f.rel, text, errors, warnings, externalUrls);
  }
  if (files.some((f) => path.extname(f.rel).toLowerCase() === ".wasm")) {
    warnings.push("package ships a .wasm binary, audit it by hand");
  }
  auditChangelog(dir, manifest, errors, warnings);
  return { errors, warnings, manifest, files, externalUrls: [...externalUrls].sort() };
}

const CHANGELOG_HEADING = /^##\s+\[?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\]?\s*-\s*(\d{4}-\d{2}-\d{2})/;

// Parses keep-a-changelog style headings: "## 1.2.0 - 2026-09-14".
export function parseChangelog(text) {
  const releases = [];
  let current = null;
  for (const line of text.split("\n")) {
    const head = line.match(CHANGELOG_HEADING);
    if (head) {
      current = { version: head[1], date: head[2], notes: [] };
      releases.push(current);
      continue;
    }
    if (current && line.trim()) current.notes.push(line.trim());
  }
  for (const rel of releases) rel.notes = rel.notes.join(" ").trim();
  return releases;
}

function auditChangelog(dir, manifest, errors, warnings) {
  const file = path.join(dir, "CHANGELOG.md");
  if (!existsSync(file)) {
    warnings.push("no CHANGELOG.md, add one so version history is reviewable");
    return;
  }
  const releases = parseChangelog(readFileSync(file, "utf8"));
  if (releases.length === 0) {
    errors.push("CHANGELOG.md has no parseable '## x.y.z - YYYY-MM-DD' headings");
    return;
  }
  if (manifest && releases[0].version !== manifest.version) {
    errors.push(
      `CHANGELOG.md top entry ${releases[0].version} does not match manifest version ${manifest.version}`,
    );
  }
  const seen = new Set();
  for (const rel of releases) {
    if (seen.has(rel.version)) errors.push(`CHANGELOG.md repeats version ${rel.version}`);
    seen.add(rel.version);
    if (!rel.notes) warnings.push(`CHANGELOG.md ${rel.version} has no notes`);
  }
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
