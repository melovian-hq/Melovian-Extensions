#!/usr/bin/env node
/*
 * Builds the registry index and installable zip packages.
 *
 * For every dir under extensions/ that passes the audit with zero errors,
 * writes packages/<id>-<version>.zip (files stored under a <id>/ top
 * folder, which the app installer accepts). packages/ is committed and
 * immutable: an existing archive is rebuilt and compared byte for byte,
 * so a republished version can never silently change content.
 *
 * registry.json carries the full version history, changelog notes parsed
 * from each extension's CHANGELOG.md, the external URL inventory the
 * audit collected, a risk rating, and an Ed25519 signature per package.
 * The index itself is signed into registry.sig so the app can verify the
 * whole document against a key compiled into the binary.
 *
 * TypeScript scripts are stripped to plain JS at pack time with the
 * built-in node type stripper. The .ts source ships in the zip next to
 * the compiled .js so reviewers see what authors wrote and the sandbox
 * only ever runs the checked output.
 *
 * Zips are written with the store method and a fixed timestamp so builds
 * are reproducible and sha256 values in registry.json stay stable.
 *
 * Usage:
 *   node tools/build.mjs                  write packages/, dist/, registry.json, registry.sig
 *   node tools/build.mjs --check          verify registry.json is in sync
 *   node tools/build.mjs --no-sign        skip signing (local dev)
 *   node tools/build.mjs --base-url URL   override the download base URL
 *
 * Signing needs REGISTRY_SIGNING_KEY or keys/registry.key.
 */

import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { copyFile, lstat, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { stripTypeScriptTypes } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { auditAll, parseChangelog } from "./audit.mjs";
import { loadPrivateKey, signBytes } from "./sign.mjs";

const root = path.dirname(fileURLToPath(new URL(".", import.meta.url)));

const DEFAULT_BASE_URL = "https://melovian-hq.github.io/Melovian-Extensions/";

// CRC32, IEEE polynomial. Small enough to keep local instead of pulling a dep.
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let crc = 0xffffffff;
  for (const byte of buf) {
    crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// Fixed DOS timestamp: 1980-01-01 00:00:00. Keeps output byte reproducible.
const DOS_TIME = 0;
const DOS_DATE = (0 << 9) | (1 << 5) | 1; // year 1980, month 1, day 1

export function buildZip(entries) {
  // entries: [{ name: "id/rel/path", data: Buffer }]. Stored uncompressed.
  const localParts = [];
  const central = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name, "utf8");
    const crc = crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // UTF-8 names flag
    local.writeUInt16LE(0, 8); // store method
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18); // compressed size
    local.writeUInt32LE(data.length, 22); // uncompressed size
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28); // extra length
    localParts.push(local, nameBuf, data);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4); // version made by
    cd.writeUInt16LE(20, 6); // version needed
    cd.writeUInt16LE(0x0800, 8); // UTF-8 flag
    cd.writeUInt16LE(0, 10); // store
    cd.writeUInt16LE(DOS_TIME, 12);
    cd.writeUInt16LE(DOS_DATE, 14);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt16LE(0, 30); // extra
    cd.writeUInt16LE(0, 32); // comment
    cd.writeUInt16LE(0, 34); // disk
    cd.writeUInt16LE(0, 36); // internal attrs
    cd.writeUInt32LE((0o100644 << 16) >>> 0, 38); // external attrs, regular file
    cd.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([cd, nameBuf]));

    offset += 30 + nameBuf.length + data.length;
  }

  const cdStart = offset;
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(cdStart, 16);
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...localParts, cdBuf, eocd]);
}

function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function capabilities(manifest, files) {
  return {
    script: Boolean(manifest.script),
    wasm: files.some((f) => f.rel.toLowerCase().endsWith(".wasm")),
    styles: (manifest.styles ?? []).length,
    appTheme: Boolean(manifest.appTheme),
    trackRules: (manifest.trackRules ?? []).length,
    playerHooks: (manifest.playerHooks ?? []).length,
  };
}

// Coarse risk rating for display. Script and wasm raise the ceiling on
// what a package could do, external URLs raise the privacy surface.
function riskRating(manifest, files, externalUrls) {
  const wasm = files.some((f) => f.rel.toLowerCase().endsWith(".wasm"));
  if (wasm) return "high";
  if (manifest.script || externalUrls.length > 0) return "medium";
  return "low";
}

// Compiles a .ts script to .js with the node type stripper. The packaged
// manifest is rewritten to point at the emitted file so the sandbox only
// ever loads checked JavaScript.
function compileScript(scriptPath, source) {
  return stripTypeScriptTypes(source, {
    mode: "strip",
    sourceMap: false,
  });
}

async function collectSorted(dir) {
  const files = [];
  async function walk(current, relBase) {
    for (const name of (await readdir(current)).sort()) {
      const full = path.join(current, name);
      const rel = relBase ? `${relBase}/${name}` : name;
      const st = await lstat(full);
      if (st.isDirectory()) await walk(full, rel);
      else if (st.isFile()) files.push(rel);
    }
  }
  await walk(dir, "");
  return { files };
}

async function extensionEntries(dir, manifest) {
  const { files } = await collectSorted(dir);
  const entries = [];
  let packagedManifest = null;
  for (const rel of files) {
    let data = await readFile(path.join(dir, rel));
    if (rel === "melovian-extension.json") {
      packagedManifest = JSON.parse(data.toString("utf8"));
      continue;
    }
    entries.push({ name: `${manifest.id}/${rel}`, data });
  }
  if (!packagedManifest) {
    throw new Error(`${manifest.id}: manifest missing from package input`);
  }

  const script = packagedManifest.script;
  if (typeof script === "string" && script.toLowerCase().endsWith(".ts")) {
    const tsName = script.replace(/\\/g, "/");
    const tsRel = tsName.startsWith(`${manifest.id}/`) ? tsName.slice(manifest.id.length + 1) : tsName;
    const source = await readFile(path.join(dir, tsRel));
    const compiled = compileScript(tsRel, source.toString("utf8"));
    const jsRel = tsRel.replace(/\.ts$/i, ".js");
    entries.push({ name: `${manifest.id}/${jsRel}`, data: Buffer.from(compiled, "utf8") });
    packagedManifest.script = jsRel;
  }

  entries.sort((a, b) => (a.name < b.name ? -1 : 1));
  entries.unshift({
    name: `${manifest.id}/melovian-extension.json`,
    data: Buffer.from(`${JSON.stringify(packagedManifest, null, 2)}\n`, "utf8"),
  });
  return entries;
}

function versionSort(a, b) {
  const pa = a.split(".").map((n) => parseInt(n, 10));
  const pb = b.split(".").map((n) => parseInt(n, 10));
  for (let i = 0; i < 3; i += 1) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  }
  return 0;
}

// Loads prior registry.json so publishedAt dates for existing versions
// carry forward instead of resetting on every rebuild.
async function loadPreviousIndex() {
  const file = path.join(root, "registry.json");
  if (!existsSync(file)) return null;
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch {
    return null;
  }
}

export async function buildIndex({ baseUrl = DEFAULT_BASE_URL, sign = true } = {}) {
  const base = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const results = await auditAll(root);
  const previous = await loadPreviousIndex();
  const extensions = [];
  const zips = new Map();
  const failures = [];
  const key = sign ? await loadPrivateKey() : null;

  const packagesDir = path.join(root, "packages");
  await mkdir(packagesDir, { recursive: true });

  for (const [name, result] of results) {
    if (result.errors.length > 0 || !result.manifest) {
      failures.push(name);
      continue;
    }
    const manifest = result.manifest;
    const dir = path.join(root, "extensions", name);
    const entries = await extensionEntries(dir, manifest);
    const zip = buildZip(entries);
    const fileName = `${manifest.id}-${manifest.version}.zip`;
    const zipPath = path.join(packagesDir, fileName);

    // Immutability gate: a committed archive for this version must match
    // the rebuild exactly. Anything else means content changed without a
    // version bump, which is how weaponized updates hide.
    if (existsSync(zipPath)) {
      const existing = await readFile(zipPath);
      if (!existing.equals(zip)) {
        failures.push(name);
        console.error(
          `error  ${name}: version ${manifest.version} already published with different content, bump the version`,
        );
        continue;
      }
    } else {
      await writeFile(zipPath, zip);
    }
    zips.set(fileName, zip);

    const changelog = existsSync(path.join(dir, "CHANGELOG.md"))
      ? parseChangelog(await readFile(path.join(dir, "CHANGELOG.md"), "utf8"))
      : [];

    const prevEntry = previous?.extensions?.find?.((e) => e.id === manifest.id);
    const prevVersions = Array.isArray(prevEntry?.versions) ? prevEntry.versions : [];

    const signature = key ? signBytes(key, zip).toString("base64") : null;
    const packageInfo = {
      url: `${base}packages/${fileName}`,
      sha256: sha256Hex(zip),
      bytes: zip.length,
      ...(signature ? { signature } : {}),
    };

    const prevCurrent = prevVersions.find((v) => v.version === manifest.version);
    const versions = [
      {
        version: manifest.version,
        ...packageInfo,
        releasedAt:
          changelog[0]?.date ?? prevCurrent?.releasedAt ?? new Date().toISOString().slice(0, 10),
        notes: changelog[0]?.notes ?? prevCurrent?.notes ?? "",
      },
      ...prevVersions
        .filter((v) => versionSort(v.version, manifest.version) < 0)
        .map((v) => ({ ...v })),
    ];

    // Every historical version must still have its committed archive,
    // and its recorded sha256 must still match. Re-sign the archive so
    // each shipped version carries a signature.
    for (const v of versions.slice(1)) {
      const archived = path.join(packagesDir, `${manifest.id}-${v.version}.zip`);
      if (!existsSync(archived)) {
        failures.push(name);
        console.error(
          `error  ${name}: version ${v.version} is listed in registry history but packages/${manifest.id}-${v.version}.zip is missing`,
        );
        continue;
      }
      const archivedZip = await readFile(archived);
      if (v.sha256 && sha256Hex(archivedZip) !== v.sha256) {
        failures.push(name);
        console.error(
          `error  ${name}: archived package for ${v.version} no longer matches its recorded sha256`,
        );
        continue;
      }
      v.url = `${base}packages/${manifest.id}-${v.version}.zip`;
      v.bytes = archivedZip.length;
      if (key) v.signature = signBytes(key, archivedZip).toString("base64");
    }

    extensions.push({
      id: manifest.id,
      name: manifest.name,
      version: manifest.version,
      ...(manifest.description ? { description: manifest.description } : {}),
      ...(manifest.author ? { author: manifest.author } : {}),
      ...(manifest.homepage ? { homepage: manifest.homepage } : {}),
      ...(manifest.license ? { license: manifest.license } : {}),
      ...(manifest.tags?.length ? { tags: manifest.tags } : {}),
      ...(manifest.icon
        ? { icon: `extensions/${manifest.id}/${manifest.icon.replace(/\\/g, "/")}` }
        : {}),
      ...(manifest.image
        ? { image: `extensions/${manifest.id}/${manifest.image.replace(/\\/g, "/")}` }
        : {}),
      ...(manifest.screenshots?.length
        ? {
            screenshots: manifest.screenshots.map(
              (s) => `extensions/${manifest.id}/${s.replace(/\\/g, "/")}`,
            ),
          }
        : {}),
      package: packageInfo,
      versions,
      changelog,
      externalUrls: result.externalUrls ?? [],
      capabilities: capabilities(manifest, result.files.map((f) => ({ rel: f.rel }))),
      risk: riskRating(manifest, result.files, result.externalUrls ?? []),
      audit: {
        status: "pass",
        warnings: result.warnings,
      },
    });
  }

  extensions.sort((a, b) => a.id.localeCompare(b.id));
  const index = {
    version: 1,
    generatedAt: new Date().toISOString(),
    extensions,
  };
  return { index, zips, failures, results, key };
}

const isMain =
  process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isMain) {
  const args = process.argv.slice(2);
  const check = args.includes("--check");
  const noSign = args.includes("--no-sign");
  const baseIdx = args.indexOf("--base-url");
  const baseUrl =
    baseIdx > -1 && args[baseIdx + 1]
      ? args[baseIdx + 1]
      : process.env.REGISTRY_BASE_URL || DEFAULT_BASE_URL;

  const { index, zips, failures, results, key } = await buildIndex({
    baseUrl,
    sign: !noSign,
  });

  for (const [name, result] of results) {
    for (const err of result.errors) console.error(`error  ${name}: ${err}`);
    for (const warn of result.warnings) console.log(`warn   ${name}: ${warn}`);
  }
  if (failures.length > 0) {
    console.error(`\nbuild aborted, failed audit: ${failures.join(", ")}`);
    process.exit(1);
  }

  const indexBytes = Buffer.from(`${JSON.stringify(index, null, 2)}\n`, "utf8");

  if (check) {
    const committedPath = path.join(root, "registry.json");
    if (!existsSync(committedPath)) {
      console.error("registry.json is missing, run node tools/build.mjs");
      process.exit(1);
    }
    const committed = JSON.parse(await readFile(committedPath, "utf8"));
    // Without a signing key the rebuilt index has no signatures, so strip
    // them from both sides before comparing.
    const strip = (doc) => {
      const clone = JSON.parse(JSON.stringify({ ...doc, generatedAt: null }));
      for (const e of clone.extensions ?? []) {
        delete e.package?.signature;
        for (const v of e.versions ?? []) delete v.signature;
      }
      return clone;
    };
    const same =
      JSON.stringify(key ? { ...committed, generatedAt: null } : strip(committed)) ===
      JSON.stringify(key ? { ...index, generatedAt: null } : strip(index));
    if (!same) {
      console.error("registry.json is out of date, run node tools/build.mjs");
      process.exit(1);
    }
    const sigPath = path.join(root, "registry.sig");
    if (!noSign) {
      if (!existsSync(sigPath)) {
        console.error("registry.sig is missing, run node tools/build.mjs");
        process.exit(1);
      }
      const { loadPublicKeyHex, verifyBytes } = await import("./sign.mjs");
      const pubHex = await loadPublicKeyHex();
      const sig = Buffer.from((await readFile(sigPath, "utf8")).trim(), "base64");
      const committedBytes = await readFile(committedPath);
      if (!verifyBytes(pubHex, committedBytes, sig)) {
        console.error("registry.sig does not verify against registry.json");
        process.exit(1);
      }
    }
    console.log("registry.json is in sync");
    process.exit(0);
  }

  const distDir = path.join(root, "dist");
  await rm(distDir, { recursive: true, force: true });
  await mkdir(distDir, { recursive: true });
  for (const fileName of await readdir(path.join(root, "packages"))) {
    if (fileName.endsWith(".zip")) {
      await copyFile(path.join(root, "packages", fileName), path.join(distDir, fileName));
    }
  }
  await writeFile(path.join(root, "registry.json"), indexBytes);
  if (key) {
    const sig = signBytes(key, indexBytes);
    await writeFile(path.join(root, "registry.sig"), `${sig.toString("base64")}\n`);
  }
  console.log(
    `wrote registry.json with ${index.extensions.length} extension(s) and ${zips.size} zip(s)`,
  );
}
