#!/usr/bin/env node
/*
 * Builds the registry index and installable zip packages.
 *
 * For every dir under extensions/ that passes the audit with zero errors,
 * writes dist/<id>-<version>.zip (files stored under a <id>/ top folder,
 * which the app installer accepts) and an entry in registry.json at the
 * repo root. registry.json is committed so melovian-web and the app can
 * consume it from raw git or the published Pages site.
 *
 * Zips are written with the store method and a fixed timestamp so builds
 * are reproducible and sha256 values in registry.json stay stable.
 *
 * Usage:
 *   node tools/build.mjs                  write dist/ and registry.json
 *   node tools/build.mjs --check          verify registry.json is in sync
 *   node tools/build.mjs --base-url URL   override the download base URL
 *
 * The base URL defaults to REGISTRY_BASE_URL or the GitHub Pages site.
 * Icon and image fields in registry.json stay repo-relative paths;
 * consumers resolve them against the base URL.
 */

import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { lstat, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { auditAll } from "./audit.mjs";

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

async function extensionEntries(dir, id) {
  const { files } = await collectSorted(dir);
  const entries = [];
  for (const rel of files) {
    const data = await readFile(path.join(dir, rel));
    entries.push({ name: `${id}/${rel}`, data });
  }
  return entries;
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

export async function buildIndex({ baseUrl = DEFAULT_BASE_URL } = {}) {
  const base = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const results = await auditAll(root);
  const extensions = [];
  const zips = new Map();
  const failures = [];

  for (const [name, result] of results) {
    if (result.errors.length > 0 || !result.manifest) {
      failures.push(name);
      continue;
    }
    const manifest = result.manifest;
    const dir = path.join(root, "extensions", name);
    const entries = await extensionEntries(dir, manifest.id);
    const zip = buildZip(entries);
    const fileName = `${manifest.id}-${manifest.version}.zip`;
    zips.set(fileName, zip);

    extensions.push({
      id: manifest.id,
      name: manifest.name,
      version: manifest.version,
      ...(manifest.description ? { description: manifest.description } : {}),
      ...(manifest.author ? { author: manifest.author } : {}),
      ...(manifest.icon
        ? { icon: `extensions/${manifest.id}/${manifest.icon.replace(/\\/g, "/")}` }
        : {}),
      ...(manifest.image
        ? { image: `extensions/${manifest.id}/${manifest.image.replace(/\\/g, "/")}` }
        : {}),
      package: {
        url: `${base}dist/${fileName}`,
        sha256: sha256Hex(zip),
        bytes: zip.length,
      },
      capabilities: capabilities(manifest, result.files.map((f) => ({ rel: f.rel }))),
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
  return { index, zips, failures, results };
}

const isMain =
  process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isMain) {
  const args = process.argv.slice(2);
  const check = args.includes("--check");
  const baseIdx = args.indexOf("--base-url");
  const baseUrl =
    baseIdx > -1 && args[baseIdx + 1]
      ? args[baseIdx + 1]
      : process.env.REGISTRY_BASE_URL || DEFAULT_BASE_URL;

  const { index, zips, failures, results } = await buildIndex({ baseUrl });

  for (const [name, result] of results) {
    for (const err of result.errors) console.error(`error  ${name}: ${err}`);
    for (const warn of result.warnings) console.log(`warn   ${name}: ${warn}`);
  }
  if (failures.length > 0) {
    console.error(`\nbuild aborted, failed audit: ${failures.join(", ")}`);
    process.exit(1);
  }

  if (check) {
    const committedPath = path.join(root, "registry.json");
    if (!existsSync(committedPath)) {
      console.error("registry.json is missing, run node tools/build.mjs");
      process.exit(1);
    }
    const committed = JSON.parse(await readFile(committedPath, "utf8"));
    const same =
      JSON.stringify({ ...committed, generatedAt: null }) ===
      JSON.stringify({ ...index, generatedAt: null });
    if (!same) {
      console.error("registry.json is out of date, run node tools/build.mjs");
      process.exit(1);
    }
    console.log("registry.json is in sync");
    process.exit(0);
  }

  const distDir = path.join(root, "dist");
  await rm(distDir, { recursive: true, force: true });
  await mkdir(distDir, { recursive: true });
  for (const [fileName, zip] of zips) {
    await writeFile(path.join(distDir, fileName), zip);
  }
  await writeFile(
    path.join(root, "registry.json"),
    `${JSON.stringify(index, null, 2)}\n`,
  );
  console.log(
    `wrote registry.json with ${index.extensions.length} extension(s) and ${zips.size} zip(s)`,
  );
}
