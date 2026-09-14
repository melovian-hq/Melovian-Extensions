import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";

import { auditExtension, MANIFEST_NAME } from "./audit.mjs";
import { buildZip } from "./build.mjs";

// Fixtures live under the repo, not os.tmpdir(), so tests still run in
// environments where /tmp writes are restricted.
const repoRoot = path.dirname(fileURLToPath(new URL(".", import.meta.url)));

function makeDir(files) {
  const dir = mkdtempSync(path.join(repoRoot, ".tmp-test-"));
  const extDir = path.join(dir, "my-ext");
  mkdirSync(extDir, { recursive: true });
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(extDir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return { dir: extDir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const baseManifest = {
  id: "my-ext",
  name: "My ext",
  version: "1.0.0",
};

function manifest(overrides = {}) {
  return JSON.stringify({ ...baseManifest, ...overrides });
}

test("valid manifest passes", async () => {
  const { dir, cleanup } = makeDir({ [MANIFEST_NAME]: manifest() });
  const result = await auditExtension(dir);
  assert.equal(result.errors.length, 0, result.errors.join("\n"));
  cleanup();
});

test("missing manifest fails", async () => {
  const { dir, cleanup } = makeDir({ "readme.txt": "hi" });
  const result = await auditExtension(dir);
  assert.ok(result.errors.some((e) => e.includes("missing")));
  cleanup();
});

test("id must match directory name", async () => {
  const { dir, cleanup } = makeDir({
    [MANIFEST_NAME]: manifest({ id: "other-id" }),
  });
  const result = await auditExtension(dir);
  assert.ok(result.errors.some((e) => e.includes("does not match directory")));
  cleanup();
});

test("bad id fails", async () => {
  const { dir, cleanup } = makeDir({
    [MANIFEST_NAME]: manifest({ id: "Bad_ID" }),
  });
  const result = await auditExtension(dir);
  assert.ok(result.errors.some((e) => e.includes("manifest id")));
  cleanup();
});

test("bad version fails", async () => {
  const { dir, cleanup } = makeDir({
    [MANIFEST_NAME]: manifest({ version: "1.0" }),
  });
  const result = await auditExtension(dir);
  assert.ok(result.errors.some((e) => e.includes("semver")));
  cleanup();
});

test("script blocklist mirrors the app sandbox", async () => {
  for (const source of [
    "fetch('https://evil.example')",
    "var w = window",
    "eval('1')",
    "require('fs')",
    "import x from 'y'",
    "document.cookie",
    "globalThis.x = 1",
    "x.__proto__ = {}",
    "new Function('return 1')",
    "process.env.SECRET",
    "localStorage.getItem('k')",
  ]) {
    const { dir, cleanup } = makeDir({
      [MANIFEST_NAME]: manifest({ script: "script.js" }),
      "script.js": `function register(api) { ${source} }`,
    });
    const result = await auditExtension(dir);
    assert.ok(
      result.errors.some((e) => e.includes("blocked pattern")),
      `expected block for ${source}`,
    );
    cleanup();
  }
});

test("script over 32 KiB fails", async () => {
  const { dir, cleanup } = makeDir({
    [MANIFEST_NAME]: manifest({ script: "script.js" }),
    "script.js": `function register(api) {} // ${"x".repeat(33 * 1024)}`,
  });
  const result = await auditExtension(dir);
  assert.ok(result.errors.some((e) => e.includes("script limit")));
  cleanup();
});

test("path traversal in styles fails", async () => {
  const { dir, cleanup } = makeDir({
    [MANIFEST_NAME]: manifest({ styles: ["../escape.css"] }),
  });
  const result = await auditExtension(dir);
  assert.ok(result.errors.some((e) => e.includes("safe relative path")));
  cleanup();
});

test("disallowed file types fail", async () => {
  const { dir, cleanup } = makeDir({
    [MANIFEST_NAME]: manifest(),
    "evil.sh": "echo hi",
    "evil.exe": "MZ",
  });
  const result = await auditExtension(dir);
  assert.ok(result.errors.filter((e) => e.includes("disallowed file type")).length === 2);
  cleanup();
});

test("hidden files fail", async () => {
  const { dir, cleanup } = makeDir({
    [MANIFEST_NAME]: manifest(),
    ".secret": "x",
  });
  const result = await auditExtension(dir);
  assert.ok(result.errors.some((e) => e.includes("hidden file")));
  cleanup();
});

test("secrets in files fail", async () => {
  const { dir, cleanup } = makeDir({
    [MANIFEST_NAME]: manifest(),
    "notes.txt": "key is AKIAIOSFODNN7EXAMPLE",
  });
  const result = await auditExtension(dir);
  assert.ok(result.errors.some((e) => e.includes("AWS access key")));
  cleanup();
});

test("css with remote url fails", async () => {
  const { dir, cleanup } = makeDir({
    [MANIFEST_NAME]: manifest({ styles: ["theme.css"] }),
    "theme.css": ".x { background: url(https://evil.example/t.png) }",
  });
  const result = await auditExtension(dir);
  assert.ok(result.errors.some((e) => e.includes("remote url()")));
  cleanup();
});

test("svg with script or handlers fails", async () => {
  const { dir, cleanup } = makeDir({
    [MANIFEST_NAME]: manifest({ icon: "assets/icon.svg" }),
    "assets/icon.svg": '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>',
  });
  const result = await auditExtension(dir);
  assert.ok(result.errors.some((e) => e.includes("event handler")));
  cleanup();
});

test("missing referenced files fail", async () => {
  const { dir, cleanup } = makeDir({
    [MANIFEST_NAME]: manifest({ icon: "assets/icon.svg" }),
  });
  const result = await auditExtension(dir);
  assert.ok(result.errors.some((e) => e.includes("does not exist")));
  cleanup();
});

test("bad titleRegex fails", async () => {
  const { dir, cleanup } = makeDir({
    [MANIFEST_NAME]: manifest({
      trackRules: [{ match: { titleRegex: "([" }, decoration: {} }],
    }),
  });
  const result = await auditExtension(dir);
  assert.ok(result.errors.some((e) => e.includes("does not compile")));
  cleanup();
});

test("http decoration url fails, https warns nothing", async () => {
  const { dir, cleanup } = makeDir({
    [MANIFEST_NAME]: manifest({
      trackRules: [
        { match: {}, decoration: { iconUrl: "http://evil.example/x.png" } },
      ],
    }),
  });
  const result = await auditExtension(dir);
  assert.ok(result.errors.some((e) => e.includes("must be https")));
  cleanup();
});

test("extension with no effect warns", async () => {
  const { dir, cleanup } = makeDir({ [MANIFEST_NAME]: manifest() });
  const result = await auditExtension(dir);
  assert.equal(result.errors.length, 0);
  assert.ok(result.warnings.some((w) => w.includes("declares no")));
  cleanup();
});

test("buildZip writes a readable archive", () => {
  const zip = buildZip([
    { name: "my-ext/melovian-extension.json", data: Buffer.from("{}") },
    { name: "my-ext/script.js", data: Buffer.from("function register(){}") },
  ]);
  assert.equal(zip.readUInt32LE(0), 0x04034b50);
  assert.equal(zip.readUInt32LE(zip.length - 22), 0x06054b50);

  const again = buildZip([
    { name: "my-ext/melovian-extension.json", data: Buffer.from("{}") },
    { name: "my-ext/script.js", data: Buffer.from("function register(){}") },
  ]);
  assert.deepEqual(zip, again, "zip output must be deterministic");

  try {
    const tmp = mkdtempSync(path.join(repoRoot, ".tmp-zip-"));
    const zipPath = path.join(tmp, "test.zip");
    writeFileSync(zipPath, zip);
    const out = execFileSync("unzip", ["-l", zipPath], { encoding: "utf8" });
    assert.ok(out.includes("my-ext/melovian-extension.json"));
    assert.ok(out.includes("my-ext/script.js"));
    execFileSync("unzip", ["-t", zipPath]);
    rmSync(tmp, { recursive: true, force: true });
  } catch (err) {
    if (err.code === "ENOENT") return; // unzip not installed, skip system check
    throw err;
  }
});
