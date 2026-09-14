#!/usr/bin/env node
/*
 * Generates the Ed25519 keypair used to sign registry packages.
 *
 *   node tools/keygen.mjs
 *
 * Writes keys/registry.pub (committed) and keys/registry.key (gitignored,
 * 64-char hex seed). The private key also lives in the GitHub Actions
 * secret REGISTRY_SIGNING_KEY for the publish workflow. The public key
 * is compiled into the Melovian app as the trust anchor.
 */

import { generateKeyPairSync } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(new URL(".", import.meta.url)));
const keysDir = path.join(root, "keys");

const { publicKey, privateKey } = generateKeyPairSync("ed25519");

// JWK d is the raw 32-byte seed (base64url), x is the public key.
const seedHex = Buffer.from(
  privateKey.export({ format: "jwk" }).d,
  "base64url",
).toString("hex");
const pubHex = Buffer.from(
  publicKey.export({ format: "jwk" }).x,
  "base64url",
).toString("hex");

await mkdir(keysDir, { recursive: true });
await writeFile(path.join(keysDir, "registry.key"), `${seedHex}\n`, { mode: 0o600 });
await writeFile(path.join(keysDir, "registry.pub"), `${pubHex}\n`);

console.log(`wrote keys/registry.pub (${pubHex})`);
console.log("wrote keys/registry.key (gitignored, keep it secret)");
console.log("add the seed to GitHub as the REGISTRY_SIGNING_KEY secret");
console.log("compile the public key into the app as DefaultRegistryKey");
