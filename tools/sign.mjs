// SPDX-License-Identifier: Apache-2.0
//
// Ed25519 signing helpers shared by build.mjs and the integrity workflow.
//
// The private key is a 64-char hex seed read from the REGISTRY_SIGNING_KEY
// environment variable or keys/registry.key. The public key is committed
// at keys/registry.pub and compiled into the app.

import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(new URL(".", import.meta.url)));

export async function loadPrivateKey() {
  const env = process.env.REGISTRY_SIGNING_KEY?.trim();
  const file = path.join(root, "keys", "registry.key");
  const seed = env || (existsSync(file) ? (await readFile(file, "utf8")).trim() : "");
  if (!/^[0-9a-fA-F]{64}$/.test(seed)) {
    throw new Error(
      "no signing key: set REGISTRY_SIGNING_KEY (64-hex seed) or run tools/keygen.mjs",
    );
  }
  const jwk = {
    kty: "OKP",
    crv: "Ed25519",
    d: Buffer.from(seed, "hex").toString("base64url"),
  };
  const pubFile = path.join(root, "keys", "registry.pub");
  if (existsSync(pubFile)) {
    jwk.x = Buffer.from((await readFile(pubFile, "utf8")).trim(), "hex").toString(
      "base64url",
    );
  }
  return createPrivateKey({ key: jwk, format: "jwk" });
}

export async function loadPublicKeyHex() {
  const pub = path.join(root, "keys", "registry.pub");
  if (!existsSync(pub)) {
    throw new Error("keys/registry.pub missing, run tools/keygen.mjs");
  }
  return (await readFile(pub, "utf8")).trim().toLowerCase();
}

export function signBytes(key, data) {
  return edSign(null, Buffer.from(data), key);
}

export function verifyBytes(pubHex, data, sig) {
  const pub = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(pubHex, "hex").toString("base64url") },
    format: "jwk",
  });
  return edVerify(null, Buffer.from(data), pub, Buffer.from(sig));
}
