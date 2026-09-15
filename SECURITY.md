# Security

## Threat model

Extensions run inside Melovian's UI process, so the manifest format is deliberately small. Scripts execute in a `new Function` sandbox with no access to the DOM, network, storage, or Node APIs. Stylesheets are injected as link tags pointed at app-served assets, which is why remote CSS references are banned: a stylesheet can leak what is on screen through background image requests.

The registry side of the pipeline matters too. `registry.json` is the trust root: the app downloads a package URL from the index and verifies its sha256 before installing. A poisoned index is the main attack path, which is why this repo pins every CI action to a commit SHA, runs the audit in strict mode on every pull request, and regenerates the index in CI rather than trusting committed artifacts.

## What the audit does not catch

The audit is a gate, not a proof. It will not catch a script that is individually allowed but combined into something ugly, a css payload that hides content instead of fetching anything, or a package that is simply rude. Human review still applies, and warnings exist to flag the spots that need it (wasm, obfuscation primitives, oversized files).

## Reporting

Report a malicious or vulnerable extension, or a way around the audit or sandbox, through the main project's security policy at https://github.com/melovian-hq/Melovian/blob/main/SECURITY.md. Do not open a public issue for a live sandbox escape.

## Takedown process

When an extension is confirmed malicious or critically unsafe:

1. Run `node tools/delist.mjs <id> --reason "<short reason>"`, then `node tools/build.mjs` and push. The entry stays in the registry with a `delisted` flag so installed clients warn their users. New installs are refused by the app.
2. File a public issue recording the reason and the versions affected once the registry is updated.
3. Versions already downloaded stay on disk. The client warning is the notification path; keep the flag permanent unless the listing was a mistake.

To undo a mistaken listing run `node tools/delist.mjs <id> --restore` and rebuild.

## Signing keys

`registry.json` and every package zip are signed with an Ed25519 key. The public half lives at `keys/registry.pub` and is compiled into the app. The private half is a GitHub Actions secret (`REGISTRY_SIGNING_KEY`) plus a local `keys/registry.key` that must never be committed.

The index carries `keyId`, the first 16 hex characters of sha256(public key). Clients bind the signature to that id, which is what makes rotation safe.

Rotating the key:

1. Run `node tools/keygen.mjs` on a fresh machine or after wiping `keys/registry.key`. It writes the new pair.
2. Commit the new `keys/registry.pub` and update `DefaultRegistryKey` in the app's `internal/extensions/registry.go` so new builds trust it.
3. Set `MELOVIAN_EXTENSION_REGISTRY_EXTRA_KEYS` on the build that ships during the transition so clients accept indexes signed by either key.
4. Update the `REGISTRY_SIGNING_KEY` secret, rebuild, and republish so every artifact is signed by the new key.
5. After one release cycle, drop the old key from the extra-keys list and record the rotation in git history.

If the private key leaks, rotate immediately and treat every index signed after the leak date as suspect.
