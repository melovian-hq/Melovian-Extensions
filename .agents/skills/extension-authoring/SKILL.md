---
name: extension-authoring
description: Author, audit, and publish Melovian registry extensions. Use when creating an extension, editing a manifest, bumping a version, or debugging audit or build failures in this repo.
---

# Melovian extension authoring

## Layout

One extension per directory under `extensions/<id>/`. The manifest is `melovian-extension.json` and the manifest `id` must equal the directory name.

```
extensions/<id>/
  melovian-extension.json   manifest
  CHANGELOG.md              required, newest first
  assets/icon.svg           icon for the gallery card
  script.ts                 optional sandboxed script
  theme.css                 optional stylesheets listed in manifest.styles
```

## Commands

```bash
node tools/new.mjs <id> "Name" [--script] [--styles] [--theme]  # scaffold
node tools/audit.mjs --strict      # audit everything, warnings are fatal
node tools/audit.mjs <dir>         # audit one extension
node --test tools/*.test.mjs       # tool tests
node tools/build.mjs               # rebuild packages/ + registry.json + registry.sig
node tools/build.mjs --check       # verify committed index is in sync
node tools/build.mjs --no-sign     # local dev without the signing key
node tools/delist.mjs <id> --reason "..."   # pull an extension
```

## Manifest contract

- `id`, `name`, `version` (semver) are required.
- `permissions` declares capabilities: `styles`, `script`, `theme`, `track-decorations`, `player-hooks`. The audit fails when the package uses an undeclared capability and warns on declared-but-unused ones.
- `minAppVersion` gates install on the client app version.
- `requires` lists other registry extension ids that must be installed first.
- `settings` declares user-facing fields (`boolean`, `choice`, `text`). Keys are simple identifiers like `muted` or `accent-color`. The app renders a form, stores values per extension, and exposes them to scripts as the frozen `api.settings` object. Only declared keys and correctly typed values reach the sandbox.
- `script` may be `.ts` or `.js`. TypeScript is type-stripped at build time; the zip ships both the source and the compiled `.js` the manifest is rewritten to point at.

## Hard rules the audit enforces

- No `import`, `require`, `fetch`, `XMLHttpRequest`, `eval`, `Function(`, `window`, `document`, `localStorage`, `sessionStorage`, `__proto__`, `constructor`, `process`, `globalThis` in scripts. The sandbox does not expose them anyway.
- Type-safe scripting: use `/// <reference path="../../types/melovian-extension.d.ts" />` and the ambient `melovian` namespace. Imports are banned, so types come from the reference, not modules.
- Safe relative paths only, no hidden files, no symlinks, allowlisted extensions only.
- Script cap 32 KiB, assets 8 MiB, package 32 MiB.
- Remote `url()` in CSS is banned. `iconUrl` decorations must be https.
- SVG assets may not carry scripts, event handlers, or external references.
- No secrets, no long hex or base64 escape runs, no invisible Unicode or bidi controls (Trojan Source class).
- Version is immutable once published. Same version with different bytes fails the build; bump the version and add a changelog entry.

## Changelog format

`CHANGELOG.md` uses `## <version> - YYYY-MM-DD` headings. The newest entry must match the manifest version or the audit fails.

## Signing

`node tools/build.mjs` needs `REGISTRY_SIGNING_KEY` (64-hex seed) or `keys/registry.key`. `node tools/keygen.mjs` creates a pair. Never commit `keys/registry.key`. `registry.json` gets a `keyId` field derived from the public key; see SECURITY.md for rotation.
