# Melovian-Extensions

Community extension registry for [Melovian](https://github.com/melovian-hq/Melovian), the music player for Subsonic-compatible servers and local folders.

Every directory under `extensions/` is one installable package: a `melovian-extension.json` manifest plus whatever icons, stylesheets, and sandboxed scripts it needs. CI audits each package and builds it into a signed-checksum zip listed in `registry.json`, which is what the website gallery and the in-app browser read.

## Installing an extension

Two ways in:

- In Melovian, open Settings, Extensions, and use the registry browser. The app downloads the zip from the published registry and verifies its sha256 before installing.
- Or download the zip for the extension you want and drop it on the upload box in Settings, Extensions. Zips come from the `dist/` listing on the published registry site.

## Submitting an extension

1. Fork this repo and add `extensions/<id>/`. The id is also the directory name: lowercase, digits and dashes, 63 chars max.
2. Write a `melovian-extension.json` (schema in `schemas/manifest.schema.json`). Look at the existing extensions for working examples of `trackRules`, `styles`, `appTheme`, and `script`.
3. Run `npm run audit` locally. Fix every error. CI runs `--strict`, so fix the warnings too.
4. Run `npm run build` and commit the regenerated `registry.json`. Do not commit `dist/`.
5. Open a pull request. One extension per PR.

## What the audit checks

`tools/audit.mjs` enforces the same rules the app enforces at install and load time, plus a few that only make sense in a shared registry:

- Manifest id format, semver version, and id matching the directory name
- Relative paths only for icon, image, styles, and script. No traversal, no absolute paths
- File allowlist: json, js, mjs, wasm, css, txt, md, images, fonts. Nothing else ships
- Per-file cap of 8 MiB, package cap of 32 MiB, script cap of 32 KiB
- The script sandbox blocklist: no fetch, XHR, import, require, eval, Function, DOM, storage, or process access
- No symlinks, hidden files, or platform junk in packages
- Secret patterns (private keys, tokens, JWTs) in any text file
- CSS may not load remote resources (`@import`, remote `url()`)
- SVG may not carry scripts, event handlers, or `javascript:` URLs
- Decoration URLs must be https or paths inside the package
- `titleRegex` must compile and stay under 256 chars

Warnings do not block a local build but do block CI. Things the audit flags for human review include wasm payloads and obfuscation-shaped code (long base64 blobs, `atob`, `String.fromCharCode`).

## Registry format

`registry.json` is generated, never hand-edited. Each entry carries the manifest fields, capability counts, the audit verdict, and a `package` object with the zip URL, byte size, and sha256. The schema lives in `schemas/registry.schema.json`. The app fetches this index, resolves the package URL itself, downloads the zip, and installs only when the sha256 matches.

## Commands

```bash
npm run audit         # audit all extensions, warnings allowed
npm run audit:strict  # audit all extensions, warnings fail
npm run build         # write dist/*.zip and registry.json
npm run check         # strict audit + verify registry.json is in sync
npm test              # node:test suite for the tools
```

Needs Node 22 or newer. No dependencies; the tools are plain node stdlib.
