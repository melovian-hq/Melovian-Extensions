# Contributing

## Rules of the registry

- One extension per pull request.
- The manifest id must equal the directory name and match `^[a-z0-9][a-z0-9-]{0,62}$`.
- Every package must pass `node tools/audit.mjs --strict` and `node --test tools/*.test.mjs`.
- Regenerate and commit `registry.json` with `node tools/build.mjs`. The `dist/` directory is CI output and stays out of git.
- Include an `assets/icon.svg` (or png) so the gallery card is not a letter avatar.
- Extension code must be Apache-2.0 compatible. By submitting you agree your contribution ships under this repo's license.

## What belongs here

Extensions customize how Melovian looks and decorates tracks: `trackRules` for per-track styling, `styles` for stylesheets, `appTheme` for named chrome themes, and `script` for sandboxed logic that registers rules at runtime.

Things that do not fit the model, like new settings panels or server features, belong in the main repo as bundled extensions or core features.

## Review notes

Scripts get extra scrutiny. The sandbox blocks network, DOM, and storage access, but reviewers should still read every line of submitted `.js` and `.css`. If a package needs a capability the manifest does not model, say so in the PR instead of working around the audit.
