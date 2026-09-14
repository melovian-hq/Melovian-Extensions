# Security

## Threat model

Extensions run inside Melovian's UI process, so the manifest format is deliberately small. Scripts execute in a `new Function` sandbox with no access to the DOM, network, storage, or Node APIs. Stylesheets are injected as link tags pointed at app-served assets, which is why remote CSS references are banned: a stylesheet can leak what is on screen through background image requests.

The registry side of the pipeline matters too. `registry.json` is the trust root: the app downloads a package URL from the index and verifies its sha256 before installing. A poisoned index is the main attack path, which is why this repo pins every CI action to a commit SHA, runs the audit in strict mode on every pull request, and regenerates the index in CI rather than trusting committed artifacts.

## What the audit does not catch

The audit is a gate, not a proof. It will not catch a script that is individually allowed but combined into something ugly, a css payload that hides content instead of fetching anything, or a package that is simply rude. Human review still applies, and warnings exist to flag the spots that need it (wasm, obfuscation primitives, oversized files).

## Reporting

Report a malicious or vulnerable extension, or a way around the audit or sandbox, through the main project's security policy at https://github.com/melovian-hq/Melovian/blob/main/SECURITY.md. Do not open a public issue for a live sandbox escape.
