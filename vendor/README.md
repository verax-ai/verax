# vendor

Cedulon workspace packages packed from `cedulon` master at commit `da7bf9b`
(2026-09-04). They carry the decision-record and effect-extract APIs that
Verax depends on and that are not yet on npm: the published `@cedulon/*`
line is 0.12.0, and the tarballs here are the unreleased tree that will
become 0.13.0.

The root `package.json` pins every `@cedulon/*` name to these files through
`overrides`, so nothing resolves to the registry by accident.

This directory is temporary. When `@cedulon/core` 0.13.0 or later is on npm,
delete the tarballs, drop the overrides, and depend on the registry version.

Checksums are in `SHA256SUMS`; regenerate with `sha256sum *.tgz > SHA256SUMS`.
