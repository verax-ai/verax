# Offline install

The three packages install from the npm registry. A host that cannot
reach the registry needs a bundle built on a host that can.

## On a connected host

Check the published attestations first. `npm audit signatures` talks to
the registry (https://docs.npmjs.com/cli/v11/commands/npm-audit) and
does not run without it:

```sh
npm install @verax-ai/body
npm audit signatures
```

Then, from this repository at the version you want to ship:

```sh
npm ci
npm run sbom
npm run offline:bundle
```

`npm run sbom` writes `sbom/verax-<version>.cdx.json`. It packs
`@verax-ai/proxy`, `@verax-ai/inventory` and `@verax-ai/body`, installs
those tarballs into a temporary directory named `verax-sbom`, then runs
`npm sbom --sbom-format cyclonedx --omit dev`
(https://docs.npmjs.com/cli/v11/commands/npm-sbom). The file lists the
three packages and their production dependencies. It does not pass
`--package-lock-only`.

`npm run offline:bundle` writes `verax-offline-<version>/`:

- `packages/*.tgz` — `npm pack --workspace` of the three packages
  (https://docs.npmjs.com/cli/v11/commands/npm-pack)
- `npm-cache/` — filled by installing those tarballs into a temporary
  directory with `--cache` pointed at this folder
  (https://docs.npmjs.com/cli/v11/using-npm/config#cache)
- `sbom/` — the same CycloneDX file, `verax-<version>.cdx.json`
- `SHA256SUMS` — SHA-256 of every file in the bundle except itself
- `INSTALL-OFFLINE.md` — the steps that travel with the bundle

Move the whole `verax-offline-<version>/` directory to the isolated host.
`npm run offline:smoke` builds a bundle and then runs the isolated
install against it.

## On the isolated host

Check the checksums. On a host with GNU coreutils:

```sh
cd verax-offline-<version>
sha256sum -c SHA256SUMS
```

On any host with Node 22.6 or newer, from that directory:

```sh
node --input-type=module -e "import { createHash } from 'node:crypto'; import { readFileSync } from 'node:fs'; for (const line of readFileSync('SHA256SUMS','utf8').split(/\n/)) { if (!line) continue; const [hash, file] = line.split(/ {2}/); const got = createHash('sha256').update(readFileSync(file)).digest('hex'); if (got !== hash) { console.error('mismatch', file); process.exit(1); } } console.log('SHA256SUMS ok');"
```

Install into an empty directory. `--offline` refuses a registry request
(https://docs.npmjs.com/cli/v11/using-npm/config#offline):

```sh
npm install --offline --cache /path/to/verax-offline-<version>/npm-cache --no-audit --no-fund /path/to/verax-offline-<version>/packages/verax-ai-inventory-<version>.tgz /path/to/verax-offline-<version>/packages/verax-ai-proxy-<version>.tgz /path/to/verax-offline-<version>/packages/verax-ai-body-<version>.tgz
npx --no-install verax --version
```

`--no-audit` and `--no-fund` stop those side reports from contacting
the registry (https://docs.npmjs.com/cli/v11/using-npm/config#audit,
https://docs.npmjs.com/cli/v11/using-npm/config#fund).

## Limits

- Provenance attestations cannot be checked on a host that cannot reach
  the registry. Run `npm audit signatures` on the connected host that
  builds the bundle, then move the bundle.
- This path is `npm install` of the three packages. It is not
  `verax install`, which still talks to the registry and writes an
  administrator-owned service.
- The cache is npm's. Produce the bundle on a machine close to the
  isolated host (same OS family) if a dependency ever ships a native
  addon.
- Release workflow `release.yml` writes the CycloneDX file as an
  artifact on both `confirm=check` and `confirm=publish`. It does not
  attach it to the npm publish.
