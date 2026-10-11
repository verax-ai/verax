// The version of a Verax release is written in several places that nothing
// ties together: the three package.json files, npm, the Docker Hub tag, the
// MCP registry, the platform table, the capability matrix and the Zenodo
// archive. Each publish is a separate step, so one can be skipped and every
// file in the tree still agrees with every other file. 0.4.8 reached npm and
// the registry while Docker Hub stayed at 0.4.7 and Zenodo never archived it.
// This compares what each of them holds against the version in the tree.

export type ReleaseFacts = {
  /** packages/body/package.json */
  version: string;
  /** package name -> version in the tree */
  packages: Record<string, string>;
  /** package name -> npm `latest`, null when npm did not answer */
  npmLatest: Record<string, string | null>;
  /** commit the tag v<version> points at, null when there is no such tag */
  releaseCommit: string | null;
  /** docs/platforms.json `sha` */
  platformsSha: string;
  /** the version in the "Capability matrix — <v>" heading of docs/STATUS.md */
  statusMatrixVersion: string | null;
  /** Docker Hub digest of veraxai/verax:<version>, null when the tag is absent */
  dockerVersionDigest: string | null;
  /** Docker Hub digest of veraxai/verax:latest */
  dockerLatestDigest: string | null;
  /** version of the newest record under the Zenodo concept */
  zenodoLatestVersion: string | null;
  /** version the MCP registry marks isLatest */
  registryLatestVersion: string | null;
};

export function releaseProblems(f: ReleaseFacts): string[] {
  const v = f.version;
  const problems: string[] = [];
  for (const [name, inTree] of Object.entries(f.packages)) {
    if (inTree !== v) problems.push(`${name} is ${inTree} in the tree, body is ${v}`);
    const onNpm = f.npmLatest[name];
    if (onNpm !== inTree) problems.push(`npm latest for ${name} is ${onNpm ?? "unknown"}, the tree has ${inTree}`);
  }
  if (f.releaseCommit === null) {
    problems.push(`no tag v${v}`);
  } else if (f.platformsSha !== f.releaseCommit) {
    problems.push(`docs/platforms.json is for ${f.platformsSha.slice(0, 7)}, v${v} is ${f.releaseCommit.slice(0, 7)}`);
  }
  if (f.statusMatrixVersion !== v) {
    problems.push(`docs/STATUS.md capability matrix is for ${f.statusMatrixVersion ?? "no version"}, not ${v}`);
  }
  if (f.dockerVersionDigest === null) {
    problems.push(`Docker Hub has no veraxai/verax:${v}`);
  } else if (f.dockerLatestDigest !== f.dockerVersionDigest) {
    problems.push(`Docker Hub veraxai/verax:latest is not the ${v} image`);
  }
  if (f.zenodoLatestVersion !== v) {
    problems.push(`Zenodo's newest Verax record is ${f.zenodoLatestVersion ?? "unknown"}, not ${v}`);
  }
  if (f.registryLatestVersion !== v) {
    problems.push(`the MCP registry marks ${f.registryLatestVersion ?? "nothing"} as latest, not ${v}`);
  }
  return problems;
}

/** "## Capability matrix — 0.4.8" -> "0.4.8" */
export function statusMatrixVersion(statusMd: string): string | null {
  const m = /^## Capability matrix — (\d+\.\d+\.\d+)\s*$/m.exec(statusMd);
  return m ? m[1]! : null;
}
