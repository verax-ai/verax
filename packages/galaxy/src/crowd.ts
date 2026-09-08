import { projectNdc, type CameraEye, type Ndc } from "./labels.ts";
import type { Point3 } from "./address.ts";

/**
 * Screen gap below which two bodies read as one mark. Fixed in NDC so
 * a far knot merges and a near knot can split. Not a function of how
 * many records sit in the knot: the marker size must not leak a count.
 */
export const BODY_MERGE_NDC = 0.045;

/**
 * Two overlapping octahedrons are still two bodies. A handful in one
 * disk is the smear that has to confess it is a cluster.
 */
export const BODY_CLUSTER_MIN = 5;

export type CrowdBody = {
  readonly id: string;
  readonly at: Point3;
  readonly source: string;
};

export type BodyCluster = {
  readonly id: string;
  readonly at: Point3;
  readonly count: number;
  readonly source: string;
  readonly ids: readonly string[];
};

export type BodyCrowd = {
  readonly clusters: readonly BodyCluster[];
  readonly singles: readonly CrowdBody[];
};

function ndcOf(body: CrowdBody, cam: CameraEye): Ndc | null {
  return projectNdc(body.at, cam);
}

function find(parent: number[], i: number): number {
  let n = i;
  while (parent[n] !== n) n = parent[n]!;
  let k = i;
  while (parent[k] !== k) {
    const next = parent[k]!;
    parent[k] = n;
    k = next;
  }
  return n;
}

function union(parent: number[], a: number, b: number): void {
  const pa = find(parent, a);
  const pb = find(parent, b);
  if (pa !== pb) parent[pa] = pb;
}

/**
 * Groups bodies that sit on top of each other in the image. The count
 * on a cluster is the number of records in that neighborhood, and the
 * source is theirs when they share one, or scene.records when they do
 * not. Records are not dropped: a clustered id is still in `ids`.
 */
export function bodyClusters(bodies: readonly CrowdBody[], cam: CameraEye, mergeNdc = BODY_MERGE_NDC): BodyCrowd {
  if (bodies.length === 0) return { clusters: [], singles: [] };
  const projected: { body: CrowdBody; ndc: Ndc }[] = [];
  const behind: CrowdBody[] = [];
  for (const body of bodies) {
    const ndc = ndcOf(body, cam);
    if (ndc) projected.push({ body, ndc });
    else behind.push(body);
  }
  const n = projected.length;
  const parent = Array.from({ length: n }, (_, i) => i);
  const r2 = mergeNdc * mergeNdc;
  for (let i = 0; i < n; i += 1) {
    const a = projected[i]!.ndc;
    for (let j = i + 1; j < n; j += 1) {
      const b = projected[j]!.ndc;
      const dx = a.x - b.x;
      const dy = a.y - b.y;
      if (dx * dx + dy * dy <= r2) union(parent, i, j);
    }
  }
  const groups = new Map<number, { body: CrowdBody; ndc: Ndc }[]>();
  for (let i = 0; i < n; i += 1) {
    const root = find(parent, i);
    const list = groups.get(root) ?? [];
    list.push(projected[i]!);
    groups.set(root, list);
  }
  const clusters: BodyCluster[] = [];
  const singles: CrowdBody[] = [...behind];
  let clusterIndex = 0;
  for (const list of groups.values()) {
    if (list.length < BODY_CLUSTER_MIN) {
      for (const row of list) singles.push(row.body);
      continue;
    }
    const sources = new Set(list.map((row) => row.body.source));
    const source = sources.size === 1 ? list[0]!.body.source : "scene.records";
    let x = 0;
    let y = 0;
    let z = 0;
    const ids: string[] = [];
    for (const row of list) {
      x += row.body.at.x;
      y += row.body.at.y;
      z += row.body.at.z;
      ids.push(row.body.id);
    }
    const count = list.length;
    clusters.push({
      id: `cluster:${clusterIndex}`,
      at: { x: x / count, y: y / count, z: z / count },
      count,
      source,
      ids,
    });
    clusterIndex += 1;
  }
  return { clusters, singles };
}

/** Fixed NDC size of the cluster mark. Not a function of `count`. */
export const CLUSTER_MARK_NDC = 0.048;

export function clusterMarkScale(_count: number): number {
  return CLUSTER_MARK_NDC;
}

/** The writing on a cluster: the measured count and the source it came from. */
export function clusterLabelText(count: number, source: string): string {
  return `${count} · ${source}`;
}

/**
 * A filled disk for the cluster mark. Same canvas for every count: the
 * mark is not a bar chart.
 */
export function paintClusterMark(canvas: HTMLCanvasElement): boolean {
  const ctx = canvas.getContext("2d");
  if (!ctx) return false;
  const size = 64;
  canvas.width = size;
  canvas.height = size;
  ctx.clearRect(0, 0, size, size);
  ctx.fillStyle = "rgba(207, 230, 255, 0.7)";
  ctx.beginPath();
  ctx.arc(size / 2, size / 2, size / 2 - 2, 0, Math.PI * 2);
  ctx.fill();
  return true;
}
