#!/usr/bin/env node
// Raycast the default camera through figure-box ratios. Writes model-space points.

import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { NodeIO } from "@gltf-transform/core";
import { ALL_EXTENSIONS } from "@gltf-transform/extensions";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const RATIOS = {
  head: [0.508, 0.055],
  face: [0.508, 0.106],
  core: [0.455, 0.237],
  "left-hand": [0.129, 0.439],
  "right-hand": [0.886, 0.434],
  torso: [0.515, 0.48],
  ground: [0.606, 0.918],
};

function applyMat4(m, p) {
  const w = m[3] * p[0] + m[7] * p[1] + m[11] * p[2] + m[15];
  const inv = w === 0 ? 1 : 1 / w;
  return [
    (m[0] * p[0] + m[4] * p[1] + m[8] * p[2] + m[12]) * inv,
    (m[1] * p[0] + m[5] * p[1] + m[9] * p[2] + m[13]) * inv,
    (m[2] * p[0] + m[6] * p[1] + m[10] * p[2] + m[14]) * inv,
  ];
}

function collect(prim, world, triangles) {
  const pos = prim.getAttribute("POSITION");
  if (!pos || prim.getMode() !== 4) return;
  const vertex = (i) => {
    const out = [0, 0, 0];
    pos.getElement(i, out);
    return applyMat4(world, out);
  };
  const indices = prim.getIndices();
  if (indices) {
    const n = indices.getCount();
    for (let i = 0; i + 2 < n; i += 3) {
      triangles.push([vertex(indices.getScalar(i)), vertex(indices.getScalar(i + 1)), vertex(indices.getScalar(i + 2))]);
    }
  } else {
    const n = pos.getCount();
    for (let i = 0; i + 2 < n; i += 3) triangles.push([vertex(i), vertex(i + 1), vertex(i + 2)]);
  }
}

function trianglesOf(document) {
  const triangles = [];
  const visit = (node) => {
    const mesh = node.getMesh();
    if (mesh) for (const prim of mesh.listPrimitives()) collect(prim, node.getWorldMatrix(), triangles);
    for (const child of node.listChildren()) visit(child);
  };
  for (const scene of document.getRoot().listScenes()) {
    for (const node of scene.listChildren()) visit(node);
  }
  return triangles;
}

function bboxOf(triangles) {
  const min = [Infinity, Infinity, Infinity];
  const max = [-Infinity, -Infinity, -Infinity];
  for (const tri of triangles) {
    for (const p of tri) {
      for (let i = 0; i < 3; i += 1) {
        min[i] = Math.min(min[i], p[i]);
        max[i] = Math.max(max[i], p[i]);
      }
    }
  }
  return { min, max };
}

function intersect(orig, dir, tri) {
  const eps = 1e-7;
  const e1 = [tri[1][0] - tri[0][0], tri[1][1] - tri[0][1], tri[1][2] - tri[0][2]];
  const e2 = [tri[2][0] - tri[0][0], tri[2][1] - tri[0][1], tri[2][2] - tri[0][2]];
  const h = [dir[1] * e2[2] - dir[2] * e2[1], dir[2] * e2[0] - dir[0] * e2[2], dir[0] * e2[1] - dir[1] * e2[0]];
  const a = e1[0] * h[0] + e1[1] * h[1] + e1[2] * h[2];
  if (Math.abs(a) < eps) return null;
  const f = 1 / a;
  const s = [orig[0] - tri[0][0], orig[1] - tri[0][1], orig[2] - tri[0][2]];
  const u = f * (s[0] * h[0] + s[1] * h[1] + s[2] * h[2]);
  if (u < 0 || u > 1) return null;
  const q = [s[1] * e1[2] - s[2] * e1[1], s[2] * e1[0] - s[0] * e1[2], s[0] * e1[1] - s[1] * e1[0]];
  const v = f * (dir[0] * q[0] + dir[1] * q[1] + dir[2] * q[2]);
  if (v < 0 || u + v > 1) return null;
  const t = f * (e2[0] * q[0] + e2[1] * q[1] + e2[2] * q[2]);
  return t > eps ? t : null;
}

function rayFor(ratioX, ratioY, box) {
  const cam = [0, 0.2, 5.4];
  const fov = (44 * Math.PI) / 180;
  const aspect = 1;
  const visibleH = 2 * 5.4 * Math.tan(fov / 2);
  const visibleW = visibleH * aspect;
  const fitEdge = 4.2;
  const sx = box.max[0] - box.min[0];
  const sy = box.max[1] - box.min[1];
  const sz = box.max[2] - box.min[2];
  const scale = fitEdge / Math.max(sx, sy, sz, 1e-6);
  const cx = (box.min[0] + box.max[0]) / 2;
  const cy = (box.min[1] + box.max[1]) / 2;
  const cz = (box.min[2] + box.max[2]) / 2;
  const minW = [(-cx + box.min[0]) * scale, (-cy + box.min[1]) * scale, (-cz + box.min[2]) * scale];
  const maxW = [(-cx + box.max[0]) * scale, (-cy + box.max[1]) * scale, (-cz + box.max[2]) * scale];
  const x = minW[0] + (maxW[0] - minW[0]) * ratioX;
  const y = maxW[1] - (maxW[1] - minW[1]) * ratioY;
  const ndcX = x / (visibleW / 2);
  const ndcY = (y - 0.2) / (visibleH / 2);
  const dir = [ndcX * Math.tan(fov / 2) * aspect, ndcY * Math.tan(fov / 2), -1];
  const len = Math.hypot(dir[0], dir[1], dir[2]) || 1;
  return { orig: cam, dir: [dir[0] / len, dir[1] / len, dir[2] / len], fallback: [x / scale + cx, y / scale + cy, cz] };
}

export async function writeAnchors(glbPath, outPath) {
  const io = new NodeIO().registerExtensions(ALL_EXTENSIONS);
  const document = await io.read(glbPath);
  const triangles = trianglesOf(document);
  if (triangles.length === 0) throw new Error("anchors: no triangles");
  const box = bboxOf(triangles);
  const sx = box.max[0] - box.min[0];
  const sy = box.max[1] - box.min[1];
  const sz = box.max[2] - box.min[2];
  const scale = 4.2 / Math.max(sx, sy, sz, 1e-6);
  const cx = (box.min[0] + box.max[0]) / 2;
  const cy = (box.min[1] + box.max[1]) / 2;
  const cz = (box.min[2] + box.max[2]) / 2;
  const fitted = triangles.map((tri) =>
    tri.map((p) => [(p[0] - cx) * scale, (p[1] - cy) * scale, (p[2] - cz) * scale]),
  );
  const out = {};
  for (const [id, [rx, ry]] of Object.entries(RATIOS)) {
    const ray = rayFor(rx, ry, box);
    let best = Infinity;
    let hit = null;
    for (const tri of fitted) {
      const t = intersect(ray.orig, ray.dir, tri);
      if (t != null && t < best) {
        best = t;
        hit = [
          (ray.orig[0] + ray.dir[0] * t) / scale + cx,
          (ray.orig[1] + ray.dir[1] * t) / scale + cy,
          (ray.orig[2] + ray.dir[2] * t) / scale + cz,
        ];
      }
    }
    out[id] = hit ?? ray.fallback;
  }
  writeFileSync(outPath, `${JSON.stringify(out, null, 2)}\n`);
  return out;
}

const invoked = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invoked) {
  const glb = process.env.VERAX_MODEL_GLB;
  if (!glb) {
    process.stderr.write("anchors: set VERAX_MODEL_GLB\n");
    process.exit(78);
  }
  const dest = process.argv[2] ?? join(root, "apps", "body-map", "src", "anchors.json");
  const result = await writeAnchors(glb, dest);
  process.stdout.write(`${Object.keys(result).length} ${dest}\n`);
}
