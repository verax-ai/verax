#!/usr/bin/env node
// Area-weighted surface samples. Reads VERAX_MODEL_GLB via gltf-transform
// (no THREE.GLTFLoader - that wants a DOM). Math.random is not used.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { NodeIO } from "@gltf-transform/core";
import { ALL_EXTENSIONS } from "@gltf-transform/extensions";

const COUNT = 60_000;
const SEED = 0x56455258;
const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function triangleArea(a, b, c) {
  const ux = b[0] - a[0];
  const uy = b[1] - a[1];
  const uz = b[2] - a[2];
  const vx = c[0] - a[0];
  const vy = c[1] - a[1];
  const vz = c[2] - a[2];
  const cx = uy * vz - uz * vy;
  const cy = uz * vx - ux * vz;
  const cz = ux * vy - uy * vx;
  return 0.5 * Math.hypot(cx, cy, cz);
}

function applyMat4(m, p) {
  const x = p[0];
  const y = p[1];
  const z = p[2];
  const w = m[3] * x + m[7] * y + m[11] * z + m[15];
  const inv = w === 0 ? 1 : 1 / w;
  return [
    (m[0] * x + m[4] * y + m[8] * z + m[12]) * inv,
    (m[1] * x + m[5] * y + m[9] * z + m[13]) * inv,
    (m[2] * x + m[6] * y + m[10] * z + m[14]) * inv,
  ];
}

function collectPrimitive(prim, world, triangles) {
  const pos = prim.getAttribute("POSITION");
  if (!pos) return;
  if (prim.getMode() !== 4) return;
  const indices = prim.getIndices();
  const vertex = (i) => {
    const out = [0, 0, 0];
    pos.getElement(i, out);
    return applyMat4(world, out);
  };
  if (indices) {
    const n = indices.getCount();
    for (let i = 0; i + 2 < n; i += 3) {
      triangles.push([vertex(indices.getScalar(i)), vertex(indices.getScalar(i + 1)), vertex(indices.getScalar(i + 2))]);
    }
  } else {
    const n = pos.getCount();
    for (let i = 0; i + 2 < n; i += 3) {
      triangles.push([vertex(i), vertex(i + 1), vertex(i + 2)]);
    }
  }
}

function readTriangles(document) {
  const triangles = [];
  const visit = (node) => {
    const world = node.getWorldMatrix();
    const mesh = node.getMesh();
    if (mesh) {
      for (const prim of mesh.listPrimitives()) collectPrimitive(prim, world, triangles);
    }
    for (const child of node.listChildren()) visit(child);
  };
  const scenes = document.getRoot().listScenes();
  if (scenes.length === 0) {
    for (const mesh of document.getRoot().listMeshes()) {
      for (const prim of mesh.listPrimitives()) {
        collectPrimitive(prim, [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1], triangles);
      }
    }
    return triangles;
  }
  for (const scene of scenes) {
    for (const node of scene.listChildren()) visit(node);
  }
  return triangles;
}

function prefixAreas(areas) {
  const prefix = new Float64Array(areas.length);
  let acc = 0;
  for (let i = 0; i < areas.length; i += 1) {
    acc += areas[i] ?? 0;
    prefix[i] = acc;
  }
  return prefix;
}

function pickTriangle(rand, prefix, total) {
  const x = rand() * total;
  let lo = 0;
  let hi = prefix.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (prefix[mid] < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function sampleOnTriangle(rand, tri) {
  let u = rand();
  let v = rand();
  if (u + v > 1) {
    u = 1 - u;
    v = 1 - v;
  }
  const w = 1 - u - v;
  const [a, b, c] = tri;
  return [a[0] * w + b[0] * u + c[0] * v, a[1] * w + b[1] * u + c[1] * v, a[2] * w + b[2] * u + c[2] * v];
}

export async function samplePoints(glbPath, outDir) {
  const glb = readFileSync(glbPath);
  const sourceSha256 = createHash("sha256").update(glb).digest("hex");
  const io = new NodeIO().registerExtensions(ALL_EXTENSIONS);
  const document = await io.read(glbPath);
  const triangles = readTriangles(document);
  if (triangles.length === 0) throw new Error("sample-points: no TRIANGLES primitives");
  const areas = triangles.map((t) => triangleArea(t[0], t[1], t[2]));
  const total = areas.reduce((s, a) => s + a, 0);
  if (!(total > 0)) throw new Error("sample-points: zero area");
  const prefix = prefixAreas(areas);
  const rand = mulberry32(SEED);
  const points = [];
  let minx = Infinity;
  let miny = Infinity;
  let minz = Infinity;
  let maxx = -Infinity;
  let maxy = -Infinity;
  let maxz = -Infinity;
  for (let i = 0; i < COUNT; i += 1) {
    const p = sampleOnTriangle(rand, triangles[pickTriangle(rand, prefix, total)]);
    points.push(p);
    minx = Math.min(minx, p[0]);
    miny = Math.min(miny, p[1]);
    minz = Math.min(minz, p[2]);
    maxx = Math.max(maxx, p[0]);
    maxy = Math.max(maxy, p[1]);
    maxz = Math.max(maxz, p[2]);
  }
  const dx = maxx - minx || 1;
  const dy = maxy - miny || 1;
  const dz = maxz - minz || 1;
  const body = Buffer.alloc(32 + COUNT * 6);
  body.writeUInt32LE(1, 0);
  body.writeUInt32LE(COUNT, 4);
  body.writeFloatLE(minx, 8);
  body.writeFloatLE(miny, 12);
  body.writeFloatLE(minz, 16);
  body.writeFloatLE(maxx, 20);
  body.writeFloatLE(maxy, 24);
  body.writeFloatLE(maxz, 28);
  for (let i = 0; i < COUNT; i += 1) {
    const p = points[i];
    const o = 32 + i * 6;
    body.writeUInt16LE(Math.max(0, Math.min(65535, Math.round(((p[0] - minx) / dx) * 65535))), o);
    body.writeUInt16LE(Math.max(0, Math.min(65535, Math.round(((p[1] - miny) / dy) * 65535))), o + 2);
    body.writeUInt16LE(Math.max(0, Math.min(65535, Math.round(((p[2] - minz) / dz) * 65535))), o + 4);
  }
  mkdirSync(outDir, { recursive: true });
  const binPath = join(outDir, "verax-points.bin");
  const jsonPath = join(outDir, "verax-points.json");
  writeFileSync(binPath, body);
  const meta = {
    version: 1,
    count: COUNT,
    bbox: { min: [minx, miny, minz], max: [maxx, maxy, maxz] },
    sourceSha256,
  };
  writeFileSync(jsonPath, `${JSON.stringify(meta, null, 2)}\n`);
  return { binPath, jsonPath, sha256: createHash("sha256").update(body).digest("hex"), meta };
}

const invoked = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invoked) {
  const glb = process.env.VERAX_MODEL_GLB;
  if (!glb) {
    process.stderr.write("sample-points: set VERAX_MODEL_GLB\n");
    process.exit(78);
  }
  const out = process.argv[2] ?? join(root, "apps", "panel", "public");
  const result = await samplePoints(glb, out);
  process.stdout.write(`${result.sha256} ${result.binPath}\n`);
}
