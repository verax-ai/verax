#!/usr/bin/env node
// Pack the operator GLB for the web. Output is gitignored.

import { statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { NodeIO } from "@gltf-transform/core";
import { ALL_EXTENSIONS } from "@gltf-transform/extensions";
import { dedup, meshopt, prune, quantize, textureCompress } from "@gltf-transform/functions";
import { MeshoptEncoder } from "meshoptimizer";
import sharp from "sharp";

const MAX_BYTES = Math.floor(2.5 * 1024 * 1024);
const root = join(dirname(fileURLToPath(import.meta.url)), "..");

export async function packModel(glbPath, outPath) {
  await MeshoptEncoder.ready;
  const io = new NodeIO().registerExtensions(ALL_EXTENSIONS).registerDependencies({
    "meshopt.encoder": MeshoptEncoder,
  });
  const document = await io.read(glbPath);
  await document.transform(
    dedup(),
    prune(),
    textureCompress({ encoder: sharp, targetFormat: "webp", resize: [1024, 1024], quality: 70, effort: 80 }),
    quantize(),
    meshopt({ encoder: MeshoptEncoder, level: "high" }),
  );
  const bytes = await io.writeBinary(document);
  if (bytes.byteLength > MAX_BYTES) {
    throw new Error(`pack-model: ${bytes.byteLength} bytes exceeds ${MAX_BYTES}`);
  }
  writeFileSync(outPath, bytes);
  return { outPath, bytes: bytes.byteLength };
}

const invoked = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invoked) {
  const glb = process.env.VERAX_MODEL_GLB;
  if (!glb) {
    process.stderr.write("pack-model: set VERAX_MODEL_GLB\n");
    process.exit(78);
  }
  const out = process.argv[2] ?? join(root, "apps", "panel", "public", "verax-body.glb");
  try {
    statSync(glb);
  } catch {
    process.stderr.write(`pack-model: missing ${glb}\n`);
    process.exit(78);
  }
  const result = await packModel(glb, out);
  process.stdout.write(`${result.bytes} ${result.outPath}\n`);
}
