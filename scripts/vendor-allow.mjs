// The enroll and sign-in pages import `/vendor/@simplewebauthn/browser/esm/index.js`,
// and that module imports the rest of the package's `esm` tree. The issuer
// serves only that tree. The list is built once at start from the directory;
// a request is a lookup. Drive letters, UNC, and any other path are refused
// here, before a filesystem call, so `D:/secret.txt` and `//host/share/f`
// never become a path that is opened.

import { readdirSync } from "node:fs";
import { join } from "node:path";

/**
 * True when `rel` must not be turned into a path. No filesystem call.
 * Refuses a drive letter, a leading `/` (which covers `//host/share`),
 * `..`, `\`, `:`, `%`, and an empty segment.
 * @param {unknown} rel
 */
export function vendorRelRefused(rel) {
  if (typeof rel !== "string" || rel.length === 0) return true;
  if (rel.includes("\0") || rel.includes("..") || rel.includes("\\") || rel.includes(":") || rel.includes("%")) {
    return true;
  }
  if (rel.charCodeAt(0) === 47) return true;
  if (rel.split("/").some((part) => part === "" || part === "." || part === "..")) return true;
  return false;
}

/**
 * Absolute path of an allow-listed file, or null. Null does not touch the
 * filesystem: the caller must not read when this returns null.
 * @param {unknown} rel
 * @param {Map<string, string>} files
 */
export function vendorServePath(rel, files) {
  if (vendorRelRefused(rel)) return null;
  if (!(files instanceof Map)) return null;
  const file = files.get(rel);
  return typeof file === "string" ? file : null;
}

/**
 * @param {unknown} rel
 * @param {Map<string, string>} files
 * @param {(path: string) => Buffer} readFileSync
 * @returns {Buffer | null}
 */
export function readVendorFile(rel, files, readFileSync) {
  const path = vendorServePath(rel, files);
  if (path === null) return null;
  return readFileSync(path);
}

/**
 * Files under `<vendorRoot>/esm`, keyed by the URL rel (`esm/index.js`).
 * Symbolic links are not followed and are not served.
 * @param {string} vendorRoot
 * @returns {Map<string, string>}
 */
export function collectVendorEsm(vendorRoot) {
  /** @type {Map<string, string>} */
  const files = new Map();
  walk(join(vendorRoot, "esm"), "esm", files);
  return files;
}

/**
 * @param {string} dir
 * @param {string} prefix
 * @param {Map<string, string>} files
 */
function walk(dir, prefix, files) {
  /** @type {import("node:fs").Dirent[]} */
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    if (ent.isSymbolicLink()) continue;
    const rel = `${prefix}/${ent.name}`;
    if (ent.isDirectory()) {
      walk(join(dir, ent.name), rel, files);
      continue;
    }
    if (!ent.isFile()) continue;
    if (vendorRelRefused(rel)) continue;
    files.set(rel, join(dir, ent.name));
  }
}
