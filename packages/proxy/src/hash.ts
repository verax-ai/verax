import { createHash } from "node:crypto";
import { canonical } from "@cedulon/core";

/** SHA-256 of Cedulon's RFC 8785 canonical JSON, 64-char lowercase hex. */
export function sha256Canonical(value: unknown): string {
  return createHash("sha256").update(canonical(value), "utf8").digest("hex");
}
