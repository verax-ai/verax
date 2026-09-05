import { createHash } from "node:crypto";
import { canonical } from "@cedulon/core";

/** SHA-256 of Cedulon's RFC 8785 canonical JSON, 64-char lowercase hex. */
export function sha256Canonical(value: unknown): string {
  return createHash("sha256").update(canonical(value), "utf8").digest("hex");
}

/** Decision and effect rows hash this same descriptor on a successful allow. */
export function effectDescriptor(tool: string, args: Record<string, unknown>, threw = false): Record<string, unknown> {
  return threw ? { tool, arguments: args, threw: true } : { tool, arguments: args };
}
