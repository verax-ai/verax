export function vendorRelRefused(rel: unknown): boolean;
export function vendorServePath(rel: unknown, files: Map<string, string>): string | null;
export function readVendorFile(
  rel: unknown,
  files: Map<string, string>,
  readFileSync: (path: string) => Buffer,
): Buffer | null;
export function collectVendorEsm(vendorRoot: string): Map<string, string>;
