export const ISSUER_BODY_CAP: number;
export function payloadTooLarge(err: unknown): boolean;
export function readIssuerBody(
  req: AsyncIterable<Uint8Array | Buffer> & { destroy?: () => void },
): Promise<string>;
