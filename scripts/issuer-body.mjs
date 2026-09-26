// The issuer reads a request body only up to this cap. Past it, the read
// stops and the caller answers 413. The cap is applied while the chunks
// arrive, not after the whole stream has been buffered.

export const ISSUER_BODY_CAP = 64 * 1024;

/**
 * @param {unknown} err
 */
export function payloadTooLarge(err) {
  return Boolean(err && typeof err === "object" && err.code === "PAYLOAD_TOO_LARGE");
}

/**
 * @param {AsyncIterable<Uint8Array | Buffer> & { destroy?: () => void }} req
 */
export async function readIssuerBody(req) {
  /** @type {Buffer[]} */
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (total + buf.length > ISSUER_BODY_CAP) {
      if (typeof req.destroy === "function") req.destroy();
      const err = new Error("payload-too-large");
      err.code = "PAYLOAD_TOO_LARGE";
      throw err;
    }
    total += buf.length;
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}
