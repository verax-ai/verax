import type { IncomingMessage, ServerResponse } from "node:http";

export const MAX_BODY_BYTES = 1024 * 1024;

export function contentLengthOverLimit(req: IncomingMessage): boolean {
  const raw = req.headers["content-length"];
  if (raw === undefined) return false;
  const n = Number(Array.isArray(raw) ? raw[0] : raw);
  return Number.isFinite(n) && n > MAX_BODY_BYTES;
}

export async function readJsonBody(
  req: IncomingMessage,
  max: number,
): Promise<{ ok: true; value: unknown } | { ok: false; tooLarge: true } | { ok: false; bad: true }> {
  if (contentLengthOverLimit(req)) return { ok: false, tooLarge: true };
  const chunks: Buffer[] = [];
  let seen = 0;
  try {
    for await (const chunk of req) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      seen += buf.length;
      if (seen > max) {
        return { ok: false, tooLarge: true };
      }
      chunks.push(buf);
    }
  } catch {
    return { ok: false, bad: true };
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (text === "") return { ok: true, value: undefined };
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false, bad: true };
  }
}

export function send(res: ServerResponse, status: number, body: unknown, headers?: Record<string, string>): void {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(text),
    "x-content-type-options": "nosniff",
    ...headers,
  });
  res.end(text);
}
