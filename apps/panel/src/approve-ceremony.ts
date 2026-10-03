import {
  startAuthentication,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialDescriptorJSON,
} from "@simplewebauthn/browser";

import type { ApproveOutcome } from "./observatory/Observatory.tsx";
import { authorizedFetch } from "./session.ts";

/**
 * Sign the approval the screen is showing, then post it.
 *
 * The panel always runs this ceremony. With no operator enrolled the body
 * does not require a signature, but the challenge door still answers. An
 * install in that state cannot sign in, so this control is not reached there.
 */
export async function approveWithPasskey(ref: string, requestHash: string): Promise<ApproveOutcome> {
  const challengeRes = await authorizedFetch(`/api/approve/challenge?ref=${encodeURIComponent(ref)}`);
  const challengeBody = (await challengeRes.json().catch(() => ({}))) as {
    challenge?: unknown;
    rpId?: unknown;
    allowCredentials?: unknown;
    error?: unknown;
  };
  if (!challengeRes.ok) {
    if (challengeRes.status === 404) {
      return {
        ok: false,
        error: typeof challengeBody.error === "string" ? challengeBody.error : "unknown-ref",
      };
    }
    if (challengeRes.status === 503 && challengeBody.error === "passkey-closed") {
      return { ok: false, error: "passkey-closed" };
    }
    return { ok: false, error: `http-${challengeRes.status}` };
  }
  const allowCredentials = descriptors(challengeBody.allowCredentials);
  if (
    typeof challengeBody.challenge !== "string" ||
    challengeBody.challenge === "" ||
    typeof challengeBody.rpId !== "string" ||
    challengeBody.rpId === "" ||
    !allowCredentials
  ) {
    return { ok: false, error: `http-${challengeRes.status}` };
  }
  let assertion: AuthenticationResponseJSON;
  try {
    assertion = await startAuthentication({
      optionsJSON: {
        challenge: challengeBody.challenge,
        rpId: challengeBody.rpId,
        allowCredentials,
        userVerification: "required",
        timeout: 60_000,
      },
    });
  } catch (err) {
    if (cancelled(err)) return { ok: false, error: "approve-cancelled" };
    return { ok: false, error: err instanceof Error ? err.message : "unknown" };
  }
  const res = await authorizedFetch("/api/approve", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ref, requestHash, assertion }),
  });
  const body = (await res.json().catch(() => ({}))) as { allowRef?: unknown; error?: unknown };
  if (res.ok && typeof body.allowRef === "string") {
    return { ok: true, allowRef: body.allowRef };
  }
  return { ok: false, error: typeof body.error === "string" ? body.error : `http-${res.status}` };
}

export function descriptors(value: unknown): PublicKeyCredentialDescriptorJSON[] | null {
  if (!Array.isArray(value)) return null;
  const out: PublicKeyCredentialDescriptorJSON[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object") return null;
    const row = item as { id?: unknown; type?: unknown };
    if (typeof row.id !== "string" || row.id === "" || row.type !== "public-key") return null;
    out.push({ id: row.id, type: "public-key" });
  }
  return out;
}

function errorName(err: unknown): string {
  if (typeof err !== "object" || err === null || !("name" in err)) return "";
  return typeof err.name === "string" ? err.name : "";
}

/** The browser names a dismissed prompt `NotAllowedError` or `AbortError`. */
export function cancelled(err: unknown): boolean {
  const name = errorName(err);
  if (name === "NotAllowedError" || name === "AbortError") return true;
  if (typeof err === "object" && err !== null && "cause" in err) {
    const causeName = errorName(err.cause);
    return causeName === "NotAllowedError" || causeName === "AbortError";
  }
  return false;
}
