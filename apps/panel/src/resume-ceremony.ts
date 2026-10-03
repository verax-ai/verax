import { startAuthentication, type AuthenticationResponseJSON } from "@simplewebauthn/browser";

import { cancelled, descriptors } from "./approve-ceremony.ts";
import { authorizedFetch } from "./session.ts";
import type { HaltState, SwitchOutcome } from "./StopSwitch.tsx";

/**
 * Sign the resume, then post it. A resume lets every held call through again,
 * so the body asks for the operator's passkey once one is enrolled. The
 * challenge names the newest halt-history line, so a signature made here fits
 * this resume and no later one.
 *
 * Stopping does not come through here: a halt is one press and never waits
 * for a passkey.
 */
export async function resumeWithPasskey(): Promise<SwitchOutcome> {
  const challengeRes = await authorizedFetch("/api/resume/challenge");
  const challengeBody = (await challengeRes.json().catch(() => ({}))) as {
    challenge?: unknown;
    rpId?: unknown;
    allowCredentials?: unknown;
    error?: unknown;
  };
  if (!challengeRes.ok) {
    if (challengeRes.status === 503 && challengeBody.error === "passkey-closed") {
      return { ok: false, error: "passkey-closed" };
    }
    return { ok: false, error: typeof challengeBody.error === "string" ? challengeBody.error : `http-${challengeRes.status}` };
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
    if (cancelled(err)) return { ok: false, error: "resume-cancelled" };
    return { ok: false, error: err instanceof Error ? err.message : "unknown" };
  }
  const res = await authorizedFetch("/api/resume", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ assertion }),
  });
  const body = (await res.json().catch(() => ({}))) as HaltState & { error?: unknown };
  if (res.ok && typeof body.halted === "boolean") return { ok: true, state: body };
  return { ok: false, error: typeof body.error === "string" ? body.error : `http-${res.status}` };
}
