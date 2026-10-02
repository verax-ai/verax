import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const startAuthentication = vi.hoisted(() => vi.fn());
vi.mock("@simplewebauthn/browser", () => ({
  startAuthentication,
}));

import { App } from "../src/App.tsx";
import { approveWithPasskey } from "../src/approve-ceremony.ts";
import { Observatory } from "../src/observatory/Observatory.tsx";
import { panelCopy } from "../src/copy.ts";
import { rememberToken } from "../src/session.ts";
import type { PendingApproval, RailAction } from "../src/rail/types.ts";
import { setLang } from "./with-lang.ts";

afterEach(() => {
  cleanup();
});

beforeEach(() => {
  setLang("tr");
});

const waiting: PendingApproval = {
  ref: "d-open",
  requestHash: "ab".repeat(32),
  subject: "spend",
  ruleText: "Sample spend needs operator approval.",
  inputsSummary: { count: 0, ids: [] },
  amount: 1000,
  currency: "TRY",
  payee: "example-payee",
  expiresAtMs: 9_999_999_999_999,
  status: "pending",
  brain: "sample-brain",
};

const resolved: PendingApproval = { ...waiting, ref: "d-done", status: "approved" };

const deferRecord: RailAction = {
  record: {
    claims: {
      subject: "spend",
      decision: "defer",
      reasonCode: "approval-required",
      timestampMs: 1_788_800_000_000,
      decider: "verax-proxy",
      ref: "d-open",
      requestHash: "ab".repeat(32),
      policyHash: "aa".repeat(32),
      effectHash: null,
    },
  },
  effect: null,
  rule: { id: "spend-sample", tool: "spend", text: "Sample spend needs operator approval." },
  finding: null,
  inputs: { principal: { brain: "sample-brain", scopes: ["verax:pay"] }, inputs: [] },
  inputsBound: true,
};

const allowRecord: RailAction = {
  ...deferRecord,
  record: {
    claims: {
      ...deferRecord.record.claims,
      decision: "allow",
      reasonCode: "approved-by-operator",
      ref: "a-open",
    },
  },
};

function open(extra: Record<string, unknown> = {}) {
  render(<Observatory actions={[]} status="ok" demo={false} pending={[waiting, resolved]} {...extra} />);
  fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
}

/**
 * An approval is money leaving, and it cannot be taken back. That shapes what
 * the screen owes the operator: never a button that cannot work, never an
 * approval without being asked first, never a claim of success that the body
 * did not make.
 */
describe("approving from the screen", () => {
  it("draws no button when the session cannot approve", () => {
    open();
    expect(screen.queryByRole("button", { name: panelCopy()["approve.button"] })).toBeNull();
  });

  it("offers it only on what is still waiting", () => {
    open({ canApprove: true, onApprove: vi.fn() });
    const buttons = screen.getAllByRole("button", { name: panelCopy()["approve.button"] });
    // Two rows are listed; only the pending one is a decision still open.
    expect(buttons.length).toBe(1);
  });

  it("asks before it approves, and names what is being approved", () => {
    const onApprove = vi.fn();
    open({ canApprove: true, onApprove });
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    // The tap opens the question. It does not approve.
    expect(onApprove).not.toHaveBeenCalled();
    const asked = screen.getByTestId("approve-confirm").textContent ?? "";
    expect(asked).toContain("10,00");
    expect(asked).toContain("example-payee");
    expect(asked).toContain("Sample spend needs operator approval.");
  });

  it("sends the ref and the hash the screen was showing", async () => {
    const onApprove = vi.fn(async () => ({ ok: true as const, allowRef: "a-1" }));
    open({ canApprove: true, onApprove });
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.yes"] }));
    await waitFor(() => {
      expect(onApprove).toHaveBeenCalledWith("d-open", "ab".repeat(32));
    });
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).toContain("a-1");
    });
  });

  it("says the sample was not sent instead of claiming it approved one", async () => {
    const onApprove = vi.fn(async () => ({ ok: false as const, error: "sample-not-sent" }));
    open({ canApprove: true, onApprove });
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.yes"] }));
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).toBe(panelCopy()["approve.sample"]);
    });
  });

  it("says the request changed instead of claiming it approved one", async () => {
    const onApprove = vi.fn(async () => ({ ok: false as const, error: "stale" }));
    open({ canApprove: true, onApprove });
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.yes"] }));
    await waitFor(() => {
      const said = screen.getByTestId("approve-outcome").textContent ?? "";
      expect(said).toBe(panelCopy()["approve.stale"]);
    });
  });

  it("repeats the body's own reason when it refuses for another cause", async () => {
    const onApprove = vi.fn(async () => ({ ok: false as const, error: "already-resolved" }));
    open({ canApprove: true, onApprove });
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.yes"] }));
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).toContain("already-resolved");
    });
  });
});

function openRecords(extra: Record<string, unknown> = {}) {
  render(
    <Observatory
      actions={[deferRecord, allowRecord]}
      status="ok"
      demo={false}
      pending={[waiting, resolved]}
      {...extra}
    />,
  );
}

describe("approving from the record", () => {
  it("draws the control on a waiting record in the detail pane", () => {
    openRecords({ canApprove: true, onApprove: vi.fn() });
    const waitingRow = screen.getAllByRole("button").find((b) => (b.textContent ?? "").includes("bekliyor"));
    expect(waitingRow).toBeTruthy();
    fireEvent.click(waitingRow!);
    expect(screen.getByTestId("record-approve")).toBeTruthy();
    expect(screen.getByRole("button", { name: panelCopy()["approve.button"] })).toBeTruthy();
  });

  it("draws no control on a record that is not waiting", () => {
    openRecords({ canApprove: true, onApprove: vi.fn() });
    const allowed = screen.getAllByRole("button").find((b) => (b.textContent ?? "").includes("onaylandı"));
    expect(allowed).toBeTruthy();
    fireEvent.click(allowed!);
    expect(screen.queryByTestId("record-approve")).toBeNull();
  });

  it("draws no control when the session cannot approve", () => {
    openRecords({ onApprove: vi.fn() });
    const waitingRow = screen.getAllByRole("button").find((b) => (b.textContent ?? "").includes("bekliyor"));
    fireEvent.click(waitingRow!);
    expect(screen.queryByRole("button", { name: panelCopy()["approve.button"] })).toBeNull();
    expect(screen.queryByTestId("record-approve")).toBeNull();
  });
});

const SIGNED = {
  id: "cred-1",
  rawId: "cred-1",
  type: "public-key" as const,
  response: {
    clientDataJSON: "Y2xpZW50",
    authenticatorData: "YXV0aA",
    signature: "c2ln",
  },
  clientExtensionResults: {},
};

const CHALLENGE = {
  challenge: "Y2hhbGxlbmdl",
  rpId: "localhost",
  allowCredentials: [{ id: "cred-1", type: "public-key" }],
};

function postsOf(fetchMock: ReturnType<typeof vi.fn>): RequestInit[] {
  return fetchMock.mock.calls
    .filter((call) => {
      const init = call[1] as RequestInit | undefined;
      return String(call[0]) === "/api/approve" && init?.method === "POST";
    })
    .map((call) => call[1] as RequestInit);
}

/**
 * The button asks the body for a challenge and posts the authenticator's
 * answer. The sample scenario never reaches that door.
 */
describe("signing an approval", () => {
  afterEach(() => {
    rememberToken(null);
    vi.unstubAllGlobals();
  });

  beforeEach(() => {
    startAuthentication.mockReset();
  });

  async function confirm(): Promise<void> {
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.yes"] }));
  }

  it("asks for the challenge, signs it, and posts the assertion", async () => {
    startAuthentication.mockResolvedValue(SIGNED);
    const fetchMock = vi.fn(async (input: RequestInfo) => {
      const url = String(input);
      if (url.startsWith("/api/approve/challenge")) {
        return new Response(JSON.stringify(CHALLENGE), { status: 200 });
      }
      return new Response(JSON.stringify({ allowRef: "a-1" }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    open({ canApprove: true, onApprove: (ref: string, requestHash: string) => approveWithPasskey(ref, requestHash) });
    await confirm();
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).toContain("a-1");
    });
    const challenge = fetchMock.mock.calls.find((call) => String(call[0]).startsWith("/api/approve/challenge"));
    expect(String(challenge?.[0])).toBe("/api/approve/challenge?ref=d-open");
    expect(startAuthentication).toHaveBeenCalledWith({
      optionsJSON: {
        challenge: CHALLENGE.challenge,
        rpId: CHALLENGE.rpId,
        allowCredentials: CHALLENGE.allowCredentials,
        userVerification: "required",
        timeout: 60_000,
      },
    });
    const posts = postsOf(fetchMock);
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0]?.body))).toEqual({
      ref: "d-open",
      requestHash: "ab".repeat(32),
      assertion: SIGNED,
    });
  });

  it("shows the cancelled sentence and does not post when the passkey prompt is dismissed", async () => {
    startAuthentication.mockRejectedValue(Object.assign(new Error("dismissed"), { name: "NotAllowedError" }));
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(CHALLENGE), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    open({ canApprove: true, onApprove: (ref: string, requestHash: string) => approveWithPasskey(ref, requestHash) });
    await confirm();
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).toBe(panelCopy()["approve.cancelled"]);
    });
    expect(postsOf(fetchMock)).toHaveLength(0);
  });

  it("shows the cancelled sentence and does not post when the ceremony is aborted", async () => {
    startAuthentication.mockRejectedValue(Object.assign(new Error("aborted"), { name: "AbortError" }));
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(CHALLENGE), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    open({ canApprove: true, onApprove: (ref: string, requestHash: string) => approveWithPasskey(ref, requestHash) });
    await confirm();
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).toBe(panelCopy()["approve.cancelled"]);
    });
    expect(postsOf(fetchMock)).toHaveLength(0);
  });

  it("shows that passkey is closed and does not post when the challenge is closed", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ error: "passkey-closed" }), { status: 503 }));
    vi.stubGlobal("fetch", fetchMock);
    open({ canApprove: true, onApprove: (ref: string, requestHash: string) => approveWithPasskey(ref, requestHash) });
    await confirm();
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).toBe(panelCopy()["approve.passkeyClosed"]);
    });
    expect(startAuthentication).not.toHaveBeenCalled();
    expect(postsOf(fetchMock)).toHaveLength(0);
  });

  it("says unknown-ref when the challenge is missing and does not post", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ error: "unknown-ref" }), { status: 404 }));
    vi.stubGlobal("fetch", fetchMock);
    open({ canApprove: true, onApprove: (ref: string, requestHash: string) => approveWithPasskey(ref, requestHash) });
    await confirm();
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).toContain("unknown-ref");
    });
    expect(startAuthentication).not.toHaveBeenCalled();
    expect(postsOf(fetchMock)).toHaveLength(0);
  });

  it("names the status when the challenge is forbidden and does not post", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ error: "scope-missing" }), { status: 403 }));
    vi.stubGlobal("fetch", fetchMock);
    open({ canApprove: true, onApprove: (ref: string, requestHash: string) => approveWithPasskey(ref, requestHash) });
    await confirm();
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).toContain("http-403");
    });
    expect(screen.getByTestId("approve-outcome").textContent).not.toContain("scope-missing");
    expect(startAuthentication).not.toHaveBeenCalled();
    expect(postsOf(fetchMock)).toHaveLength(0);
  });

  it("leaves the sample scenario off the network", async () => {
    vi.stubGlobal("location", {
      search: "?demo=1&lang=tr",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign: vi.fn(),
    });
    const fetchMock = vi.fn(async () => new Response("{}", { status: 404 }));
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => {
      expect(document.querySelector(".record-row.defer")).toBeTruthy();
    });
    fireEvent.click(document.querySelector(".record-row.defer")!);
    await confirm();
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).toBe(panelCopy()["approve.sample"]);
    });
    expect(fetchMock.mock.calls.filter((call) => String(call[0]).includes("/api/approve"))).toHaveLength(0);
    expect(startAuthentication).not.toHaveBeenCalled();
  });
});
