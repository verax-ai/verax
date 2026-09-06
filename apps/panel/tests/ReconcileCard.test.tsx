import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ReconcileCard } from "../src/ReconcileCard.tsx";

afterEach(() => {
  cleanup();
});

describe("external-source card", () => {
  it("shows the channel, scope, and ghost count when a report is present", () => {
    render(
      <ReconcileCard
        report={{
          scope: { channel: "sent", windowStartMs: 20, windowEndMs: 180100, rowCount: 5 },
          matched: [],
          ghost: [{ channel: "sent", externalId: "g", occurredAtMs: 55, subject: "mail.send" }],
          unsent: [],
          outOfScope: [],
        }}
      />,
    );
    expect(screen.getByText(/Dış kaynak: sent/)).toBeTruthy();
    expect(screen.getByText(/kapsam/)).toBeTruthy();
    expect(screen.getByText(/1 hayalet/)).toBeTruthy();
  });

  it("says the external source is not connected when there is no report", () => {
    render(<ReconcileCard report={null} />);
    expect(screen.getByText("dış kaynak bağlı değil")).toBeTruthy();
  });
});
