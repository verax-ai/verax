export type RailDecision = {
  claims: {
    subject: string;
    decision: "allow" | "deny" | "defer";
    reasonCode: string;
    timestampMs: number;
    decider: string;
    ref: string | null;
    policyHash: string;
    effectHash: string | null;
  };
};

export type RailEffect = {
  row: {
    ref: string;
    effectClass: string;
    effectHash: string;
    timestampMs: number;
    actor?: string;
  };
};

export type PolicyRule = {
  id: string;
  tool: string;
  text: string;
};

export type PolicyBundle = {
  hash: string;
  document: { rules?: PolicyRule[] };
};

export type RailFinding = {
  code: string | null;
  label: string | null;
  summary?: string;
};

export type RailAction = {
  record: RailDecision;
  effect: RailEffect | null;
  rule: PolicyRule | null;
  finding: RailFinding | null;
};
