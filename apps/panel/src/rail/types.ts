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
    inputsHash?: string | null;
  };
};

export type RailInputs = {
  principal: { brain: string; scopes: string[] };
  inputs: { id: string; versionHash: string; validFromMs: number; validUntilMs: number }[];
};

export type RailEffect = {
  row: {
    ref: string;
    effectClass: string;
    effectHash: string;
    timestampMs: number;
    actor?: string;
  };
  witnessClass?: string;
  receipt?: unknown;
  attestation?: unknown;
};

export type PolicyRule = {
  id: string;
  tool: string;
  text: string;
};

export type MissingRule = {
  text: null;
  missing: "historical policy unavailable";
};

export type RailRule = PolicyRule | MissingRule;

export type PolicyDocument = {
  rules?: PolicyRule[];
};

export type PolicyBundle = {
  hash: string;
  document: PolicyDocument;
};

export type RailFinding = {
  code: string | null;
  label: string | null;
  summary?: string;
};

export type RailWarning = {
  id: string;
  code: string;
  detail?: string;
};

export type RailAction = {
  record: RailDecision;
  effect: RailEffect | null;
  rule: RailRule | null;
  finding: RailFinding | null;
  guarantee?: "unconditional" | "conditional";
  warnings?: RailWarning[];
  witnessClass?: string | null;
  inputs?: RailInputs | null;
  inputsBound?: boolean;
  trustRoot?: { pinned: boolean; issuerMatches: boolean | null; source: "env" | "own-key" | null };
};
