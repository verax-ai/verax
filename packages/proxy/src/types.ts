import type { DecisionKind, SignedDecisionRecord } from "@cedulon/core";
import type { EffectRow, SignedEffectExtract } from "@cedulon/effect-extract";

/** Who asked. G2 fills `brain` from JWT `sub` and `scopes` from `scope`. */
export type Principal = {
  brain: string;
  scopes: ReadonlySet<string>;
  /** JWT `iss`. Optional so existing fixtures stay `{ brain, scopes }`. */
  iss?: string;
  /** Explicit JWT `tenant` claim, when the issuer sends one. */
  tenant?: string;
  /** Explicit JWT `org` claim, when the issuer sends one and `tenant` is absent. */
  org?: string;
};

/** Same shape as `@cedulon/mcp-guard` so a later wrap can sit on this type. */
export type ToolCall = {
  name: string;
  arguments: Record<string, unknown>;
};

/** Same shape as `@cedulon/mcp-guard`. claimedHash is a side field; it does not enter the ledger or audit. */
export type ToolResult = {
  content: { type: "text"; text: string }[];
  isError: boolean;
  claimedHash?: string;
};

export type PolicyDecision = {
  decision: DecisionKind;
  reasonCode: string;
  rule: string | null;
};

export type PolicyEvalCtx = {
  spentTodayMinor?: (currency: string) => number;
};

export type PolicyLimits = {
  ratePerMinute?: number;
  dailyMax?: number;
  diskFreeBytes: number;
};

export type Policy = {
  hash: string;
  approvalTtlMs: number;
  limits: PolicyLimits;
  /** Document-root posture. Absent keeps today's optional `_inputs`. */
  requireInputs?: boolean;
  evaluate(call: ToolCall, principal: Principal, ctx?: PolicyEvalCtx): PolicyDecision;
  rule(id: string | null): { id: string; text: string } | null;
};

export type WitnessClass = "self" | "same-org" | "third-party" | "regulated";

export type EffectAttestation = {
  coseHex: string;
};

export type LedgerEffect = {
  row: EffectRow;
  witnessClass: WitnessClass;
  /** Hash of the ToolResult (or thrown payload). Not an EffectRow field. */
  resultHash?: string;
  /** One-row extract signed at call time. */
  receipt?: SignedEffectExtract;
  /** Signed { ref, effectHash, witnessClass, resultHash } via COSE Sign1. */
  attestation?: EffectAttestation;
};

export type RecordSigner = {
  privateKeyPem: string;
  publicKeyPem: string;
};

export type EffectSigner = {
  privateKeyPem: string;
  publicKeyPem: string;
};

export type ExtractWindow = {
  startMs: number;
  endMs: number;
};

/**
 * Third implementations (a later obsigna daemon) must be able to sit here.
 * Append is async on purpose: no synchronous-file assumption.
 */
export type Ledger = {
  appendDecision(signed: SignedDecisionRecord): Promise<void>;
  appendDecisionChained(build: (prevRecordHash: string | null) => SignedDecisionRecord): Promise<void>;
  appendEffect(row: EffectRow, witnessClass?: WitnessClass, resultHash?: string): Promise<void>;
  decisions(): Promise<SignedDecisionRecord[]>;
  effects(): Promise<LedgerEffect[]>;
  lastDecisionHash(): Promise<string | null>;
  exportExtract(window: ExtractWindow, signer: EffectSigner): Promise<SignedEffectExtract>;
};

export type DecisionInputRow = {
  id: string;
  versionHash: string;
  validFromMs: number;
  validUntilMs: number;
  /** Optional provenance. Same idea as memory.put `source`; additive. */
  source?: Record<string, unknown>;
};

export type DecisionInputs = {
  principal: { brain: string; scopes: string[]; iss?: string; tenant?: string; org?: string };
  inputs: DecisionInputRow[];
  approver?: { id: string; via: "cli" | "proxy"; resolves: string };
};

export type InputsLog = {
  append(ref: string, inputs: DecisionInputs): Promise<void>;
  get(ref: string): Promise<DecisionInputs | null>;
};

export type ResolvedInput = {
  versionHash: string;
  validFromMs: number;
  validUntilMs: number;
};

export type ProxyDeps = {
  policy: Policy;
  recordSigner: RecordSigner;
  effectSigner: EffectSigner;
  ledger: Ledger;
  now: () => number;
  nonce: () => string;
  inner: (call: ToolCall, principal: Principal, ref?: string) => Promise<ToolResult>;
  inputsLog?: InputsLog;
  resolveInput?: (id: string, principal?: Principal) => Promise<ResolvedInput | null>;
  /** True when the call names another tenant's memory id or decision ref. */
  checkTenantMismatch?: (call: ToolCall, principal: Principal) => Promise<boolean>;
};

export type ExplainFinding = {
  code: string | null;
  label: "conditional" | null;
  detail: string | null;
  summary: string;
  notApplicable?: string[];
};

export type ExplainChain = {
  intact: boolean;
  breakAt: string | null;
};

export type ExplainWarning = {
  id: string;
  code: string;
  detail: string;
};

export type ExplainOpts = {
  issuerTrust?: { publicKeyPem: string | readonly string[]; source?: "env" | "own-key" };
  extract?: import("@cedulon/effect-extract").SignedEffectExtract | import("@cedulon/x402-adapter").SignedRailExtract;
  inputsLog?: InputsLog;
};

export type ExplainTrustRoot = {
  pinned: boolean;
  issuerMatches: boolean | null;
  source: "env" | "own-key" | null;
};

export type ExplainPair = {
  defer: SignedDecisionRecord | null;
  resolution: SignedDecisionRecord | null;
};

export type ExplainResult = {
  record: SignedDecisionRecord;
  effect: LedgerEffect | null;
  pair?: ExplainPair;
  finding: ExplainFinding;
  witnessClass: WitnessClass | null;
  balanced: boolean;
  chain: ExplainChain;
  guarantee: "unconditional" | "conditional";
  warnings: ExplainWarning[];
  trustRoot: ExplainTrustRoot;
  scope?: {
    accountId: string;
    railId: string;
    windowStartMs: number;
    windowEndMs: number;
  };
};
