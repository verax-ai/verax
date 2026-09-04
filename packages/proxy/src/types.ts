import type { DecisionKind, SignedDecisionRecord } from "@cedulon/core";
import type { EffectRow, SignedEffectExtract } from "@cedulon/effect-extract";

/** Who asked. G2 fills `brain` from JWT `sub` and `scopes` from `scope`. */
export type Principal = {
  brain: string;
  scopes: ReadonlySet<string>;
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

export type Policy = {
  hash: string;
  evaluate(call: ToolCall, principal: Principal): PolicyDecision;
};

export type WitnessClass = "self" | "same-org" | "third-party" | "regulated";

export type LedgerEffect = {
  row: EffectRow;
  witnessClass: WitnessClass;
  /** Hash of the ToolResult (or thrown payload). Not an EffectRow field. */
  resultHash?: string;
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

export type ProxyDeps = {
  policy: Policy;
  recordSigner: RecordSigner;
  effectSigner: EffectSigner;
  ledger: Ledger;
  now: () => number;
  nonce: () => string;
  inner: (call: ToolCall, principal: Principal) => Promise<ToolResult>;
};

export type ExplainFinding = {
  code: string | null;
  label: "conditional" | null;
  detail: string | null;
  summary: string;
  notApplicable?: string[];
};

export type ExplainResult = {
  record: SignedDecisionRecord;
  effect: LedgerEffect | null;
  finding: ExplainFinding;
  witnessClass: WitnessClass | null;
  balanced: boolean;
};
