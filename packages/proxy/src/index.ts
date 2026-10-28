export { createProxy, LedgerDenyUnrecorded } from "./proxy.ts";
export { clearProcessHalted, isProcessHalted, markProcessHalted, persistHaltedSwitch } from "./process-halt.ts";
export { effectDescriptor, sha256Canonical } from "./hash.ts";
export { samePublicKey, thirdPartyReceiptRejection } from "./third-party.ts";
export { loadPolicy, TERMINAL_CONTROL_CLASS, DISPLAY_ESCAPE_CLASS, terminalText, terminalLines } from "./policy.ts";
export type { PolicyParseOptions } from "./policy.ts";
export { FileLedger, MemoryLedger, readLedgerTail, lockHolderAlive, lockState, lockBeatOf } from "./ledger.ts";
export { indexCoverage, listPieceFiles } from "./ledger-manifest.ts";
export { explain } from "./explain.ts";
export {
  approvePending,
  approvalsLogFor,
  createApprovalBudgetGuard,
  enqueueApprovalCommand,
  loadApprovalsFromDir,
} from "./approvals.ts";
export {
  loadDecisionRefsFromDir,
  loadDecisionRequestHashesFromDir,
  loadEffectsFromDir,
  parseCardCsv,
  parseChannelJsonl,
  reconcile,
} from "./reconcile.ts";
export { tenantKey } from "./tenant.ts";
// The body writes checkpoints and signs its own effect attestations. Both were
// reached through a relative path into this package, which only exists inside
// this repository: a published body would have imported a file that is not there.
// The disk seam is public for the same reason: a caller that drives the body
// through this package must be able to inject a full disk into the very
// instance the proxy uses. Deep imports are not in the exports map.
export { diskProbe } from "./disk.ts";
export { checkpointsPath, readCheckpointFile } from "./checkpoints.ts";
export { signEffectAttestation } from "./ledger.ts";
export { spokenReason } from "./spoken-reason.ts";
export { OPERATOR_REMOVED_DIR, operatorRemovalMark } from "./operator-removal-sync.ts";
export type { ApprovalRow, ApproveResult } from "./approvals.ts";
export type { CardCsvOpts, ChannelRow, ReconcileReport } from "./reconcile.ts";
export type { FileLedgerOpts, LedgerCounts, LockHolder } from "./ledger.ts";
export type { ApprovalSignature, ControlSignature, OperatorRemovalInput, RevokeInput } from "./types.ts";
export type {
  EffectSigner,
  ExplainChain,
  ExplainPair,
  ExplainFinding,
  ExplainOpts,
  ExplainResult,
  ExplainTrustRoot,
  ExplainWarning,
  ExtractWindow,
  Ledger,
  LedgerEffect,
  MediaContent,
  Policy,
  PolicyDecision,
  Principal,
  ProxyDeps,
  RecordSigner,
  ResultContent,
  TextContent,
  ToolCall,
  ToolResult,
  WitnessClass,
} from "./types.ts";

export { verifyLedger } from "./verify-ledger.ts";
export type {
  VerifyResult,
  VerifyOptions,
  VerifyTrust,
  VerifyControl,
  VerifyInputs,
  VerifyAnchors,
} from "./verify-ledger.ts";
export { anchorEntryHash, appendAnchor, readAnchors } from "./anchors.ts";
export type { AnchorRoute, AnchorRow } from "./anchors.ts";
export { verifyReceipt } from "./transparency-receipt.ts";
export type { ReceiptCheck, ReceiptStage } from "./transparency-receipt.ts";
