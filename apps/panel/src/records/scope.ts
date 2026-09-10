import type { Copy } from "../copy.ts";
import type { ReconcileCardReport } from "../ReconcileCard.tsx";
import type { RailAction, RailWarning } from "../rail/types.ts";

export type ScopeLines = {
  signature: string;
  witness: string;
  external: string;
};

function matchedRefs(report: ReconcileCardReport): Set<string> {
  const out = new Set<string>();
  for (const row of report.matched ?? []) {
    const ref = row.effect?.ref;
    if (typeof ref === "string" && ref !== "") out.add(ref);
  }
  return out;
}

function unpaidRefs(report: ReconcileCardReport): Set<string> {
  const out = new Set<string>();
  for (const row of report.authorizedUnpaid ?? []) {
    if (typeof row.ref === "string" && row.ref !== "") out.add(row.ref);
  }
  return out;
}

function ghostRefs(report: ReconcileCardReport): Set<string> {
  const out = new Set<string>();
  for (const row of report.ghost) {
    if (typeof row === "string" && row !== "") out.add(row);
    else if (row && typeof row === "object" && "ref" in row && typeof (row as { ref: unknown }).ref === "string") {
      out.add((row as { ref: string }).ref);
    }
  }
  return out;
}

export function evidenceScope(copy: Copy, opts: {
  action: RailAction | null;
  inspected: boolean;
  issuerMatches?: boolean | null;
  pinSource?: "env" | "own-key" | null;
  reconcile: ReconcileCardReport | null;
}): ScopeLines {
  const action = opts.action;
  let signature: string;
  if (!opts.inspected) {
    signature = copy["scope.signature.unmeasured"];
  } else if (opts.issuerMatches === true) {
    signature = copy["scope.signature.verified"];
  } else if (opts.issuerMatches === false) {
    signature = copy["scope.signature.failed"];
  } else if (opts.pinSource == null) {
    signature = copy["scope.signature.noPin"];
  } else {
    signature = copy["scope.signature.unmeasured"];
  }

  const witnessClass = action?.witnessClass ?? action?.effect?.witnessClass ?? null;
  let witness: string;
  if (witnessClass === "self") witness = copy["scope.witness.self"];
  else if (witnessClass === "same-org") witness = copy["scope.witness.sameOrg"];
  else if (typeof witnessClass === "string" && witnessClass !== "") {
    witness = copy["scope.witness.named"].replace("{class}", witnessClass);
  } else {
    witness = copy["scope.witness.none"];
  }

  let external: string;
  if (opts.reconcile === null) {
    external = copy["scope.external.unbound"];
  } else if (action?.effect?.row.effectClass !== "spend") {
    external = copy["scope.external.notSpend"];
  } else {
    const ref = action.effect.row.ref;
    if (matchedRefs(opts.reconcile).has(ref)) external = copy["scope.external.matched"];
    else if (unpaidRefs(opts.reconcile).has(ref)) external = copy["scope.external.unpaid"];
    else if (ghostRefs(opts.reconcile).has(ref)) external = copy["scope.external.ghost"];
    else external = copy["scope.external.absent"];
  }

  return { signature, witness, external };
}

export function pinLabel(copy: Copy, source: "env" | "own-key" | null | undefined): string {
  if (source === "env") return copy["pin.env"];
  if (source === "own-key") return copy["pin.ownKey"];
  return copy["pin.none"];
}

export function guaranteeLabel(copy: Copy, state: "unconditional" | "conditional" | null | undefined): string {
  if (state === "unconditional") return copy["guarantee.unconditional"];
  if (state === "conditional") return copy["guarantee.conditional"];
  return copy.disconnected;
}

export function warningCodes(warnings: readonly RailWarning[]): string {
  return warnings.map((w) => w.code).join(" ");
}
