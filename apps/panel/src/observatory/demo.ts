import { parseLedger } from "../rail/parse.ts";
import type { PolicyStore } from "../rail/parse.ts";
import type { RailAction, RailInputs } from "../rail/types.ts";
import decisionsText from "../../../../packages/proxy/tests/fixtures/ledger-golden/decisions.jsonl?raw";
import effectsText from "../../../../packages/proxy/tests/fixtures/ledger-golden/effects.jsonl?raw";
import inputsText from "../../../../packages/proxy/tests/fixtures/ledger-golden/inputs.jsonl?raw";
import policyStore from "../../../../packages/proxy/tests/fixtures/ledger-golden/policy-store.json";

function parseInputsJsonl(text: string): Record<string, RailInputs> {
  const out: Record<string, RailInputs> = {};
  for (const line of text.split("\n")) {
    if (line === "") continue;
    const row = JSON.parse(line) as { ref: string; inputs: RailInputs };
    if (typeof row.ref !== "string" || row.ref === "") continue;
    out[row.ref] = row.inputs;
  }
  return out;
}

export function loadDemoActions(): RailAction[] {
  return parseLedger(
    decisionsText,
    effectsText,
    policyStore as PolicyStore,
    parseInputsJsonl(inputsText),
  );
}
