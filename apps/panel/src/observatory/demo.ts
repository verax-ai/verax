import { parseLedger } from "../rail/parse.ts";
import type { PolicyBundle, RailAction } from "../rail/types.ts";
import decisionsText from "../../../../packages/proxy/tests/fixtures/ledger-golden/decisions.jsonl?raw";
import effectsText from "../../../../packages/proxy/tests/fixtures/ledger-golden/effects.jsonl?raw";
import policy from "../../../../packages/proxy/policy/default.json";

export function loadDemoActions(): RailAction[] {
  return parseLedger(decisionsText, effectsText, {
    hash: "fixture",
    document: policy as PolicyBundle["document"],
  });
}
