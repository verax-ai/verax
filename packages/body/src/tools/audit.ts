import { explain, type ExplainOpts, type Ledger, type ToolCall, type ToolResult } from "@verax-ai/proxy";

export async function auditExplain(
  call: ToolCall,
  ledger: Ledger,
  opts?: ExplainOpts,
): Promise<ToolResult> {
  const ref = call.arguments.ref;
  if (typeof ref !== "string" || ref === "") {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "ref-required" }) }],
      isError: true,
    };
  }
  let result;
  try {
    result = await explain(ledger, ref, opts);
  } catch (err) {
    if (err instanceof Error && err.message.startsWith("explain-unknown-ref:")) {
      // No such record. Saying "denied" over a row the proxy allowed would make the
      // answer disagree with the ledger; the refusal for another tenant's ref is a
      // signed deny written by the proxy, not this string.
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "unknown-ref" }) }],
        isError: true,
      };
    }
    throw err;
  }
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          record: result.record.claims,
          effect: result.effect,
          finding: result.finding,
          witnessClass: result.witnessClass,
          guarantee: result.guarantee,
          warnings: result.warnings,
          trustRoot: result.trustRoot,
          pair: result.pair
            ? {
                defer: result.pair.defer?.claims ?? null,
                resolution: result.pair.resolution?.claims ?? null,
              }
            : undefined,
        }),
      },
    ],
    isError: false,
  };
}
