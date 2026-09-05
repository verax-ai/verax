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
  const result = await explain(ledger, ref, opts);
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
        }),
      },
    ],
    isError: false,
  };
}
