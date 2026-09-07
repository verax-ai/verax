import {
  explain,
  spokenReason,
  type ExplainOpts,
  type Ledger,
  type ToolCall,
  type ToolResult,
} from "@verax-ai/proxy";

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
      // Spoken the same as a tenant-mismatch refuse so the two calls look alike.
      // The operator HTTP contest path still names unknown-ref.
      return {
        content: [{ type: "text", text: JSON.stringify({ error: spokenReason("tenant-mismatch") }) }],
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
