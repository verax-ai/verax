import type { ToolCall, ToolResult } from "@verax-ai/proxy";

/** Authorizes a payment; does not move money. */
export async function spendAuthorize(call: ToolCall, ref: string): Promise<ToolResult> {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          authorized: true,
          ref,
          amountMinor: call.arguments.amountMinor,
          currency: call.arguments.currency,
          payee: call.arguments.payee,
          reference: call.arguments.reference,
        }),
      },
    ],
    isError: false,
  };
}
