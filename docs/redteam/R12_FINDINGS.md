# R12 findings — several model families, file by file

Round R12 ran against d1e33ab. Eight security-relevant files were each read by several models of different families,
side by side (DeepSeek, OpenAI Codex, xAI Grok through Cursor, and gpt-oss/Qwen through Groq for small files), each
with the threat model as context. About 95 candidate findings came back; every high or critical candidate was either
measured at the gate or read against the rest of the code. A model reading one file cannot see a guard that lives in
another, and most candidates were of that kind (for example: a negative spend amount is refused in `policy.ts`, and the
approvals lock is backed by the ledger directory lock). The rows below are the ones that held.

Four high findings. Two medium findings.

| id | severity | attacker | description | file | measured |
| --- | --- | --- | --- | --- | --- |
| R12-1 | high | The agent, with an operator who approves each request | The daily spend cap bucketed approved spends by the day the request was created, not the day it was approved. With a cap of 100, a request created at 23:59 and another at 00:00:30, both approved after midnight, spent 200 in one day. | `packages/proxy/src/approvals.ts` `spentTodayMinorOf` | reproduced against `createApprovalBudgetGuard` |
| R12-2 | high | The agent | `message.send` egress took the host after the last `@`. `a@evil.com,b@allowed.com`, `;`-separated and tab-separated lists, and a trailing newline were all allowed under an allow-list of `allowed.com`. The body queues rather than sends, but the signed decision covered recipients the policy does not name. | `packages/proxy/src/policy.ts` `HOST_EXTRACTORS` | reproduced against `evaluate` |
| R12-3 | medium | The agent, when `audit.explain` is configured `mode: "approve"` | The tenant check for `audit.explain` ran only when the fresh verdict was `allow`; the approved retry never ran it and the tool had no check of its own. Not reachable with the shipped policy. | `packages/proxy/src/proxy.ts`, `packages/body/src/tools/audit.ts` | read at the gate |
| R12-4 | high | Whoever can make ledger writes fail (for example a full disk) | If the tool succeeded and neither the effect nor the `:threw` row could be appended, the in-flight mark was still cleared, so a retry with the same `_ref` ran the tool again. | `packages/proxy/src/proxy.ts` `runInner` and the launch `finally` | read at the gate |
| R12-5 | high | Whoever can write the ledger directory | Deleting `effects.jsonl` left `verify` at `ok: true` with no problem, although the index records which refs had an effect. | `packages/proxy/src/verify-ledger.ts` | reproduced: two bound effects, file deleted, `ok: true` |
| R12-6 | medium | The agent | With `requireInputs: true`, `_inputs: []` passed as a declaration. | `packages/proxy/src/proxy.ts` `resolveInputs` | read at the gate |

## Fixes

- R12-1: approval time is recorded on the row (`approvedAtMs`) and approved spends are bucketed by it. An approved row
  without it (written before this change) counts toward every day checked.
- R12-2: `to` must be a single plain address; anything else has no host and is refused as `egress-host-missing`.
- R12-3: the tenant check runs before a `defer` is written and again before an approved call launches, and the tool
  refuses another tenant's ref itself.
- R12-4: the in-flight mark is removed only after an effect row was actually recorded; otherwise a retry answers
  `outcome-unknown`.
- R12-5: every ref the index marks as having an effect must have a bound effect row. When the index is absent the
  result says effect completeness was not checked; together with a missing index this remains the stated limit that
  only a checkpoint held elsewhere detects removal.
- R12-6: an empty `_inputs` list is `inputs-required` when inputs are required.

## Not covered by this round

`packages/body/src/server.ts` was read by one model only (the others ran out of budget, time or credits on it), and the
Codex pass did not reach `dev-issuer.mjs`, `verify-ledger.ts`, `auth.ts` or `operator-pairing.ts`. These are not
claimed as checked here.
